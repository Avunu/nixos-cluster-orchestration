# modules/nomad-acl.nix — Nomad's namespaces, policies and scoped tokens.
#
# Before this, every consumer of the API (the fence on every node, jfs-nomad-meta,
# job registration, the autoscaler, avc) read the ACL bootstrap token, so every node
# held a management token: root on any worker was root on the cluster. Now:
#
#   nomad-acl-init     the `nomad-leader` node only, and the only reader of the
#                      management token (`nomad-acl/token`, declared there only).
#                      Bootstraps ACLs with it, then applies what is below: the
#                      `apps` and `default` namespaces, one policy per role, the
#                      `clan` JWT auth method and its binding rules.
#   nomad-login@<role> every node, one per role the node has (lib/nomad-pki.nix
#                      loginRoles): exchanges the machine's pre-signed JWT
#                      (`nomad-login/jwt-<role>`, signed offline by `nomad-jwt`) for
#                      a token bound to that role's policy, and writes it to
#                      /run/nomad-tokens/<role>, 0400 root. A timer refreshes it well
#                      inside its TTL.
#
# Why JWT login: a scoped token cannot be pre-minted, because Nomad discards a
# SecretID supplied for anything but the bootstrap. A signed JWT can be, and a
# tampered one, a wrong audience, or a role with no binding rule is refused
# (tests/control-plane-attack.nix).
#
# Namespaces: `apps` may run raw_exec and nothing else; `default` may run none of
# the drivers a node could offer. Every job the cluster renders is in `apps`
# (lib/mk-app-container.nix), so a token that can submit there is the one thing
# that runs code, and no token can run anything in `default`, management included.
# Node-pool governance would be the other lever, and it is Enterprise-only.
{
  config,
  lib,
  pkgs,
  node,
  clusterLib,
  ...
}:
let
  net = clusterLib.net;
  pki = clusterLib.nomadPki;
  ns = clusterLib.nomad.appsNamespace;
  vars = config.clan.core.vars.generators;
  tls = pki.cliTlsFor vars;
  nomadAddr = net.nomadAddr node;
  isLeader = net.hasTag "nomad-leader" node;
  roles = pki.loginRoles node;

  # A new ciphertext for a file is a new value: re-run what read the old one.
  ciphertextHash =
    gen: file:
    let
      f = vars.${gen}.files.${file};
      p = config.clan.core.settings.directory + "/secrets/clan-vars/${f.rel_dir}/${f.name}/${f.name}.age";
    in
    lib.optional (builtins.pathExists p) (builtins.hashFile "sha256" p);

  namespaces = [
    {
      Name = ns;
      Description = "Declared app containers (lib/mk-app-container.nix)";
      Capabilities.EnabledTaskDrivers = [ "raw_exec" ];
    }
    {
      Name = "default";
      Description = "Nothing runs here";
      Capabilities.DisabledTaskDrivers = [
        "raw_exec"
        "exec"
        "java"
        "qemu"
        "docker"
      ];
    }
  ];

  # One policy per role. Each is the least its consumer needs; tests/control-plane-
  # attack.nix `scoped-tokens` proves each can do its job and is refused one thing
  # outside it.
  policies = {
    # Reads which allocations run where, and its own node ID. Nothing else.
    fence = ''
      namespace "${ns}" { capabilities = ["read-job"] }
      agent { policy = "read" }
    '';
    # `nomad node meta apply jfs_ready=true` (modules/storage-juicefs.nix). node:write
    # can also drain a node; that is the price of setting meta at all.
    node-meta = ''
      node { policy = "write" }
    '';
    # Registers the rendered jobs (modules/nomad-bootstrap-leader.nix).
    registrar = ''
      namespace "${ns}" { capabilities = ["submit-job", "read-job", "list-jobs"] }
    '';
    autoscaler = ''
      namespace "${ns}" {
        policy       = "scale"
        capabilities = ["list-jobs"]
      }
      node { policy = "read" }
      operator { policy = "read" }
      agent { policy = "read" }
    '';
    # avc: status, logs, and `nomad job restart` (alloc-lifecycle). Never submit.
    operator-read = ''
      namespace "${ns}" { capabilities = ["list-jobs", "read-job", "read-logs", "alloc-lifecycle"] }
      node { policy = "read" }
      agent { policy = "read" }
      operator { policy = "read" }
    '';
  };

  # role -> policy. Every role has a rule on every cluster, whichever nodes hold it.
  bindings = {
    fence = "fence";
    node-meta = "node-meta";
    registrar = "registrar";
    autoscaler = "autoscaler";
    avc = "operator-read";
  };
  bindingRules = lib.mapAttrsToList (role: policy: {
    BindType = "policy";
    BindName = policy;
    Selector = ''value.role == "${role}"'';
  }) bindings;

  # The public key is filled in at run time, from the deployed `signing.pub`.
  authMethodTemplate = {
    Name = pki.authMethod;
    Type = "JWT";
    # One region today; global costs nothing and survives a second one.
    TokenLocality = "global";
    MaxTokenTTL = pki.tokenTtl;
    # Names who logged in as what, for the ACL event stream and `nomad acl token list`.
    TokenNameFormat = "\${auth_method_name}-\${value.node}-\${value.role}";
    Default = false;
    Config = {
      JWTValidationPubKeys = [ ];
      BoundIssuer = [ pki.jwtIssuer ];
      BoundAudiences = [ pki.jwtAudience ];
      # RS256 only: never "none", and nothing the key type does not match.
      SigningAlgs = [ "RS256" ];
      ClaimMappings = {
        role = "role";
        node = "node";
      };
    };
  };

  json = name: value: pkgs.writeText name (builtins.toJSON value);
  policyFiles = lib.mapAttrs (
    name: rules:
    json "nomad-policy-${name}.json" {
      Name = name;
      Description = "modules/nomad-acl.nix: ${name}";
      Rules = rules;
    }
  ) policies;

  # `api METHOD PATH [BODY-FILE]`: the body on stdout, or a message and a non-zero
  # return on anything but 2xx. With the CLI certificate (verify_https_client).
  apiFn = ''
    api() {
      local out code
      out=$(mktemp)
      code=$(curl -sS --max-time 30 ${tls.curlArgs} -o "$out" -w '%{http_code}' \
        -H "X-Nomad-Token: $NOMAD_TOKEN" -X "$1" "${nomadAddr}$2" \
        ''${3:+--data-binary @"$3"}) || code=000
      if [ "''${code:0:1}" != 2 ]; then
        echo "nomad-acl-init: $1 $2: HTTP $code: $(head -c 300 "$out")" >&2
        rm -f "$out"
        return 1
      fi
      cat "$out"
      rm -f "$out"
    }
  '';

  initScript = pkgs.writeShellScript "nomad-acl-init" ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.curl
        pkgs.jq
        pkgs.gnugrep
      ]
    }
    export NOMAD_ADDR=${nomadAddr}
    ${lib.concatStrings (lib.mapAttrsToList (k: v: "export ${k}=${v}\n") tls.env)}
    NOMAD_TOKEN=$(cat "$CREDENTIALS_DIRECTORY/token"); export NOMAD_TOKEN
    ${apiFn}
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    # Raft leadership first (up to ~5 min): nothing below is accepted without it.
    for _ in $(seq 1 60); do
      if curl -sf --max-time 5 ${tls.curlArgs} "${nomadAddr}/v1/status/leader" | grep -q ':'; then
        break
      fi
      sleep 5
    done

    # Bootstrap ACLs with OUR token. Nomad accepts this once per cluster; every later
    # run gets "ACL bootstrap already done", the steady state. Then the token must be
    # management here: a cluster bootstrapped with any other token is not ours to
    # configure, and that is a hard failure, not something to skip.
    management=0
    for _ in $(seq 1 30); do
      if ${config.services.nomad.package}/bin/nomad acl bootstrap "$CREDENTIALS_DIRECTORY/token" >/dev/null 2>&1; then
        echo "nomad-acl-init: ACL system bootstrapped"
      fi
      if api GET /v1/acl/token/self 2>/dev/null | jq -e '.Type == "management"' >/dev/null; then
        management=1
        break
      fi
      sleep 5
    done
    if [ "$management" != 1 ]; then
      echo "nomad-acl-init: the nomad-acl token is not a management token on this cluster" >&2
      exit 1
    fi

    ${lib.concatMapStrings (n: ''
      api POST /v1/namespace ${json "nomad-namespace-${n.Name}.json" n} >/dev/null
      echo "nomad-acl-init: namespace ${n.Name}"
    '') namespaces}

    ${lib.concatStrings (
      lib.mapAttrsToList (name: file: ''
        api POST /v1/acl/policy/${name} ${file} >/dev/null
        echo "nomad-acl-init: policy ${name}"
      '') policyFiles
    )}

    # The auth method, with this cluster's public key. Update when it exists, so a new
    # signing key (a `nomad-jwt` rotation) takes effect on the next run.
    jq --rawfile key "$CREDENTIALS_DIRECTORY/signing.pub" '.Config.JWTValidationPubKeys = [$key]' \
      ${json "nomad-auth-method.json" authMethodTemplate} > "$work/auth.json"
    if api GET /v1/acl/auth-method/${pki.authMethod} >/dev/null 2>&1; then
      api POST /v1/acl/auth-method/${pki.authMethod} "$work/auth.json" >/dev/null
      echo "nomad-acl-init: auth method ${pki.authMethod} updated"
    else
      api POST /v1/acl/auth-method "$work/auth.json" >/dev/null
      echo "nomad-acl-init: auth method ${pki.authMethod} created"
    fi

    # Binding rules: create what is missing, and delete what this module no longer
    # declares on this method, so a role taken away stops logging in.
    api GET /v1/acl/binding-rules > "$work/have.json"
    want=${json "nomad-binding-rules.json" bindingRules}
    jq -c '.[]' "$want" | while read -r rule; do
      if ! jq -e --argjson r "$rule" --arg m ${pki.authMethod} \
          'any(.[]; .AuthMethod == $m and .BindType == $r.BindType and .BindName == $r.BindName and .Selector == $r.Selector)' \
          "$work/have.json" >/dev/null; then
        jq --arg m ${pki.authMethod} --argjson r "$rule" -n '$r + { AuthMethod: $m }' > "$work/rule.json"
        api POST /v1/acl/binding-rule "$work/rule.json" >/dev/null
        echo "nomad-acl-init: binding rule $rule"
      fi
    done
    jq -r --arg m ${pki.authMethod} --slurpfile want "$want" \
      '.[] | select(.AuthMethod == $m)
           | select(. as $h | $want[0] | any(.BindType == $h.BindType and .BindName == $h.BindName and .Selector == $h.Selector) | not)
           | .ID' "$work/have.json" | while read -r id; do
      api DELETE /v1/acl/binding-rule/"$id" >/dev/null
      echo "nomad-acl-init: removed binding rule $id"
    done
  '';

  loginScript =
    role:
    pkgs.writeShellScript "nomad-login-${role}" ''
      set -euo pipefail
      export PATH=${
        lib.makeBinPath [
          pkgs.coreutils
          pkgs.curl
          pkgs.jq
        ]
      }
      work=$(mktemp -d)
      trap 'rm -rf "$work"' EXIT
      # The JWT goes on stdin, never into an argv anyone can read in /proc.
      jq -n --arg m ${pki.authMethod} --rawfile t "$CREDENTIALS_DIRECTORY/jwt" \
        '{ AuthMethodName: $m, LoginToken: ($t | rtrimstr("\n")) }' > "$work/body.json"
      code=$(curl -sS --max-time 30 ${tls.curlArgs} -o "$work/out" -w '%{http_code}' \
        -X POST --data-binary @- "${nomadAddr}/v1/acl/login" < "$work/body.json") || code=000
      if [ "$code" != 200 ]; then
        echo "nomad-login@${role}: refused or unreachable: HTTP $code: $(head -c 300 "$work/out" 2>/dev/null)" >&2
        exit 1
      fi
      secret=$(jq -r '.SecretID // empty' "$work/out")
      if [ -z "$secret" ]; then
        echo "nomad-login@${role}: the login returned no token" >&2
        exit 1
      fi
      umask 077
      mkdir -p ${pki.tokenDir}
      printf '%s' "$secret" > ${pki.tokenDir}/.${role}.tmp
      chmod 0400 ${pki.tokenDir}/.${role}.tmp
      mv ${pki.tokenDir}/.${role}.tmp ${pki.tokenDir}/${role}
      echo "nomad-login@${role}: token $(jq -r .AccessorID "$work/out") until $(jq -r .ExpirationTime "$work/out")"
    '';

  # Each role's token, asked whether the cluster still knows it. The login timer
  # renews a token every 6 h, which is the right pace for a TTL and the wrong one for
  # a token the cluster has forgotten (its ACL state rebuilt: a single voter
  # reinstalled, raft reset in a recovery): every consumer of it would get 403 until
  # the next timer. So every few minutes a refused token gets a fresh login. Only a
  # refusal does: Nomad not answering is not this unit's problem, and logging in then
  # would fail too. The autoscaler picks the new token up through its login's
  # ExecStartPost; the fence and the scripts read the file on every run.
  tokenCheckScript = pkgs.writeShellScript "nomad-token-check" ''
    set -uo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.curl
        pkgs.systemd
      ]
    }
    for role in ${lib.escapeShellArgs roles}; do
      tok=$(cat ${pki.tokenDir}/"$role" 2>/dev/null) || continue
      [ -n "$tok" ] || continue
      code=$(curl -sS --max-time 10 ${tls.curlArgs} -o /dev/null -w '%{http_code}' \
        -H "X-Nomad-Token: $tok" "${nomadAddr}/v1/acl/token/self") || code=000
      case "$code" in
        401 | 403)
          echo "nomad-token-check: the $role token is refused (HTTP $code): logging in again"
          systemctl start --no-block "nomad-login@$role.service"
          ;;
      esac
    done
  '';
in
{
  systemd.tmpfiles.rules = [ "d ${pki.tokenDir} 0700 root root -" ];

  systemd.services = lib.mkMerge [
    {
      nomad-token-check = {
        description = "Log in again for any scoped Nomad token the cluster refuses";
        after = [ "nomad.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${tokenCheckScript}";
        };
      };
    }

    (lib.mkIf isLeader {
      nomad-acl-init = {
        description = "Nomad ACLs: bootstrap, namespaces, policies, JWT login";
        after = [
          "nomad.service"
          "network-online.target"
        ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        # The script is store-hashed, so a policy change re-runs it on the next switch;
        # a new signing key changes no script, so its ciphertext does it.
        restartTriggers = ciphertextHash "nomad-jwt" "signing.pub";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${initScript}";
          LoadCredential = [
            "token:${vars.nomad-acl.files.token.path}"
            "signing.pub:${vars.nomad-jwt.files."signing.pub".path}"
          ];
          Restart = "on-failure";
          RestartSec = 10;
        };
      };
    })

    (lib.listToAttrs (
      map (
        role:
        lib.nameValuePair "nomad-login@${role}" {
          description = "Nomad login as ${role} (a scoped token in ${pki.tokenDir}/${role})";
          # On the leader, after the auth method exists. Elsewhere the leader may not be
          # up yet: Restart= retries until it is.
          after = [
            "nomad.service"
            "network-online.target"
          ]
          ++ lib.optional isLeader "nomad-acl-init.service";
          wants = [ "network-online.target" ] ++ lib.optional isLeader "nomad-acl-init.service";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${loginScript role}";
            LoadCredential = [ "jwt:${vars.nomad-login.files."jwt-${role}".path}" ];
            Restart = "on-failure";
            RestartSec = 10;
          }
          # The autoscaler loads its token once, at start (a DynamicUser reads it as a
          # credential). --no-block: at boot it is queued behind this very unit.
          // lib.optionalAttrs (role == "autoscaler") {
            ExecStartPost = "-${pkgs.systemd}/bin/systemctl --no-block try-restart nomad-autoscaler.service";
          };
        }
      ) roles
    ))
  ];

  systemd.timers =
    lib.listToAttrs (
      map (
        role:
        lib.nameValuePair "nomad-login@${role}" {
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = pki.tokenRefresh;
            OnUnitActiveSec = pki.tokenRefresh;
            RandomizedDelaySec = "10min";
          };
        }
      ) roles
    )
    // {
      nomad-token-check = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "10min";
          OnUnitActiveSec = "5min";
          RandomizedDelaySec = "30s";
        };
      };
    };
}
