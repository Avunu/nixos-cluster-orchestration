# Eval-level check of modules/secrets.nix: what a node is given of the site's secrets
# and what it is not, where each lands, what the gate holds, and what agenix-rekey
# makes of a node whose secrets were never rekeyed.
#
# Three sites: the fixture (placeholders, no node has a recipient), the secure fixture
# (the install-time secrets), and tests/fixtures/agenix (real ciphertext, a recipient
# and rekeyed files, which tests/secrets-tpm.nix boots).
#
# Run: nix build .#checks.<system>.secrets
{
  pkgs,
  lib,
  mkCluster,
  mkSecure,
  fixtureCluster,
  fixtureTopology,
}:
let
  node1 = fixtureCluster.nixosConfigurations.node1;
  c = node1.config;
  # A worker: no Nomad server's secrets.
  worker = fixtureCluster.nixosConfigurations.node2.config;
  secure = (mkSecure { }).nixosConfigurations.node1.config;

  agenixFixture = import ./fixtures/agenix;
  real =
    (mkCluster {
      self = {
        inputs = { };
        outPath = agenixFixture.directory;
      };
      inherit (agenixFixture) directory;
      topology = fixtureTopology;
      meta.name = "fixture-agenix";
      masterIdentities = [
        {
          identity = agenixFixture.masterIdentityAt;
          pubkey = agenixFixture.masterPubkey;
        }
      ];
      admins = import ./fixtures/admins.nix;
    }).nixosConfigurations.node1;

  gens = c.cluster.secrets.generators;
  file =
    cfg: gen: name:
    cfg.cluster.secrets.generators.${gen}.files.${name};
  ageNames = cfg: lib.attrNames cfg.age.secrets;
  evaluates = v: (builtins.tryEval (builtins.deepSeq v true)).success;
  failed = cfg: map (a: a.message) (lib.filter (a: !a.assertion) cfg.assertions);

  # agenix-rekey's stand-in for a host with no recipient (its modules/agenix-rekey.nix).
  dummyPubkey = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

  checks = [
    # ── what a node is given ────────────────────────────────────────────────
    {
      name = "every generated file a node is meant to hold is an agenix secret, at the path the modules read";
      ok =
        c.cluster.secrets.lowered != [ ]
        && lib.length c.cluster.secrets.lowered == lib.length (ageNames c)
        && lib.all (
          f:
          let
            s = c.age.secrets.${lib.removePrefix "/run/secrets/" f.path};
          in
          s.path == f.path
          && toString s.rekeyFile == toString f.source
          && s.owner == f.owner
          && s.group == f.group
          && s.mode == f.mode
        ) c.cluster.secrets.lowered;
    }
    {
      # The VM tests and the modules' own scripts name these.
      name = "the paths are the ones in use: /run/secrets/shared/<generator>/<file> and /run/secrets/per-machine/<node>/<generator>/<file>";
      ok =
        (file c "nomad-acl" "token").path == "/run/secrets/shared/nomad-acl/token"
        && (file c "nomad-tls" "agent.key").path == "/run/secrets/per-machine/node1/nomad-tls/agent.key"
        &&
          (file worker "nomad-tls" "agent.key").path == "/run/secrets/per-machine/node2/nomad-tls/agent.key"
        && c.age.secretsDir == "/run/secrets"
        && c.age.secrets."per-machine/node1/wg-ctrl/private".owner == "systemd-network";
    }
    {
      name = "the files are kept one per generator file, where lib/secrets-layout.nix says";
      ok =
        (file c "nomad-acl" "token").storedAs == "secrets/shared/nomad-acl/token.age"
        && (file c "nomad-tls" "agent.key").storedAs == "secrets/per-machine/node1/nomad-tls/agent.key.age"
        && (file c "wg-ctrl" "public").storedAs == "secrets/per-machine/node1/wg-ctrl/public"
        && toString c.age.rekey.localStorageDir == toString ./fixtures + "/secrets/rekeyed/node1";
    }
    {
      name = "a public file is read from the repository, and a secret has no value at evaluation";
      ok =
        (file c "wg-ctrl" "public").exists
        && (file c "wg-ctrl" "public").value == (import ./lib/fixture-wg.nix).node1.public
        && !(evaluates (file c "wg-ctrl" "private").value);
    }
    {
      name = "a persisted prompt is a file of its generator";
      ok = gens.ovh-s3.files ? "access-key" && gens.ovh-s3.files."access-key".secret;
    }

    # ── what a node is not given ────────────────────────────────────────────
    {
      name = "an operator's secret and a generator's input are on no node";
      ok =
        (file c "nomad-ca" "ca.key").exists
        && lib.all (n: !(c.age.secrets ? ${n})) [
          "shared/nomad-ca/ca.key"
          "shared/nomad-jwt/signing.key"
          "shared/cloudflare/provision-token"
        ]
        && c.age.secrets ? "shared/nomad-ca/ca.crt";
    }
    {
      name = "an install-time secret is on no running node, and stays where the install reads it";
      ok =
        (file secure "luks" "passphrase").exists
        &&
          (file secure "luks" "passphrase").path
          == "/run/partitioning-secrets/per-machine/node1/luks/passphrase"
        && lib.all (
          n: !lib.hasInfix "luks" n && !lib.hasInfix "volume-identity" n && !lib.hasInfix "initrd-ssh" n
        ) (ageNames secure)
        && !(secure.age.secrets ? "per-machine/node1/emergency-access/password");
    }
    {
      name = "a worker is given no Nomad server's secret";
      ok =
        !(worker.cluster.secrets.generators ? nomad-acl)
        && lib.all (n: !lib.hasInfix "nomad-acl" n && !lib.hasInfix "nomad-gossip" n) (ageNames worker);
    }
    {
      name = "a file is read by services or at install, and nothing else can be asked for";
      ok =
        !(evaluates
          (node1.extendModules {
            modules = [ { cluster.secrets.generators.probe.files.x.neededFor = "activation"; } ];
          }).config.cluster.secrets.generators.probe.files.x.neededFor
        );
    }
    {
      name = "a public file named like a ciphertext is refused";
      ok = lib.any (lib.hasInfix "may not be named *.age") (
        failed
          (node1.extendModules {
            modules = [ { cluster.secrets.generators.probe.files."x.age".secret = false; } ];
          }).config
      );
    }

    # ── how it gets there ───────────────────────────────────────────────────
    {
      name = "a node decrypts with its TPM identity and nothing else, from files rekeyed into the repository";
      ok =
        c.age.identityPaths == [ c.cluster.secrets.identityPath ]
        && c.age.rekey.storageMode == "local"
        && lib.all (p: lib.elem p (map lib.getName c.age.rekey.agePlugins)) [
          "age-plugin-tpm"
          "age-plugin-yubikey"
        ]
        && lib.hasInfix "with-plugins" c.age.ageBin;
    }
    {
      name = "a node with no recipient yet evaluates, with placeholders that nothing was rekeyed for";
      ok =
        c.age.rekey.hostPubkey == dummyPubkey
        && evaluates (map (s: s.file.drvPath) (lib.attrValues c.age.secrets))
        && lib.all (s: lib.hasInfix "placeholder" s.file.name) (lib.attrValues c.age.secrets);
    }
    {
      name = "a node with a recipient is built from its own rekeyed files";
      ok =
        real.config.age.rekey.hostPubkey == lib.removeSuffix "\n" (
          builtins.readFile (agenixFixture.directory + "/secrets/recipients/node1.pub")
        )
        &&
          ageNames real.config == [
            "per-machine/node1/wg-ctrl/private"
            "shared/canary/value"
          ]
        && lib.all (s: lib.hasSuffix "-${s.name}.age" s.file) (lib.attrValues real.config.age.secrets);
    }
    {
      # agenix-rekey's own assertion: "Rekeyed secret for age.secrets.<n> not found,
      # please run `agenix rekey -a` again". A missing rekeyed file stops the build; it
      # never becomes a node without the secret.
      name = "a node with a recipient and a secret nobody rekeyed for it does not evaluate";
      ok =
        !(evaluates
          (real.extendModules {
            modules = [
              {
                age.secrets.unrekeyed.rekeyFile = agenixFixture.directory + "/secrets/shared/canary/value.age";
              }
            ];
          }).config.age.secrets.unrekeyed.file
        );
    }

    # ── fail closed ─────────────────────────────────────────────────────────
    {
      name = "Nomad does not start on a boot whose secrets did not all decrypt, nor what retries until it answers";
      ok =
        lib.sort lib.lessThan c.cluster.secrets.gate == [
          "nomad-acl-init.service"
          "nomad-bootstrap.service"
          "nomad-login@avc.service"
          "nomad-login@fence.service"
          "nomad-login@node-meta.service"
          "nomad-login@registrar.service"
          "nomad.service"
        ]
        &&
          lib.sort lib.lessThan worker.cluster.secrets.gate == [
            "nomad-login@avc.service"
            "nomad-login@fence.service"
            "nomad-login@node-meta.service"
            "nomad.service"
          ]
        && c.systemd.services.cluster-secrets.requiredBy == c.cluster.secrets.gate
        && c.systemd.services.cluster-secrets.before == c.cluster.secrets.gate
        && c.systemd.services.cluster-secrets.serviceConfig.RemainAfterExit;
    }
    {
      # systemd keeps the start job of a oneshot it is restarting, and multi-user.target
      # waits for it: with the agent held, a unit left to retry against it would keep
      # the boot from finishing.
      name = "every unit that starts with the boot and retries after Nomad is held with it";
      ok =
        let
          retriesAfterNomad = lib.attrNames (
            lib.filterAttrs (
              _: u:
              lib.elem "nomad.service" u.after
              && lib.elem "multi-user.target" u.wantedBy
              && (u.serviceConfig.Type or "") == "oneshot"
              && (u.serviceConfig.Restart or "no") != "no"
            ) c.systemd.services
          );
        in
        retriesAfterNomad != [ ]
        && lib.all (u: lib.elem "${u}.service" c.cluster.secrets.gate) retriesAfterNomad;
    }
    {
      name = "the gate is not restarted by a switch, and the watch runs without it";
      ok =
        !c.systemd.services.cluster-secrets.restartIfChanged
        && c.systemd.timers.cluster-secrets-watch.wantedBy == [ "timers.target" ]
        &&
          c.systemd.services.cluster-secrets-watch.serviceConfig.ExecStart
          == c.systemd.services.cluster-secrets.serviceConfig.ExecStart;
    }
    {
      # A node whose secrets failed has to be reachable, and has to be able to pull the
      # commit that repairs it.
      name = "nothing a repair needs waits for the gate";
      ok =
        lib.all
          (
            u:
            let
              unit = c.systemd.services.${u};
            in
            !lib.elem "cluster-secrets.service" (unit.requires ++ unit.after ++ unit.bindsTo ++ unit.requisite)
          )
          [
            "sshd"
            "systemd-networkd"
            "cluster-upgrade"
          ];
    }

    # ── for the tool that runs the generators ───────────────────────────────
    {
      name = "every generator of every machine is exported as data";
      ok =
        let
          e = fixtureCluster.secrets;
          tls = e.node1.generators.nomad-tls;
        in
        lib.attrNames e == lib.attrNames fixtureTopology.nodes
        && lib.attrNames e.node1.generators == lib.attrNames gens
        && tls.dependencies == [ "nomad-ca" ]
        && !tls.share
        && lib.isDerivation tls.script
        && tls.validationHash == gens.nomad-tls.validationHash
        && tls.files."agent.key".storedAs == "secrets/per-machine/node1/nomad-tls/agent.key.age"
        && e.node1.generators.ovh-s3.prompts."secret-key".type == "hidden"
        && e.node1.recipient == null
        && evaluates (builtins.unsafeDiscardStringContext (builtins.toJSON e.node2));
    }
  ];

  bad = lib.filter (x: !x.ok) checks;
in
pkgs.runCommand "secrets-checks" { } (
  if bad == [ ] then
    ''
      echo "${toString (builtins.length checks)} secrets checks passed"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') bad}
      exit 1
    ''
)
