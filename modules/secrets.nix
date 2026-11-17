# modules/secrets.nix — how a secret is declared, where it is kept, and how it
# reaches a node. What the cluster's secrets ARE is modules/vars.nix and the kinds.
#
# ── declared ────────────────────────────────────────────────────────────────
# `cluster.secrets.generators.<name>` describes how a set of files is made: a script
# that writes them to $out, the programs it needs, what it asks the operator
# ($prompts/<name>), and the generators whose files it reads ($in/<generator>/<file>).
# Nothing on a node ever runs one. `cluster.secrets.export` is the same information as
# data, for the tool on the operator's machine that does.
#
# ── kept ────────────────────────────────────────────────────────────────────
# One file per generator file in the site's repository, by lib/secrets-layout.nix:
# a secret encrypted to the operators' master identities, a public file in the clear.
#
# ── on a node ───────────────────────────────────────────────────────────────
# A file that is secret, deployed and read by services becomes an agenix secret at the
# path the modules read, /run/secrets/<scope>/<generator>/<file>. Its `rekeyFile` is
# the master-encrypted source, which the node cannot read; `agenix rekey` re-encrypts
# it to this node's recipient and commits the result, and that file is what the
# closure carries. The recipient is an age-plugin-tpm identity, so the private half
# is in the node's TPM and nowhere else. A switch therefore needs nothing uploaded
# and no operator key, which is what the pull loop (modules/pull-deploy.nix) requires.
#
# What a node is never given: a file with `deploy = false` (an operator's, or an
# input to another generator), and a file with `neededFor = "partitioning"` (read once,
# at install). Neither is rekeyed, so neither is in any closure.
#
# A declared file whose source is not in the repository yet is not lowered: the node
# evaluates and builds without it, as a new site must before its secrets exist. What
# reads it finds nothing at its path. lib/mk-app-container.nix refuses that for an
# app's secrets.
#
# A node with no recipient in the repository yet (not installed) gets agenix-rekey's
# placeholders, which decrypt nowhere, and its warning.
#
# ── fail closed ─────────────────────────────────────────────────────────────
# agenix decrypts during activation and carries on when a file does not decrypt: the
# boot completes, the secret is absent, and after a live switch the previous values are
# gone too. `cluster-secrets.service` turns that into a failed unit: it requires every
# lowered secret at its path, once per boot, and `cluster.secrets.gate` lists the units
# that do not start without it. That is Nomad's agent, the one unit that makes a node
# take work: with no agent the node runs no app and the servers see it down, where a
# node short one secret would otherwise join and start the apps that do not need it.
# And the units that only talk to that agent and retry until it answers
# (modules/nomad-acl.nix, modules/nomad-register.nix): systemd keeps the start job of
# a oneshot it is restarting, so left to retry against an agent that is held they
# would keep the boot from ever finishing.
#
# Not gated, on purpose: sshd, networkd and the pull loop, because a node whose secrets
# failed must stay reachable and must still be able to pull the commit that repairs it;
# and the infrastructure units that read a secret, which fail on the missing file by
# themselves.
#
# A gate that passed does not run again on a switch, because a unit it holds would be
# restarted with it. `cluster-secrets-watch` does, every minute: the same check, a
# failed unit, and `cluster_secrets_missing` for SecretsMissing (lib/alert-rules.nix).
# A gate that failed is started again by the next switch, which starts every active
# target again (multi-user.target among them), and what it held starts after it.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  layout = import ../lib/secrets-layout.nix;
  cfg = config.cluster.secrets;
  dir = cfg.directory;

  fileType =
    generator:
    types.submodule (
      { name, config, ... }:
      let
        rel = "${
          layout.scope {
            inherit (generator) share;
            inherit (cfg) machine;
          }
        }/${generator.name}";
      in
      {
        options = {
          name = mkOption {
            type = types.str;
            default = name;
            readOnly = true;
            description = "The file's name under $out.";
          };
          secret = mkOption {
            type = types.bool;
            default = true;
            description = "Whether the file is encrypted in the repository. A public file is committed in the clear and readable at evaluation, as `value`.";
          };
          deploy = mkOption {
            type = types.bool;
            default = true;
            description = "Whether a node is given the file. False for an operator's secret and for one that only another generator reads.";
          };
          owner = mkOption {
            type = types.str;
            default = "root";
            description = "The file's owner on the node.";
          };
          group = mkOption {
            type = types.str;
            default = "root";
            description = "The file's group on the node.";
          };
          mode = mkOption {
            type = types.strMatching "^[0-7]{4}$";
            default = "0400";
            description = "The file's mode on the node.";
          };
          neededFor = mkOption {
            type = types.enum [
              "partitioning"
              "services"
            ];
            default = "services";
            description = ''
              When the file is read. `services`: by units on the running node, where
              activation decrypts it. `partitioning`: once, at install, by disko and its
              hooks; it is on no running node.
            '';
          };
          path = mkOption {
            type = types.str;
            readOnly = true;
            description = "Where the file is on the node; for a public file, where it is in the repository.";
            default =
              if !config.secret then
                toString config.source
              else if config.neededFor == "partitioning" then
                "${layout.partitioningDir}/${rel}/${name}"
              else
                "${layout.runtimeDir}/${rel}/${name}";
          };
          source = mkOption {
            type = types.path;
            readOnly = true;
            description = "The file in the site's repository: the master-encrypted ciphertext, or the public value.";
            default = (if config.secret then layout.source else layout.public) dir rel name;
          };
          storedAs = mkOption {
            type = types.str;
            readOnly = true;
            description = "`source`, relative to the site's directory.";
            default = layout.storedAs {
              inherit rel;
              inherit (config) secret;
              file = name;
            };
          };
          exists = mkOption {
            type = types.bool;
            readOnly = true;
            description = "Whether `source` is in the repository, which is to say whether the generator has run.";
            default = builtins.pathExists config.source;
          };
          value = mkOption {
            type = types.str;
            readOnly = true;
            description = "A public file's content. Guard a read with `exists`: there is no value before the generator has run.";
            default =
              if config.secret then
                throw "cluster.secrets: ${generator.name}/${name} is a secret, and has no value at evaluation."
              else if config.exists then
                builtins.readFile config.source
              else
                throw "cluster.secrets: ${generator.name}/${name} has not been generated for ${cfg.machine} (no ${config.storedAs}).";
          };
        };
      }
    );

  promptType = types.submodule (
    { name, ... }:
    {
      options = {
        description = mkOption {
          type = types.str;
          default = name;
          description = "What the operator is asked for.";
        };
        type = mkOption {
          type = types.enum [
            "hidden"
            "line"
            "multiline"
            "multiline-hidden"
          ];
          default = "line";
          description = "How the answer is read.";
        };
        persist = mkOption {
          type = types.bool;
          default = false;
          description = "Whether the answer is itself a file of the generator, of the prompt's name.";
        };
      };
    }
  );

  # A scalar, or a set of scalars or of such sets. No lists: their order would be part
  # of the hash.
  scalar = types.oneOf [
    types.bool
    types.int
    types.str
  ];
  validationType = types.nullOr (
    types.oneOf [
      scalar
      (types.attrsOf (
        types.oneOf [
          scalar
          (types.attrsOf scalar)
        ]
      ))
    ]
  );

  generatorType = types.submodule (
    { name, config, ... }:
    let
      persisted = lib.attrNames (lib.filterAttrs (_: p: p.persist) config.prompts);
    in
    {
      options = {
        name = mkOption {
          type = types.str;
          default = name;
          readOnly = true;
          description = "The generator's name: its directory in the repository and on a node.";
        };
        share = mkOption {
          type = types.bool;
          default = false;
          description = "Whether the fleet has one value (made once, the same on every node that declares the generator) or each node its own.";
        };
        files = mkOption {
          type = types.attrsOf (fileType config);
          default = { };
          description = "The files the script writes to $out.";
        };
        prompts = mkOption {
          type = types.attrsOf promptType;
          default = { };
          description = "What the operator is asked before the script runs, each answer a file at $prompts/<name>.";
        };
        dependencies = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Generators whose files the script reads, at $in/<generator>/<file>.";
        };
        runtimeInputs = mkOption {
          type = types.listOf types.package;
          default = [ ];
          description = "Packages on the script's PATH.";
        };
        script = mkOption {
          type = types.lines;
          default = "";
          description = "Bash. Writes every declared file to $out.";
        };
        validation = mkOption {
          type = validationType;
          default = null;
          description = "Values the files depend on. When they change the files are stale and are made again.";
        };
        validationHash = mkOption {
          type = types.nullOr types.str;
          readOnly = true;
          description = "A hash of `validation`, or null without one.";
          default =
            if config.validation == null then
              null
            else
              builtins.hashString "sha256" (builtins.toJSON config.validation);
        };
        finalScript = mkOption {
          type = types.package;
          readOnly = true;
          description = "The script as it is run: its PATH set, a persisted prompt copied to its file. Run with $out, $in and $prompts set.";
          default = pkgs.writeScript "generator-${name}" ''
            #!${pkgs.runtimeShell}
            set -euo pipefail
            PATH=${lib.makeBinPath (config.runtimeInputs ++ [ pkgs.coreutils ])}
            ${lib.concatMapStrings (p: ''
              cat "$prompts/${p}" > "$out/${p}"
            '') persisted}
            ${config.script}
          '';
        };
      };
      config.files = lib.genAttrs persisted (_: { });
    }
  );

  allFiles = lib.concatLists (
    lib.mapAttrsToList (
      _: g: lib.mapAttrsToList (_: f: f // { generator = g.name; }) g.files
    ) cfg.generators
  );
  # agenix's name for a file: its path below /run/secrets.
  ageName = f: lib.removePrefix "${layout.runtimeDir}/" f.path;

  recipientFile = layout.recipient dir cfg.machine;

  textDir = "/var/lib/prometheus-node-exporter-text";
  check = pkgs.writeShellScript "cluster-secrets-check" ''
    set -u
    missing=0
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      if [ ! -e "$p" ]; then
        echo "cluster-secrets: $p is missing: it did not decrypt at activation" >&2
        missing=$((missing + 1))
      fi
    done < ${
      pkgs.writeText "cluster-secrets-paths" (lib.concatMapStrings (f: "${f.path}\n") cfg.lowered)
    }
    # Write-then-rename, so a scrape never reads half a file.
    ${pkgs.coreutils}/bin/mkdir -p ${textDir}
    printf 'cluster_secrets_missing %s\ncluster_secrets_expected %s\n' "$missing" ${toString (lib.length cfg.lowered)} \
      > ${textDir}/cluster_secrets.prom.tmp
    ${pkgs.coreutils}/bin/mv ${textDir}/cluster_secrets.prom.tmp ${textDir}/cluster_secrets.prom
    if [ "$missing" -gt 0 ]; then
      echo "cluster-secrets: $missing of ${toString (lib.length cfg.lowered)} secrets are missing." \
        "The node's age identity is ${cfg.identityPath}, on its TPM: \`journalctl -b | grep 'age: error'\` has why." >&2
      exit 1
    fi
  '';
in
{
  options.cluster.secrets = {
    generators = mkOption {
      type = types.attrsOf generatorType;
      default = { };
      description = "How each set of secret and public files is made. See modules/secrets.nix.";
    };

    directory = mkOption {
      type = types.path;
      description = "The site's repository (mkCluster's `directory`), where lib/secrets-layout.nix puts every file.";
    };
    machine = mkOption {
      type = types.str;
      description = "This machine's name in the repository's layout: its key under topology.nodes.";
    };

    masterIdentities = mkOption {
      type = types.listOf types.unspecified;
      default = [ ];
      description = "The operators' age identities, as agenix-rekey's `age.rekey.masterIdentities` takes them (mkCluster's `masterIdentities`).";
    };
    extraEncryptionPubkeys = mkOption {
      type = types.listOf types.unspecified;
      default = [ ];
      description = "Recipients every secret is also encrypted to and nothing is decrypted with day to day: the offline one (mkCluster's `extraRecipients`).";
    };

    identityPath = mkOption {
      type = types.str;
      default = "/var/lib/cluster-secrets/identity.txt";
      description = ''
        This node's age-plugin-tpm identity file: a handle to a key that only this
        machine's TPM can use. The key is bound to the TPM and to no boot state, so
        with this file anything booted on the machine can decrypt the node's secrets.
        It belongs on the node's encrypted disk, which only the node's own signed boot
        opens, and not in the repository.
      '';
    };

    gate = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "nomad.service" ];
      description = "Units that are not started on a boot whose secrets did not all decrypt.";
    };

    lowered = mkOption {
      type = types.listOf types.unspecified;
      readOnly = true;
      internal = true;
      description = "The files agenix decrypts on this node: secret, deployed, read by services, and generated.";
      default = lib.filter (f: f.exists) cfg.deployed;
    };
    deployed = mkOption {
      type = types.listOf types.unspecified;
      readOnly = true;
      internal = true;
      description = "The files a node is meant to hold, generated yet or not.";
      default = lib.filter (f: f.secret && f.deploy && f.neededFor == "services") allFiles;
    };

    export = mkOption {
      type = types.unspecified;
      readOnly = true;
      description = ''
        Every generator of this machine as data, for the tool that runs them:
        `nix eval --json .#clusterSecrets.<machine>`. `script` is a store path to build
        and run with $out, $in and $prompts set; `storedAs` is where each file goes,
        relative to the site's directory, a secret encrypted to the master identities.
      '';
      default = {
        inherit (cfg) machine;
        recipient =
          if builtins.pathExists recipientFile then "secrets/recipients/${cfg.machine}.pub" else null;
        generators = lib.mapAttrs (_: g: {
          inherit (g) share dependencies validationHash;
          script = g.finalScript;
          inherit (g) runtimeInputs;
          prompts = lib.mapAttrs (_: p: { inherit (p) description type persist; }) g.prompts;
          files = lib.mapAttrs (_: f: {
            inherit (f)
              secret
              deploy
              neededFor
              owner
              group
              mode
              path
              storedAs
              exists
              ;
          }) g.files;
        }) cfg.generators;
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = lib.all (f: f.secret || !lib.hasSuffix ".age" f.name) allFiles;
        message = "cluster.secrets: a public file may not be named *.age: that is where its generator's secret of the same stem is kept (lib/secrets-layout.nix).";
      }
    ];

    age = {
      # The TPM identity and nothing else: agenix's default, the SSH host keys, would
      # be a second key that decrypts nothing.
      identityPaths = [ cfg.identityPath ];
      # Activation's PATH is fixed, so the plugin comes with the binary.
      ageBin = "${pkgs.age.withPlugins (ps: [ ps.age-plugin-tpm ])}/bin/age";
      # Each activation decrypts into a new directory on a tmpfs that never swaps and
      # points /run/secrets at it, so a file is either the new value or absent.
      secretsDir = layout.runtimeDir;
      secretsMountPoint = "${layout.runtimeDir}.d";

      rekey = {
        storageMode = "local";
        localStorageDir = layout.rekeyed dir cfg.machine;
        hostPubkey = lib.mkIf (builtins.pathExists recipientFile) (
          lib.removeSuffix "\n" (builtins.readFile recipientFile)
        );
        inherit (cfg) masterIdentities extraEncryptionPubkeys;
        # On the operator's machine, for `agenix rekey`: the master identities are
        # YubiKeys, and a node's recipient is its TPM's.
        agePlugins = [
          pkgs.age-plugin-yubikey
          pkgs.age-plugin-tpm
        ];
      };

      secrets = lib.listToAttrs (
        map (
          f:
          lib.nameValuePair (ageName f) {
            rekeyFile = f.source;
            inherit (f) owner group mode;
          }
        ) cfg.lowered
      );
    };

    systemd.services.cluster-secrets = {
      description = "Require every secret this node was given";
      wantedBy = [ "multi-user.target" ];
      before = cfg.gate;
      requiredBy = cfg.gate;
      # Once per boot. Restarted on a switch, it would restart what it gates.
      restartIfChanged = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = check;
      };
    };

    systemd.services.cluster-secrets-watch = {
      description = "Check that every secret this node was given is still there";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = check;
      };
    };
    systemd.timers.cluster-secrets-watch = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitActiveSec = "1min";
        AccuracySec = "10s";
      };
    };
  };
}
