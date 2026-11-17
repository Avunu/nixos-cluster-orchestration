# modules/github-access.nix — how a node reads the site's private GitHub repositories:
# its own flake, the flake's private inputs, and what an app fetches at evaluation.
#
# All of the cluster's GitHub access is one GitHub App, and its private key is in the
# cluster-ci Worker (workers/cluster-ci) and, encrypted to the operators, in the site's
# repository (`github-app`, modules/vars.nix). No node holds it. A node asks the
# Worker, with the per-node bearer token of the pipeline's agent (`ci/token`), and is
# handed installation tokens that GitHub itself has narrowed: read-only, the
# repositories the site uses, one hour. Which repositories those are is read by the
# Worker from the site's repository, never from the node (src/access.js there, and
# lib/github-repos.nix for the ones no lock names).
#
# So what a stolen node can reach at GitHub is what it could already read, for at most
# an hour after its token is taken out of the Worker's AGENT_TOKENS.
#
# `topology.ci.url` turns it on, since the Worker is who is asked. A site without it
# has no tokens and reads public repositories only: whether a repository is private
# cannot be known at evaluation, so a private one then fails where it is fetched, with
# GitHub's "not found", in cluster-upgrade's log.
#
# ── what is written, and who reads it ────────────────────────────────────────
# modules/github-access.py, as cluster-github-token.service, writes two files under
# /run/cluster-github (a tmpfs; 0600, root), each by rename:
#
#   nix.conf      `access-tokens = github.com/<owner>/<repo>=<token> …`, read by Nix's
#                 own `github:` fetcher, which takes the longest prefix that matches
#                 (libfetchers/github.cc, getAccessToken; Nix 2.35). `!include`d below,
#                 and `!include` of a file that is not there, or that the caller may
#                 not read, is ignored: a node with no token degrades to public
#                 repositories, and no nix command fails to parse its configuration.
#   tokens.json   the same tokens with their repositories and expiry, read by the
#                 credential helper.
#
# `access-tokens` is not enough: for a `git+https://` input (a project with submodules)
# and for builtins.fetchGit, Nix runs `git fetch`, which knows nothing of it and asks
# for a username. A netrc answered that while there was one token for all of
# github.com; it cannot tell one owner from another. So git is given a credential
# helper, in the system's git configuration, for https://github.com only and with
# `useHttpPath`, so that git names the repository it wants and is answered with that
# repository's token or with nothing.
#
# Why the system's configuration: every fetch of a flake on a node runs as root, in the
# process that evaluates (the pull loop's `nix build`, the agent's, a pushed
# nixos-rebuild), not in the nix-daemon; Nix starts git with its own environment
# unchanged (libfetchers/git-utils.cc, `fetch`), and a root system service has no HOME,
# so git reads no per-user configuration there. /etc/gitconfig is read by all of them.
# Any other user's git runs the helper too and gets nothing: it cannot read the file.
#
# ── when ─────────────────────────────────────────────────────────────────────
# On a timer, every ten minutes: the Worker hands out nothing with under half an hour
# left, so a node always holds a token good for the next build. And before each tick of
# the pull loop, which wants this unit and runs after it, so the first pull after a
# boot does not depend on the timer having fired. Wants, not requires: a Worker that is
# away must not stop a pull that a still-good token, or a public repository, would
# serve. The agent starts it before a preview's build for the same reason
# (modules/ci-agent.py).
#
# Never part of boot: nothing in multi-user.target pulls the service in, it is a
# oneshot with no Restart=, and its three tries end within minutes. After an install the
# node's `ci/token` is in its first closure, so the order is: activation decrypts it,
# the timer (or the first pull, five minutes in) asks the Worker, and the pull follows.
#
# GitHubTokenStale (lib/alert-rules.nix) reads the last success, so a Worker outage is
# seen while the tokens held are still good.
{
  config,
  lib,
  pkgs,
  topology,
  ...
}:
let
  url = topology.ci.url or null;
  enabled = url != null;
  runDir = "/run/cluster-github";
  layout = import ../lib/secrets-layout.nix;

  tool = pkgs.writeScript "cluster-github-access" (
    "#!${pkgs.python3}/bin/python3\n" + builtins.readFile ./github-access.py
  );
in
{
  options.cluster.github = {
    enable = lib.mkOption {
      type = lib.types.bool;
      readOnly = true;
      default = enabled;
      description = "Whether this node asks the cluster-ci Worker for read access to the site's GitHub repositories (topology.ci.url).";
    };

    repositories = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+");
      default = [ ];
      example = [ "OWNER/private-addons" ];
      description = ''
        GitHub repositories ("OWNER/name") this site fetches that its flake.lock does not
        name. The kinds add their own (a WordPress site's content, an app's
        `preview.repo`); add a project's private submodules here, in a module of the
        site's. The site's `github-repos.json` is written from this (`avc ci repos`) and
        held to it by the merge gate (lib/github-repos.nix), and the cluster-ci Worker
        gives the nodes read access to these, the site's own repository and its lock's
        inputs, and to nothing else.
      '';
    };

    tool = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = tool;
      description = "modules/github-access.py, for the tests.";
    };
  };

  config = lib.mkMerge [
    {
      # What modules/pull-deploy.nix linked for the token this replaced. Only that link:
      # a netrc someone put there is theirs.
      system.activationScripts.cluster-github-netrc = ''
        if [ -L /root/.netrc ] && [ "$(readlink /root/.netrc)" = ${layout.runtimeDir}/shared/github-token/netrc ]; then
          rm -f /root/.netrc
        fi
      '';
    }

    (lib.mkIf enabled {
      nix.extraOptions = ''
        !include ${runDir}/nix.conf
      '';

      programs.git = {
        enable = true;
        config.credential."https://github.com" = {
          useHttpPath = true;
          helper = "${tool} credential";
        };
      };

      systemd.tmpfiles.rules = [ "d ${runDir} 0700 root root -" ];

      systemd.services.cluster-github-token = {
        description = "Read access to the site's GitHub repositories, from the cluster-ci Worker";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        environment = {
          GITHUB_ACCESS_URL = "${lib.removeSuffix "/" (toString url)}/agent/token";
          RUN_DIR = runDir;
          METRICS_DIR = "/var/lib/prometheus-node-exporter-text";
        };
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${tool} refresh";
          LoadCredential = [ "token:${config.cluster.secrets.generators.ci.files.token.path}" ];
          # Three tries of a minute at most, and the pauses between them.
          TimeoutStartSec = "5min";
        };
      };

      systemd.timers.cluster-github-token = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "30s";
          OnUnitActiveSec = "10min";
          RandomizedDelaySec = "30s";
        };
      };

      # The pull runs with a token asked for just now, when the Worker answers, and
      # with whatever is held when it does not.
      systemd.services.cluster-upgrade = {
        wants = [ "cluster-github-token.service" ];
        after = [ "cluster-github-token.service" ];
      };
    })
  ];
}
