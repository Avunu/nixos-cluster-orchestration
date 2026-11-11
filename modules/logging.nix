# modules/logging.nix — per-node log shipper: every journal on this node -> Loki.
#
# EVERY node runs one Vector, the only collector in the cluster; nothing runs
# inside a container. It reads:
#   - the host's own journal (Nomad, JuiceFS, the container@ units' console…);
#   - each app container's persistent journal, straight from the host's
#     filesystem at /var/lib/nixos-containers/<app>/var/log/journal;
#   - any extra journal an app declares (clusterApps.<n>.logging.journalDirs),
#     e.g. FreeIPA's, which lives in the image's own systemd under podman;
# and pushes to Loki on the `metrics` node (modules/logging-server.nix) over
# the control VLAN.
#
# Why read the directories rather than the host journal: nspawn's
# --link-journal=try-guest only symlinks /var/log/journal/<machine-id> to the
# transient /tmp/nspawn-root-* path of the container's start -- dangling once
# the container is up (seen on node1) -- so the host's journalctl never sees a
# container's entries. Same finding, same fix as an earlier deployment.
#
# Containers are dormant on every node and only start where Nomad puts them,
# so most of these directories are empty on most nodes. They are created
# anyway: journalctl -D on a MISSING directory exits at once, but on an empty
# one it waits and picks up the <machine-id>/ directory the guest's journald
# creates on first start (verified). And an app that moves away leaves its
# journal behind -- harmless, because Vector checkpoints each source's cursor
# and never ships an entry twice.
#
# Labels are the contract Grafana, the dashboards and lib/log-alert-rules.nix
# query by; see the README ("Logs"). The payload flakes supply APP_SERVICE and
# APP_SITE as journal fields (systemd LogExtraFields=), and write <N> syslog
# prefixes so PRIORITY is right; this normalizes whatever arrives.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  node,
  ...
}:
let
  net = clusterLib.net;
  apps = config.clusterApps;
  metricsNode = net.soleTaggedNode topology "metrics";

  checkVrl = import ../lib/vrl-check.nix { inherit pkgs lib; };

  containerJournal = n: "/var/lib/nixos-containers/${n}/var/log/journal";

  # Loki's retention (topology.logging.retention, one number and one unit, as "720h"), in
  # minutes, for the sweep of a retired store below. null if it is written otherwise.
  retentionMinutes =
    let
      m = builtins.match "([0-9]+)(m|h|d|w|y)" topology.logging.retention;
      per = {
        m = 1;
        h = 60;
        d = 1440;
        w = 10080;
        y = 525600;
      };
    in
    if m == null then null else lib.toInt (builtins.head m) * per.${lib.last m};
  lokiStore = "/var/lib/loki";

  # One journald source per journal directory, and a remap stamping `app` on
  # everything from it: the directory is what knows which app an entry belongs
  # to, not the entry (a guest's _HOSTNAME is whatever the guest set).
  appJournals = lib.concatLists (
    lib.mapAttrsToList (
      n: app:
      lib.imap0 (i: dir: {
        inherit n dir;
        id = if i == 0 then "journald-app-${n}" else "journald-app-${n}-${toString i}";
      }) ([ (containerJournal n) ] ++ app.logging.journalDirs)
    ) apps
  );

  # Stable labels. `node` comes from this configuration, not the entry, so an
  # app that Nomad moves keeps its `app` and only `node` changes.
  normalize = ''
    .node = "${node.hostName}"

    # Structured metadata, not labels: unbounded or per-process values that are
    # still worth filtering by (`| unit="…"`) without multiplying streams.
    .container_host = if exists(.host) { to_string(.host) ?? "" } else { "" }
    .unit = if exists(._SYSTEMD_UNIT) { to_string(._SYSTEMD_UNIT) ?? "unknown" } else { "unknown" }
    # A burst of session-1234.scope / run-u42.service units would otherwise fan
    # out into one stream each.
    if match(.unit, r'^(session-.*\.scope|user@.*\.service|run-.*)$') {
      .unit = "transient"
    }
    .syslog_identifier = if exists(.SYSLOG_IDENTIFIER) { to_string(.SYSLOG_IDENTIFIER) ?? "" } else { "" }
    .pid = if exists(._PID) { to_string(._PID) ?? "" } else { "" }

    # Container journals were stamped by their source. On the host journal, a
    # container's console (container@<app>.service) is that app's; the rest
    # is the platform itself.
    if !exists(.app) {
      .app = "platform"
      m, err = parse_regex(.unit, r'^container@(?P<app>.+)\.service$')
      if err == null {
        .app = m.app
      }
    }

    # The payload's own name for the process (APP_SERVICE: web, worker, db…),
    # else the unit without its suffix and instance.
    .service = if exists(.APP_SERVICE) { to_string(.APP_SERVICE) ?? "" } else { "" }
    if .service == "" {
      .service = replace(replace(.unit, r'\.(service|scope|socket|timer|mount)$', ""), r'@.*$', "")
    }

    # The Frappe site / Odoo database / WordPress site, when the payload says;
    # else the app, so the label is never empty.
    .site = if exists(.APP_SITE) { to_string(.APP_SITE) ?? "" } else { "" }
    if .site == "" {
      .site = .app
    }

    # Syslog PRIORITY -> name. Independent ifs, not an if/else chain: VRL ends
    # an expression at a newline, which makes a multi-line else-if brittle.
    prio = if exists(.PRIORITY) { to_string(.PRIORITY) ?? "6" } else { "6" }
    .level = "info"
    if prio == "0" { .level = "emerg" }
    if prio == "1" { .level = "alert" }
    if prio == "2" { .level = "crit" }
    if prio == "3" { .level = "err" }
    if prio == "4" { .level = "warning" }
    if prio == "5" { .level = "notice" }
    if prio == "7" { .level = "debug" }

    # stdout is PRIORITY 6 whatever it says. JSON loggers (Caddy/FrankenPHP,
    # the payloads' nginx access log) say it in the line instead: take their
    # level, or for an access line without one, call a 5xx an error. Never a
    # label from the line's other fields -- a Host header is client-controlled,
    # and a label from it is an unbounded stream count.
    msg = to_string(.message) ?? ""
    if prio == "6" && starts_with(msg, "{") {
      parsed, err = parse_json(msg)
      if err == null && is_object(parsed) {
        lv = downcase(to_string(parsed.level) ?? "")
        if lv == "" { lv = downcase(to_string(parsed.severity) ?? "") }
        if lv == "warn" { lv = "warning" }
        if lv == "error" { lv = "err" }
        if lv == "fatal" || lv == "panic" || lv == "critical" { lv = "crit" }
        if includes(["debug", "info", "notice", "warning", "err", "crit", "alert", "emerg"], lv) {
          .level = lv
        }
        if lv == "" {
          status = to_int(parsed.status) ?? 0
          if status >= 500 { .level = "err" }
        }
      }
    }
  '';

  normalizeCases = [
    {
      # A container's console, from the host journal.
      sample = {
        message = "Spawning container demo-odoo";
        host = node.hostName;
        _SYSTEMD_UNIT = "container@demo-odoo.service";
        PRIORITY = "6";
      };
      expect = [
        ''"app": "demo-odoo"''
        ''"service": "container"''
        ''"site": "demo-odoo"''
        ''"level": "info"''
        ''"node": "${node.hostName}"''
      ];
    }
    {
      # A payload unit carrying the journal field contract.
      sample = {
        app = "demo-erp";
        message = "frappe.web [erp.example.com] boom";
        _SYSTEMD_UNIT = "frappe-erp.example.com.service";
        PRIORITY = "3";
        APP_SERVICE = "runtime";
        APP_SITE = "erp.example.com";
      };
      expect = [
        ''"app": "demo-erp"''
        ''"service": "runtime"''
        ''"site": "erp.example.com"''
        ''"level": "err"''
      ];
    }
    {
      # An nginx JSON access line for a 502: no level field, so the status.
      sample = {
        app = "demo-odoo";
        message = builtins.toJSON {
          status = 502;
          uri = "/web";
        };
        _SYSTEMD_UNIT = "nginx.service";
        SYSLOG_IDENTIFIER = "nginx_access";
        PRIORITY = "6";
        APP_SERVICE = "nginx";
      };
      expect = [
        ''"service": "nginx"''
        ''"level": "err"''
        ''"syslog_identifier": "nginx_access"''
      ];
    }
    {
      # Caddy/FrankenPHP JSON on stdout: the line's own level wins.
      sample = {
        app = "pilot";
        message = builtins.toJSON {
          level = "warn";
          logger = "http.log.access";
        };
        _SYSTEMD_UNIT = "wordpress.service";
        PRIORITY = "6";
        APP_SERVICE = "web";
        APP_SITE = "pilot";
      };
      expect = [
        ''"level": "warning"''
        ''"service": "web"''
      ];
    }
    {
      # Session scopes collapse; no unit field at all still yields labels.
      sample = {
        message = "session opened";
        _SYSTEMD_UNIT = "session-12.scope";
      };
      expect = [
        ''"app": "platform"''
        ''"service": "transient"''
        ''"unit": "transient"''
      ];
    }
  ];

  # Groups that own journals written by someone else's journald: a container
  # image's systemd-journal GID need not be ours (FreeIPA's AlmaLinux uses 190).
  extraJournalGroups = lib.unique (
    lib.concatMap (app: app.logging.journalGroups) (lib.attrValues apps)
  );
  # A bare GID must exist on the host: systemd will not hand a DynamicUser a
  # group it cannot resolve, and fails the unit instead ("Failed to determine
  # supplementary groups", 216/GROUP) -- so Vector shipped nothing at all once
  # FreeIPA's 190 was added. Each numeric GID gets a named host group.
  isGid = g: builtins.match "[0-9]+" g != null;
  gidGroup = g: "journal-gid-${g}";
  journalGroupNames = map (g: if isGid g then gidGroup g else g) extraJournalGroups;
in
{
  # A program that fails its cases fails the system's build (lib/vrl-check.nix).
  system.extraDependencies = [ (checkVrl "normalize" normalizeCases normalize) ];

  # Pre-create every app's container journal directory (see the header). The
  # setgid bit and group match what the guest's journald creates itself.
  systemd.tmpfiles.rules = map (n: "d ${containerJournal n} 2755 root systemd-journal -") (
    lib.attrNames apps
  );

  services.vector = {
    enable = true;
    settings = {
      sources = {
        journald = {
          type = "journald";
          # Not just this boot: the cursor is checkpointed, so after a reboot
          # (or a Loki outage that spans one) the rest of the previous boot
          # still ships. It is also what makes an empty directory work at all
          # -- with a boot filter, journalctl exits on "no boot entry found".
          current_boot_only = false;
        };
        internal_metrics.type = "internal_metrics";
      }
      // lib.listToAttrs (
        map (j: {
          name = j.id;
          value = {
            type = "journald";
            journal_directory = j.dir;
            current_boot_only = false;
          };
        }) appJournals
      );

      transforms = {
        normalize = {
          type = "remap";
          inputs = [ "journald" ] ++ map (j: "tag-${j.id}") appJournals;
          source = normalize;
        };
      }
      // lib.listToAttrs (
        map (j: {
          name = "tag-${j.id}";
          value = {
            type = "remap";
            inputs = [ j.id ];
            source = ''.app = "${j.n}"'';
          };
        }) appJournals
      );

      sinks = {
        loki = {
          type = "loki";
          inputs = [ "normalize" ];
          # Over the control mesh: Loki listens on nothing else.
          endpoint = "http://${net.meshIp topology metricsNode}:${toString net.lokiPort}";
          labels = {
            node = "{{ node }}";
            app = "{{ app }}";
            site = "{{ site }}";
            service = "{{ service }}";
            level = "{{ level }}";
          };
          structured_metadata = {
            unit = "{{ unit }}";
            syslog_identifier = "{{ syslog_identifier }}";
            pid = "{{ pid }}";
            container_host = "{{ container_host }}";
          };
          # The line is the message alone: a traceback reads as a traceback.
          # Everything a developer filters by is a label or metadata above,
          # and a JSON message (Caddy, nginx) still works with `| json`.
          encoding.codec = "text";
          out_of_order_action = "accept";
          # The journal is the buffer: a journald source only advances its
          # checkpointed cursor once Loki has accepted the batch, so a Loki or
          # metrics-node outage delays logs rather than dropping them.
          acknowledgements.enabled = true;
        };

        # Scraped by Prometheus (job `vector`): LogShippingStalled alerts on it.
        metrics = {
          type = "prometheus_exporter";
          inputs = [ "internal_metrics" ];
          address = "${net.meshIp topology node}:${toString net.vectorMetricsPort}";
        };
      };
    };
  };

  # services.vector's DynamicUser has no groups, and journal files are
  # root:systemd-journal 0640 -- without this, journalctl opens nothing and
  # Vector ships nothing, silently. Set here rather
  # than with journaldAccess, which sets a string that would not merge with
  # the extra groups.
  #
  # Its metrics listener binds the mesh address, and its sink is on the mesh.
  systemd.services.vector = lib.mkMerge [
    net.meshBoundUnit
    {
      serviceConfig.SupplementaryGroups = [
        "systemd-journal"
      ]
      ++ journalGroupNames;
    }
  ];

  users.groups = lib.listToAttrs (
    map (g: lib.nameValuePair (gidGroup g) { gid = lib.toInt g; }) (lib.filter isGid extraJournalGroups)
  );

  # A node that does not run Loki keeps whatever Loki left in its store: rpool/loki is on
  # every node (lib/mk-disk-layout.nix), so that the `metrics` tag can move, and Loki's
  # compactor, which applies the retention, runs only where Loki does. After a move the
  # old node would keep client-bearing lines past retention for good. So the same
  # retention is applied here: a file older than it goes. Nothing younger is touched, so a
  # tag that comes back, or is dropped for a moment, loses nothing Loki would have kept.
  assertions = [
    {
      assertion = retentionMinutes != null;
      message = "topology.logging.retention must be one number and one unit (m, h, d, w or y), such as \"720h\": it is also the age past which a node without Loki deletes what is left in ${lokiStore}.";
    }
  ];
  systemd.services.loki-retired-store =
    lib.mkIf (!config.services.loki.enable && retentionMinutes != null)
      {
        description = "Delete what a former Loki left in ${lokiStore} past the log retention";
        path = [ pkgs.findutils ];
        serviceConfig.Type = "oneshot";
        script = ''
          [ -d ${lokiStore} ] || exit 0
          find ${lokiStore} -xdev -mindepth 1 -type f -mmin +${toString retentionMinutes} -print -delete
          find ${lokiStore} -xdev -mindepth 1 -type d -empty -delete
        '';
      };
  systemd.timers.loki-retired-store =
    lib.mkIf (!config.services.loki.enable && retentionMinutes != null)
      {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = "daily";
          Persistent = true;
          RandomizedDelaySec = "1h";
        };
      };
}
