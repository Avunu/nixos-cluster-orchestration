# The Tang host (modules/tang-server.nix), from outside and from inside: what answers on
# which interface, what the key guard refuses, the key tool's rotation with a real Clevis
# client bound at t=2, the self-probe and the /rec events reaching the real audit Worker,
# and a reboot. The `stock` VM runs `services.tang` alone and must show every hazard the
# module exists for, or the guard's tests have proven nothing (design WS15, Appendix N).
#
#   vps       the Tang host: public NIC (SSH only) and private NIC (Tang only)
#   node      a Clevis client on the private network, with a TPM and a spare disk
#   outsider  the public side, running the real watchdog Worker as the off-host receiver
#   stock     services.tang alone, the hazard control; also a private-network address
#             outside allowedClients
#
# Every address is from a documentation or private range, and every key a throwaway.
{
  pkgs,
  lib,
  mutant ? "",
  extraModule ? { },
}:
let
  tangServerModule = ../modules/tang-server.nix;

  port = 7654;
  vps = {
    public = "192.0.2.2";
    private = "10.40.0.1";
  };
  outsiderAddress = "192.0.2.3";
  nodeAddress = "10.40.0.11";
  # On the private network, outside allowedClients.
  strangerAddress = "10.40.0.99";
  allowedClients = [ "10.40.0.0/28" ];

  receiver = {
    port = 8080;
    token = "tang-server-test-audit-token";
    out = "/var/lib/audit-stub";
  };
  eventUrl = "http://${outsiderAddress}:${toString receiver.port}/event";

  # A signing and exchange pair fixed here, so the `pinned` specialisation can pin its
  # thumbprint at evaluation, as a site pins its Tang host's. Throwaway: they exist for
  # these VMs and open nothing else. `jose jwk thp -a S256` gives the names.
  pinnedThumbprint = "NZLwh7fR-bPtAsjY1g6aRuhZNLaLNQA67Nlx9wX7XBU";
  pinnedKeys = {
    "${pinnedThumbprint}.jwk" = pkgs.writeText "pinned-sig.jwk" (
      builtins.toJSON {
        alg = "ES512";
        crv = "P-521";
        d = "AClyxgMxTFLCNCV1_MVD4IH3PNB0CRdEXv2s8Vi27VZy5MWmAfxuOtEbUnhFqm4vVlTxkhLdQL0vrF1zf2x7Y82N";
        key_ops = [
          "sign"
          "verify"
        ];
        kty = "EC";
        x = "Aflkqj-zCL6DWShTzLKaRToJc7C0NW_YRxHUS1D5QJgXZtGiq5XYo_Wpp04z7LFsErLRekqSZbXU8_Rj0fBgcvBq";
        y = "ACV-6THSmA-T_dp5UuSnkY5E0ZHlV0jnotbBXkGXVdkGuz0TrudWJq2ENPJCbxNxSL4FiOC3KkJ9ep1XoOyc_9zh";
      }
    );
    "G7ZktkXGo1TgtD9Q7evsRjEtCdVgjnPQVbAEcjOJMSk.jwk" = pkgs.writeText "pinned-exc.jwk" (
      builtins.toJSON {
        alg = "ECMR";
        crv = "P-521";
        d = "ACJQHPjSVSMAauERLnD-oEaPAET0V-yLC0qEf6CwbyAn6BbD3ZE33i2Z9RujAU51F8JT6R7ovNANjpVzUR4zdH_v";
        key_ops = [ "deriveKey" ];
        kty = "EC";
        x = "ALYHT53cH42Et3E9DTN-uS6s53aJ2Pkyd3pn6g2Cnj1AY11zB8TA5sKE-iBV87phxyKsONQbpMRqGDKmxVtwpEUA";
        y = "ATk65Tpiwfkzm6uubp6r_1X1elNIt7KekNHgzFOfV9pf7m_I0cPiSPFjWsmaBSXV1-m42ZKDNxa3I0UwhKwKq1HW";
      }
    );
  };
  pinnedKeyDir = pkgs.linkFarm "tang-pinned-keys" (
    lib.mapAttrsToList (name: path: { inherit name path; }) pinnedKeys
  );

  # A Tang that accepts and never answers (Appendix O). A port with nothing behind it
  # refuses at once, and a client that returns rc=1 in 0 s has proven nothing about
  # silence [RAN in the prototype], so each held connection is logged.
  silentTang = pkgs.writeText "silent-tang.py" ''
    import socket
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", ${toString port}))
    s.listen(64)
    held = []
    while True:
        c, peer = s.accept()
        print(f"silent-tang: holding a connection from {peer[0]}", flush=True)
        held.append(c)
  '';

  tamperedTang = pkgs.writeText "tampered-tang.py" ''
    import http.server
    body = open("/root/tampered.jws", "rb").read()


    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/jose+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


    http.server.HTTPServer(("0.0.0.0", ${toString port}), H).serve_forever()
  '';

  # The module's refusals, evaluated with nothing but nixpkgs' own module list: no
  # `node`, `topology`, `clusterLib` or clan, which is also the proof that the module
  # needs none of them. Each case names the message it must fail with; only the
  # module's own assertions are forced.
  evalTang =
    module:
    import "${pkgs.path}/nixos/lib/eval-config.nix" {
      system = null;
      inherit pkgs lib;
      modules = [
        tangServerModule
        {
          # Defaults, so that a case can set any of them.
          cluster.tangServer = {
            enable = true;
            privateInterface = lib.mkDefault "eth2";
            publicInterface = lib.mkDefault "eth1";
            allowedClients = lib.mkDefault allowedClients;
          };
        }
        module
      ];
    };
  # The module's own definitions of `assertions` only: forcing every module's messages
  # would evaluate assertions that are meaningless in a system this bare.
  tangFailures =
    module:
    lib.concatMap (d: map (a: a.message) (lib.filter (a: !a.assertion) d.value)) (
      lib.filter (d: lib.hasSuffix "/modules/tang-server.nix" (toString d.file))
        (evalTang module).options.assertions.definitionsWithLocations
    );
  refusals = [
    {
      name = "firewall off";
      module.networking.firewall.enable = false;
      message = "tang-server: the firewall is half of the design";
    }
    {
      name = "Tang port open on every interface";
      module.networking.firewall.allowedTCPPorts = [ port ];
      message = "tang-server: the Tang port must not be open globally";
    }
    {
      name = "Tang port inside a global range";
      module.networking.firewall.allowedTCPPortRanges = [
        {
          from = 7000;
          to = 8000;
        }
      ];
      message = "tang-server: the Tang port must not be open globally";
    }
    {
      name = "SSH opened on every interface";
      module.services.openssh.openFirewall = lib.mkForce true;
      message = "tang-server: set services.openssh.openFirewall = false; SSH opens only on publicInterface";
    }
    {
      name = "one interface for both";
      module.cluster.tangServer.publicInterface = "eth2";
      message = "tang-server: public and private interfaces must differ";
    }
    {
      name = "a monitor URL without a token";
      module.cluster.tangServer.monitor.eventUrl = eventUrl;
      message = "tang-server: monitor.tokenFile is required when monitor.heartbeatUrl or monitor.eventUrl is set";
    }
    # The heartbeat alone, so an assertion that reads only eventUrl can't pass.
    {
      name = "a heartbeat URL without a token";
      module.cluster.tangServer.monitor.heartbeatUrl = eventUrl;
      message = "tang-server: monitor.tokenFile is required when monitor.heartbeatUrl or monitor.eventUrl is set";
    }
    # The public NIC's own list: IPAddressAllow would then be all in front of tangd.
    {
      name = "Tang port open on the public interface";
      module.networking.firewall.interfaces.eth1.allowedTCPPorts = [ port ];
      message = "tang-server: the Tang port must be open on privateInterface only, not on eth1";
    }
    {
      name = "Tang port inside a range on another interface";
      module.networking.firewall.interfaces.eth3.allowedTCPPortRanges = [
        {
          from = 7000;
          to = 8000;
        }
      ];
      message = "tang-server: the Tang port must be open on privateInterface only, not on eth3";
    }
  ];
  refusalResults = map (
    c:
    let
      got = tangFailures c.module;
    in
    if got == [ c.message ] then
      "refused: ${c.name}"
    else
      throw "tang-server eval case '${c.name}': expected exactly [ ${c.message} ], got ${builtins.toJSON got}"
  ) refusals;
  # Without this, a module whose assertions all fail would pass every case above.
  baseline =
    let
      got = tangFailures { };
    in
    if got == [ ] then
      "evaluates: baseline, with no node, topology or clan"
    else
      throw "tang-server eval baseline refused: ${builtins.toJSON got}";
  # A type, not an assertion: an empty allow list leaves only loopback. The same read of
  # the baseline must succeed, or the refusal could be any error at all.
  clientsEvaluate =
    module:
    (builtins.tryEval (builtins.deepSeq (evalTang module).config.services.tang.ipAddressAllow true))
    .success;
  emptyClients =
    if !clientsEvaluate { } then
      throw "tang-server eval: the baseline's ipAddressAllow does not evaluate"
    else if clientsEvaluate { cluster.tangServer.allowedClients = lib.mkForce [ ]; } then
      throw "tang-server eval: allowedClients = [ ] was accepted"
    else
      "refused: an empty allowedClients";
  evalReport = [ baseline ] ++ refusalResults ++ [ emptyClients ];
in
pkgs.testers.runNixOSTest {
  name = "tang-server";
  skipLint = true;
  skipTypeCheck = true;

  nodes.vps =
    { lib, pkgs, ... }:
    {
      imports = [
        tangServerModule
        extraModule
      ];
      virtualisation.memorySize = 1024;
      virtualisation.vlans = [
        1
        2
      ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = vps.public;
          prefixLength = 24;
        }
      ];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
        {
          address = vps.private;
          prefixLength = 24;
        }
      ];
      networking.firewall.enable = true;
      services.openssh.enable = true;

      cluster.tangServer = {
        enable = true;
        inherit port allowedClients;
        privateInterface = "eth2";
        publicInterface = "eth1";
        monitor = {
          heartbeatUrl = eventUrl;
          inherit eventUrl;
          tokenFile = "${pkgs.writeText "tang-audit-token" receiver.token}";
        };
      };
      # The same host once its operator has pinned a signing key: the guard then also
      # needs that key, and the probe needs /adv signed by it.
      specialisation.pinned.configuration.cluster.tangServer.pinnedThumbprints = [ pinnedThumbprint ];
      # Every address let through the socket's IPAddressAllow, so `surface` can see what
      # the firewall alone does on the public NIC: with the default list, IPAddressAllow
      # drops the outsider's SYN too and the two can't be told apart.
      specialisation.open-clients.configuration.cluster.tangServer.allowedClients = lib.mkForce [
        "0.0.0.0/0"
        "::/0"
      ];
      system.switch.enable = true;

      # A Tang whose /adv was altered after it was signed: only the probe's signature
      # check can tell (its signer is still a key the advertisement carries).
      systemd.services.tampered-tang = {
        description = "Serves /root/tampered.jws as /adv";
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${tamperedTang}";
      };
      systemd.services.silent-tang = {
        description = "A Tang that accepts and never answers";
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${silentTang}";
      };
      environment.systemPackages = [
        pkgs.jq
        pkgs.tang
      ];
    };

  nodes.node =
    { lib, pkgs, ... }:
    {
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 2 ];
      virtualisation.tpm.enable = true;
      virtualisation.emptyDiskImages = [ 64 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = nodeAddress;
          prefixLength = 24;
        }
      ];
      environment.systemPackages = [
        pkgs.clevis
        pkgs.cryptsetup
        pkgs.curl
        pkgs.jose
        pkgs.jq
        pkgs.openssh
        pkgs.tpm2-tools
      ];
    };

  nodes.outsider =
    { lib, pkgs, ... }:
    {
      virtualisation.memorySize = 1024;
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = outsiderAddress;
          prefixLength = 24;
        }
      ];
      networking.firewall.allowedTCPPorts = [ receiver.port ];
      # The real Worker's fetch handler (tests/lib/audit-stub.mjs), so an event is
      # accepted only if the Worker itself would take it: token, sender, every field.
      systemd.services.audit-stub = {
        description = "The off-host audit receiver: the real Worker, on files";
        wantedBy = [ "multi-user.target" ];
        environment = {
          WORKER = "${../workers/cluster-watchdog}/src/index.js";
          PORT = toString receiver.port;
          OUT = receiver.out;
          AUDIT_TOKENS = builtins.toJSON {
            ${receiver.token} = {
              sender = "tang";
              kinds = [
                "tang_rec"
                "tang_probe"
              ];
            };
          };
          TANG_CLIENTS = builtins.toJSON { ${nodeAddress} = "node"; };
        };
        serviceConfig.ExecStart = "${pkgs.nodejs_22}/bin/node ${./lib/audit-stub.mjs}";
      };
      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
        pkgs.netcat
        pkgs.openssh
      ];
    };

  nodes.stock =
    { lib, pkgs, ... }:
    {
      virtualisation.vlans = [ 2 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = strangerAddress;
          prefixLength = 24;
        }
      ];
      services.tang = {
        enable = true;
        ipAddressAllow = [ "127.0.0.0/8" ];
      };
      environment.systemPackages = [
        pkgs.curl
        pkgs.jose
      ];
    };

  testScript = ''
    MUTANT = "${mutant}"
    PORT = ${toString port}
    VPS_PUBLIC = "${vps.public}"
    VPS_PRIVATE = "${vps.private}"
    OUTSIDER = "${outsiderAddress}"
    NODE = "${nodeAddress}"
    STRANGER = "${strangerAddress}"
    OUT = "${receiver.out}"
    PINNED = "${pinnedThumbprint}"
    PINNED_KEYS = "${pinnedKeyDir}"
    STOCK_ROTATE = "${pkgs.tang}/libexec/tangd-rotate-keys"
    EVAL_REPORT = ${builtins.toJSON evalReport}
    CORE_PATTERN = ${builtins.toJSON (import ../lib/core-pattern.nix)}
    ${builtins.readFile ./lib/control.py}
    ${builtins.readFile ./tang-server.py}

    run_main(main)
  '';
}
