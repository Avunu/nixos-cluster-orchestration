from __future__ import annotations

import shlex

from avc.core.node import Node


def test_nomad_cmd_presents_the_nodes_client_certificate(index):
    """The API refuses a TLS handshake without a client certificate
    (verify_https_client), so every CLI call avc makes on a node names the CA, the
    node's CLI certificate and its key from the index, over https."""
    info = index.nodes["node1"]
    cmd = Node("node1", info).nomad_cmd("job status")
    words = shlex.split(cmd.replace('"$(cat ', "").replace(')"', ""))
    env = dict(w.split("=", 1) for w in words if "=" in w)
    assert env["NOMAD_ADDR"] == "https://10.10.0.1:4646"
    assert env["NOMAD_CACERT"] == info["nomad"]["caCert"]
    assert env["NOMAD_CLIENT_CERT"] == info["nomad"]["clientCert"]
    assert env["NOMAD_CLIENT_KEY"] == info["nomad"]["clientKey"]
    assert cmd.endswith("nomad job status")


def test_nomad_cmd_uses_the_scoped_avc_token_in_the_apps_namespace(index):
    """Every app's job is in `apps`, and `default` runs nothing, so a bare `nomad job
    status` must look there. The token is the node's own `avc` login, never the
    management token (which only the nomad-leader node holds)."""
    info = index.nodes["node1"]
    cmd = Node("node1", info).nomad_cmd("job status")
    words = shlex.split(cmd.replace('"$(cat ', "").replace(')"', ""))
    env = dict(w.split("=", 1) for w in words if "=" in w)
    assert env["NOMAD_NAMESPACE"] == "apps"
    assert env["NOMAD_TOKEN"] == "/run/nomad-tokens/avc"
    assert "nomad-acl" not in cmd
