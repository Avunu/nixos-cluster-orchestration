from __future__ import annotations

from pathlib import Path

import pytest

from avc.context import Ctx
from avc.core.index import parse_index

INDEX = {
    "leader": "node1",
    "flakeUrl": "github:example/cluster",
    "nodes": {
        "node1": {
            "fqdn": "node1.example.com",
            "tags": ["nomad-leader"],
            "deployHost": "192.0.2.1",
            "nomad": {
                "addr": "https://10.10.0.1:4646",
                "caCert": "/run/secrets/shared/nomad-ca/ca.crt",
                "clientCert": "/run/secrets/per-machine/node1/nomad-tls/cli.crt",
                "clientKey": "/run/secrets/per-machine/node1/nomad-tls/cli.key",
                "namespace": "apps",
                "tokenPath": "/run/nomad-tokens/avc",
            },
            "boot": {
                "enabled": True,
                "sshPort": 2222,
                "hostKeyPub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureInitrdHostKeyNotARealOne0000000000 initrd-host",
            },
        }
    },
    "apps": {
        "demo-erp": {"kind": "frappe", "homeNode": "node1", "job": "app-demo-erp", "tunnel": "t1", "hostnames": ["erp.example.com"], "generators": ["demo-erp", "demo-erp-cf"]},
        "demo-idm": {"kind": "freeipa", "homeNode": "node1", "job": "app-demo-idm", "tunnel": "t2", "hostnames": [], "generators": ["demo-idm", "demo-idm-authelia"]},
        "blog": {"kind": "wordpress", "homeNode": "node1", "job": "app-blog", "tunnel": "t3", "hostnames": [], "generators": ["wp-blog", "wp-blog-api"]},
    },
}


@pytest.fixture
def index():
    return parse_index(INDEX)


@pytest.fixture
def ctx(tmp_path: Path, index) -> Ctx:
    c = Ctx(tmp_path)
    c.__dict__["index"] = index
    c.__dict__["installed"] = ["node1"]
    return c


@pytest.fixture
def repo_root() -> Path | None:
    """The real repository, when the tests run from a checkout."""
    root = Path(__file__).resolve().parents[3]
    return root if (root / "secrets" / "policy.toml").exists() else None
