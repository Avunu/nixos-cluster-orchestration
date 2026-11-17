"""`avc ci`: the Worker's AGENT_TOKENS, from each node's own vars; the GitHub App's values;
the repositories the site uses, and which of them an installation covers."""

from __future__ import annotations

import base64
import dataclasses
import json
import os
from pathlib import Path

import pytest

from avc.core import secretstore
from avc.errors import AvcError
from avc.flows import ci


def fleet(ctx, index, monkeypatch, enabled, value=lambda machine: f"tok-{machine}\n"):
    base = index.nodes["node1"]
    nodes = {n: {**base, "ci": {"enabled": on}} for n, on in enabled.items()}
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    asked = []

    def get_value(root, machine, var_id):
        asked.append((machine, var_id))
        return value(machine)

    monkeypatch.setattr(secretstore, "get_value", get_value)
    return asked


def test_each_node_with_an_agent_is_known_by_its_own_token(ctx, index, monkeypatch, capsys):
    asked = fleet(ctx, index, monkeypatch, {"node1": True, "node2": True, "node3": False})
    assert ci.agent_tokens(ctx) == {"tok-node1": "node1", "tok-node2": "node2"}
    assert asked == [("node1", "ci/token"), ("node2", "ci/token")]
    ci.tokens(ctx)
    assert json.loads(capsys.readouterr().out) == {"tok-node1": "node1", "tok-node2": "node2"}


def test_two_nodes_with_one_token_are_refused(ctx, index, monkeypatch):
    fleet(ctx, index, monkeypatch, {"node1": True, "node2": True}, value=lambda _: "same\n")
    with pytest.raises(AvcError, match="same ci/token"):
        ci.agent_tokens(ctx)


def test_a_site_without_the_pipeline_says_so(ctx, index, monkeypatch):
    fleet(ctx, index, monkeypatch, {"node1": False})
    with pytest.raises(AvcError, match="topology.ci.url"):
        ci.agent_tokens(ctx)


# ── the GitHub App ───────────────────────────────────────────────────────────


def app_secrets(monkeypatch, values):
    asked = []

    def get_value(root, machine, var_id):
        asked.append((machine, var_id))
        return values[var_id]

    monkeypatch.setattr(secretstore, "get_value", get_value)
    return asked


def test_the_apps_values_are_printed_one_at_a_time_from_the_shared_generator(ctx, monkeypatch, capsys):
    asked = app_secrets(monkeypatch, {"github-app/webhook-secret": "hook\n", "github-app/app-id": "42\n"})
    ci.app(ctx, "webhook-secret")
    assert capsys.readouterr().out == "hook\n"
    ci.app(ctx, "app-id")
    assert capsys.readouterr().out == "42\n"
    # Shared, so read through the reference machine; and one file per call, so one touch.
    assert asked == [("node1", "github-app/webhook-secret"), ("node1", "github-app/app-id")]
    with pytest.raises(AvcError, match="private-key"):
        ci.app(ctx, "ssh-key")


def test_avc_reads_a_sites_repositories_as_the_worker_does():
    fixture = os.environ.get("AVC_SITE_REPOS_FIXTURE") or Path(__file__).resolve().parents[3] / "workers/cluster-ci/test/site-repos.json"
    f = json.loads(Path(fixture).read_text())
    assert ci.site_repos(f["site"], f["lock"], f["extra"]) == f["expect"]
    assert ci.site_of("github:acme/cluster/prod") == "acme/cluster"
    with pytest.raises(AvcError, match="github:OWNER/name"):
        ci.site_of("git+https://example.com/x")


def with_repos(ctx, index, repos):
    ctx.__dict__["index"] = dataclasses.replace(index, github_repos=tuple(repos))


def test_repos_writes_the_file_the_merge_gate_holds_to_the_flake(ctx, index):
    path = ctx.root / "github-repos.json"
    with_repos(ctx, index, [])
    ci.repos(ctx)
    assert not path.exists()
    with_repos(ctx, index, ["customer/content", "acme/addons"])
    ci.repos(ctx)
    assert json.loads(path.read_text()) == ["acme/addons", "customer/content"]
    before = path.stat().st_mtime_ns
    ci.repos(ctx)
    assert path.stat().st_mtime_ns == before
    with_repos(ctx, index, [])
    ci.repos(ctx)
    assert not path.exists()


def rsa_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # PKCS#1, as GitHub hands it out.
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return key, pem.decode()


def test_the_apps_sign_in_is_a_jwt_github_would_check():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    key, pem = rsa_pem()
    head, claims, sig = ci.app_jwt("42", pem, now=1_700_000_000).split(".")
    unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    assert json.loads(unb64(head)) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(unb64(claims)) == {"iat": 1_700_000_000 - 60, "exp": 1_700_000_000 + 540, "iss": "42"}
    key.public_key().verify(unb64(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(AvcError, match="PEM"):
        ci.app_jwt("42", "not a key")


def test_installations_says_which_of_the_sites_repositories_are_not_covered(ctx, index, monkeypatch, capsys):
    _, pem = rsa_pem()
    asked = app_secrets(monkeypatch, {"github-app/app-id": "42", "github-app/private-key": pem})
    ctx.__dict__["index"] = dataclasses.replace(index, flake_url="github:acme/cluster", github_repos=("customer/content",))
    (ctx.root / "github-repos.json").write_text('["customer/content"]')
    (ctx.root / "flake.lock").write_text(
        json.dumps(
            {
                "nodes": {
                    "shop": {"locked": {"type": "github", "owner": "acme", "repo": "shop"}},
                    "other": {"locked": {"type": "github", "owner": "acme", "repo": "other"}},
                    "nixpkgs": {"locked": {"type": "github", "owner": "NixOS", "repo": "nixpkgs"}},
                    "paused": {"locked": {"type": "github", "owner": "paused", "repo": "app"}},
                }
            }
        )
    )
    paths = []

    def github(jwt, path):
        assert jwt.count(".") == 2
        paths.append(path)
        if path == "/app":
            return {"slug": "avunu-hosting", "name": "Avunu Hosting", "html_url": "https://github.com/apps/avunu-hosting"}
        if path.startswith("/app/installations"):
            return [
                {"id": 1, "account": {"login": "Acme"}, "repository_selection": "selected"},
                {"id": 2, "account": {"login": "customer"}, "repository_selection": "all"},
                {"id": 3, "account": {"login": "paused"}, "repository_selection": "all", "suspended_at": "2026-01-01T00:00:00Z"},
                {"id": 66, "account": {"login": "mallory"}, "repository_selection": "all"},
            ]
        return None if path == "/repos/acme/other/installation" else {"id": 1}

    monkeypatch.setattr(ci, "github", github)
    got = ci.coverage(ctx)
    assert got["repositories"] == [
        ("acme/cluster", "covered"),
        ("acme/other", "not selected"),
        ("acme/shop", "covered"),
        ("customer/content", "covered"),
        ("NixOS/nixpkgs", "no installation"),
        ("paused/app", "suspended"),
    ]
    assert [(i["account"], i["used"]) for i in got["installations"]] == [("Acme", True), ("customer", True), ("mallory", False), ("paused", True)]
    # One decryption, the private key; the id is public. And nothing is asked about a
    # stranger's installation, or about a repository whose owner has none.
    assert [a for a in asked if a[1] == "github-app/private-key"] == [("node1", "github-app/private-key")]
    assert not [p for p in paths if "mallory" in p or "NixOS" in p or "paused" in p]
    assert all(p.startswith(("/app", "/repos/")) for p in paths)

    paths.clear()
    ci.installations(ctx)
    out = capsys.readouterr()
    text = out.out + out.err
    assert "avunu-hosting/installations/new" in text
    assert "run `avc ci repos`" not in text
    (ctx.root / "github-repos.json").unlink()
    ci.installations(ctx)
    out = capsys.readouterr()
    assert "avc ci repos" in out.out + out.err
