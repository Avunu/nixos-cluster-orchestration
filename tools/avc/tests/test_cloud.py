"""`avc cloud`: what a plan is allowed to do, and where what the providers issue goes."""

from __future__ import annotations

import json

import pytest

from avc.core import proc
from avc.core import vars as clanvars
from avc.errors import AvcError
from avc.flows import cloud

PLAN = {
    "resource_changes": [
        {"address": "ovh_cloud_project_storage.juicefs", "change": {"actions": ["no-op"]}},
        {"address": "ovh_cloud_project_storage.state_backup", "change": {"actions": ["create"]}},
        {"address": "cloudflare_dns_record.shop_example_com", "change": {"actions": ["update"]}},
        {"address": "cloudflare_zero_trust_tunnel_cloudflared.shop", "change": {"actions": ["no-op"], "importing": {"id": "a/b"}}},
        {"address": "cloudflare_dns_record.old_example_com", "change": {"actions": ["delete"]}},
        {"address": "ovh_cloud_project_user_s3_credential.juicefs", "change": {"actions": ["delete", "create"]}},
    ]
}


def test_a_plan_is_read_by_what_it_does():
    ch = cloud.changes(PLAN)
    assert ch["create"] == ["ovh_cloud_project_storage.state_backup"]
    assert ch["update"] == ["cloudflare_dns_record.shop_example_com"]
    assert ch["delete"] == ["cloudflare_dns_record.old_example_com"]
    assert ch["replace"] == ["ovh_cloud_project_user_s3_credential.juicefs"]
    assert ch["import"] == ["cloudflare_zero_trust_tunnel_cloudflared.shop"]


def test_nothing_is_destroyed_unless_named():
    ch = cloud.changes(PLAN)
    # A replacement destroys too: the key pair a node is using.
    assert cloud.refused(ch, []) == ["cloudflare_dns_record.old_example_com", "ovh_cloud_project_user_s3_credential.juicefs"]
    assert cloud.refused(ch, ["cloudflare_dns_record.old_example_com"]) == ["ovh_cloud_project_user_s3_credential.juicefs"]
    assert cloud.refused(ch, ["cloudflare_dns_record.old_example_com", "ovh_cloud_project_user_s3_credential.juicefs"]) == []


def test_the_state_is_encrypted_or_nothing_runs():
    hcl = cloud.encryption("0123456789abcdef" * 4)
    assert 'passphrase = "0123456789abcdef' in hcl
    # Both the state and a saved plan, and never in the clear.
    assert hcl.count("enforced = true") == 2
    for bad in ("short", 'has"quote-0123456789abcdef', "has\nnewline-0123456789abcdef"):
        with pytest.raises(AvcError, match="refusing"):
            cloud.encryption(bad)


def test_a_tunnels_credentials_are_what_cloudflared_reads():
    assert json.loads(cloud.credentials_file("acct", "tid", "c2VjcmV0")) == {
        "AccountTag": "acct",
        "TunnelID": "tid",
        "TunnelSecret": "c2VjcmV0",
    }


def test_a_tunnel_id_goes_into_the_apps_json_beside_what_is_there(tmp_path):
    (tmp_path / "apps").mkdir()
    (tmp_path / "apps" / "shop.json").write_text(json.dumps({"resources": {"cpu": 500}, "tunnel": {"default": "http_status:404"}}))
    cloud.set_tunnel_id(tmp_path, "shop", "tid-1")
    assert json.loads((tmp_path / "apps" / "shop.json").read_text()) == {
        "resources": {"cpu": 500},
        "tunnel": {"default": "http_status:404", "id": "tid-1"},
    }
    cloud.set_tunnel_id(tmp_path, "new", "tid-2")
    assert json.loads((tmp_path / "apps" / "new.json").read_text()) == {"tunnel": {"id": "tid-2"}}


def writeback():
    return {
        "writeback": {
            "machine": "node1",
            "unmanagedHosts": [],
            "vars": {"s3_juicefs_access_key": "ovh-s3/access-key", "s3_juicefs_secret_key": "ovh-s3/secret-key"},
            "tunnels": {
                "shop": {"output": "tunnel_shop", "known": False, "accountId": "acct", "credentials": "shop-cf/cloudflared"},
                "old": {"output": "tunnel_old", "known": True, "accountId": "acct", "credentials": "old-cf/cloudflared"},
            },
        }
    }


OUTPUTS = {
    "s3_juicefs_access_key": {"value": "AK"},
    "s3_juicefs_secret_key": {"value": "SK-new"},
    "tunnel_shop": {"value": {"id": "tid-shop", "secret": "c2hvcA=="}},
    # Not this tunnel's secret: it was made by hand, and adopted.
    "tunnel_old": {"value": {"id": "tid-old", "secret": "bm90LWl0cw=="}},
}


def test_what_the_providers_issue_goes_where_the_site_reads_it(ctx, monkeypatch):
    (ctx.root / "apps").mkdir(exist_ok=True)
    have = {"ovh-s3/access-key": "AK\n", "ovh-s3/secret-key": "SK-old\n"}
    ran, written = [], {}

    def run(cmd, cwd=None, check=True, **kw):
        ran.append(list(cmd))

        class P:
            returncode = 0
            stdout = have.get(cmd[-1], "") if cmd[:3] == ["clan", "vars", "get"] else ""

        return P()

    monkeypatch.setattr(proc, "run", run)
    monkeypatch.setattr(clanvars, "set_value", lambda root, machine, var_id, value: written.__setitem__(var_id, (machine, value)))
    done = cloud.write_back(ctx, writeback(), OUTPUTS)

    # The new tunnel: its id where the app is declared, staged so that clan's
    # evaluation sees the app's credentials generator, then the credentials.
    assert json.loads((ctx.root / "apps" / "shop.json").read_text()) == {"tunnel": {"id": "tid-shop"}}
    assert ["git", "add", "--", "apps/shop.json"] in ran
    assert json.loads(written["shop-cf/cloudflared"][1])["TunnelSecret"] == "c2hvcA=="
    # The adopted one keeps its own: nothing of it is written.
    assert "old-cf/cloudflared" not in written and not (ctx.root / "apps" / "old.json").exists()
    # A key pair is written when it differs, and left alone when it does not.
    assert written["ovh-s3/secret-key"] == ("node1", "SK-new")
    assert "ovh-s3/access-key" not in written
    assert len(done) == 2


def test_no_provider_is_said_plainly(ctx, monkeypatch):
    monkeypatch.setattr(proc, "out", lambda *a, **k: json.dumps({"enabled": False}))
    with pytest.raises(AvcError, match="topology.cloud"):
        cloud.load(ctx)
