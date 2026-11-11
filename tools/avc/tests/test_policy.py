from __future__ import annotations

import tomllib

import pytest

from avc.core import policy

POLICY = """
[defaults]
max_age_days = 90

[[rule]]
kind = "frappe"
never = ["encryption-key"]
reason = "encrypts data"

[[rule]]
kind = "freeipa"
suffix = "-authelia"
never = ["storage-key"]

[[rule]]
kind = "freeipa"
manual = true

[[rule]]
match = "wp-*-api"
via = "site r2-rotate"
"""


@pytest.fixture
def pol() -> policy.Policy:
    return policy.parse(tomllib.loads(POLICY))


def test_kind_rule_matches_the_generator_named_after_the_app(pol, index):
    v = pol.verdict("demo-erp", index)
    assert not v.allowed
    assert v.never == ("encryption-key",)
    assert v.reasons == ("encrypts data",)


def test_kind_rule_with_suffix(pol, index):
    assert pol.verdict("demo-idm-authelia", index).never == ("storage-key",)
    # The suffix-less freeipa rule is about the app's own generator only.
    assert not pol.verdict("demo-idm-authelia", index).manual
    assert pol.verdict("demo-idm", index).manual


def test_glob_redirects_to_an_action(pol, index):
    v = pol.verdict("wp-blog-api", index)
    assert not v.allowed and v.via == "site r2-rotate"


def test_unmatched_is_safe(pol, index):
    v = pol.verdict("alerting-watchdog", index)
    assert v.allowed and v.label.endswith("safe[/]")
    # A tunnel credential named like an app is not the app's generator.
    assert pol.verdict("demo-erp-cf", index).allowed


def test_defaults(pol):
    assert pol.max_age_days == 90


def test_the_repository_policy_parses_and_blocks_what_must_never_rotate(repo_root, index):
    if repo_root is None:
        pytest.skip("not running from a checkout")
    pol = policy.load(repo_root)
    assert pol.verdict("demo-erp", index).never == ("encryption-key",)
    assert pol.verdict("restic", index).never == ("password",)
    assert pol.verdict("nomad-acl", index).manual
    assert pol.verdict("wp-blog-api", index).via == "site r2-rotate"
    assert pol.verdict("github-token", index).allowed
