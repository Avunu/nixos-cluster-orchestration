"""The ordering the ship pipeline guarantees: post-actions (restarts, revoking
an old credential) never run before the deploy they depend on is confirmed."""

from __future__ import annotations

import pytest

from avc import ui
from avc.core import repo, ship


@pytest.fixture
def git(monkeypatch):
    state = {"ahead": 1, "pushed": False, "outgoing": ["vars/per-machine/node1/x/value"]}
    monkeypatch.setattr(repo, "changes", lambda root: [])
    monkeypatch.setattr(repo, "outgoing_paths", lambda root: state["outgoing"])
    monkeypatch.setattr(repo, "branch", lambda root: "main")
    monkeypatch.setattr(repo, "fetch", lambda root: True)
    monkeypatch.setattr(repo, "ahead_behind", lambda root: (state["ahead"], 0))
    monkeypatch.setattr(repo, "push", lambda root: state.update(pushed=True))
    monkeypatch.setattr(repo, "remote", lambda root: "origin")
    return state


@pytest.fixture
def ran(monkeypatch):
    log: list[str] = []
    monkeypatch.setattr(ship.PostAction, "run", lambda self, ctx: log.append(self.label) or True)
    return log


POST = [ship.restart("app-blog", "node1")]


def test_post_actions_run_after_a_confirmed_deploy(ctx, git, ran, monkeypatch):
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: True)
    with ui.scripted([True, True]):  # push? deploy now?
        assert ship.ship(ctx, "msg", post=POST)
    assert git["pushed"]
    assert ran == ["restart app-blog on node1"]
    assert ship.pending(ctx) == []


def test_a_failed_deploy_defers_post_actions(ctx, git, ran, monkeypatch):
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: False)
    with ui.scripted([True, True]):
        assert not ship.ship(ctx, "msg", post=POST)
    assert ran == []
    assert ship.pending(ctx) == POST


def test_deploying_later_defers_post_actions(ctx, git, ran):
    with ui.scripted([True, False]):  # push, then "later"
        assert not ship.ship(ctx, "msg", post=POST)
    assert ran == []
    assert ship.pending(ctx) == POST


def test_not_pushing_defers_and_never_deploys(ctx, git, ran, monkeypatch):
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: pytest.fail("deployed without a push"))
    with ui.scripted([False]):
        assert not ship.ship(ctx, "msg", post=POST)
    assert not git["pushed"]
    assert ship.pending(ctx) == POST


def test_off_the_deploy_branch_nothing_is_pushed(ctx, git, ran, monkeypatch):
    monkeypatch.setattr(repo, "branch", lambda root: "feature")
    with ui.scripted([]):
        assert not ship.ship(ctx, "msg", post=POST)
    assert not git["pushed"]
    assert ship.pending(ctx) == POST


@pytest.mark.parametrize("gated", ["flake.lock", "flake.nix"])
def test_a_lock_or_input_change_is_never_pushed_to_main(ctx, git, ran, monkeypatch, gated):
    # The merge gate covers these, and a direct push would skip it: they go by pull request.
    git["outgoing"] = ["vars/per-machine/node1/x/value", gated]
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: pytest.fail("deployed a lock change"))
    with ui.scripted([]), pytest.raises(ui.AvcError, match="pull request"):
        ship.ship(ctx, "msg", post=POST)
    assert not git["pushed"]
    assert ran == []
    assert ship.pending(ctx) == POST


def test_operational_changes_are_pushed_directly(ctx, git, ran, monkeypatch):
    git["outgoing"] = ["vars/per-machine/node1/x/value", "secrets/shared/y/secret", "topology.nix", "apps/blog.nix"]
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: True)
    with ui.scripted([True, True]):
        assert ship.ship(ctx, "msg", post=POST)
    assert git["pushed"]


def test_behind_origin_is_refused(ctx, git, monkeypatch):
    monkeypatch.setattr(repo, "ahead_behind", lambda root: (1, 2))
    with ui.scripted([]), pytest.raises(ui.AvcError, match="behind"):
        ship.ship(ctx, "msg")


def test_pending_runs_and_keeps_failures(ctx, monkeypatch):
    ok, bad = ship.restart("app-a", "node1"), ship.restart("app-b", "node1")
    ship.defer(ctx, [ok, bad])
    monkeypatch.setattr(ship.PostAction, "run", lambda self, ctx: self is ok or self == ok)
    ship.run_pending(ctx)
    assert ship.pending(ctx) == [bad]


def test_defer_does_not_duplicate(ctx):
    ship.defer(ctx, POST)
    ship.defer(ctx, POST)
    assert ship.pending(ctx) == POST


def test_repo_slug_of_a_flake_url():
    assert repo.repo_slug("github:Owner/Repo") == "Owner/Repo"
    assert repo.repo_slug("github:Owner/Repo/some-ref") == "Owner/Repo"
    assert repo.repo_slug("git+https://example.com/Owner/Repo.git?ref=main") == "Owner/Repo"
    assert repo.repo_slug("git+ssh://git@example.com/Owner/Repo") == "Owner/Repo"
    assert repo.repo_slug("path:/srv/cluster") is None
