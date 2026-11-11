"""What the ship pipeline guarantees.

A change reaches the deploy branch by pull request and in no other way, and
post-actions (restarts, revoking an old credential) never run before the deploy
they depend on is confirmed.

The repository is a real one: a clone, and a bare remote whose `main` refuses
every push but the forge's own merge, as a protected branch does. The forge is
a stand-in for GitHub that keeps pull requests in memory and merges them the
way the site's settings do (a squash).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from avc import ui
from avc.context import Ctx
from avc.core import pr, proc, repo, ship

PROTECT_MAIN = """#!/bin/sh
while read -r old new ref; do
  if [ "$ref" = refs/heads/main ] && [ -z "$FORGE_MERGE" ]; then
    echo "protected branch: main takes pull requests only" >&2
    exit 1
  fi
done
"""


def git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    p = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, env={**os.environ, **(env or {})})
    assert p.returncode == 0, f"git {' '.join(args)}: {p.stderr}"
    return p.stdout.strip()


class Forge:
    """GitHub, as far as avc.core.pr talks to it."""

    def __init__(self, bare: Path, work: Path) -> None:
        self.bare, self.work = bare, work
        self.prs: dict[str, dict] = {}
        self.gate = "green"  # green: merges when asked to | pending | red
        self.allow_auto = True
        self.unavailable = False
        self.updated: list[int] = []
        self.finds = 0
        self.pull_refs = True  # GitHub's refs/pull/N/head
        self.before_find = lambda: None

    def main(self) -> str:
        return git(self.bare, "rev-parse", "refs/heads/main")

    def branches(self) -> list[str]:
        return git(self.bare, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()

    def _sync(self, d: dict) -> None:
        """An open pull request follows its branch, and so does refs/pull/N/head."""
        if d["state"] == "OPEN" and d["branch"] in self.branches():
            d["head"] = git(self.bare, "rev-parse", f"refs/heads/{d['branch']}")
            if self.pull_refs:
                git(self.bare, "update-ref", f"refs/pull/{d['number']}/head", d["head"])

    def merge(self, branch: str) -> None:
        """What the forge does once the gate is green: a squash onto main."""
        if branch in self.prs:
            self._sync(self.prs[branch])
        git(self.work, "fetch", "--quiet", "origin")
        git(self.work, "checkout", "--quiet", "-B", "main", "origin/main")
        git(self.work, "merge", "--quiet", "--squash", f"origin/{branch}")
        git(self.work, "commit", "--quiet", "-m", f"{branch} (squashed)")
        git(self.work, "push", "--quiet", "origin", "main", env={"FORGE_MERGE": "1"})
        if branch in self.prs:
            self.prs[branch]["state"] = "MERGED"

    def commit_on_main(self, path: str, content: str) -> None:
        """Someone else's pull request merging."""
        git(self.work, "fetch", "--quiet", "origin")
        git(self.work, "checkout", "--quiet", "-B", "main", "origin/main")
        (self.work / path).parent.mkdir(parents=True, exist_ok=True)
        (self.work / path).write_text(content)
        git(self.work, "add", "-A")
        git(self.work, "commit", "--quiet", "-m", f"other: {path}")
        git(self.work, "push", "--quiet", "origin", "main", env={"FORGE_MERGE": "1"})

    # ── avc.core.pr ──

    def find(self, root: Path, branch: str) -> pr.PullRequest | None:
        if self.unavailable:
            raise pr.Unavailable("gh: not found on PATH")
        self.finds += 1
        assert self.finds < 200, "still waiting for a merge that is not coming"
        self.before_find()
        d = self.prs.get(branch)
        if d is None:
            return None
        self._sync(d)
        if d["state"] == "OPEN" and branch in self.branches() and d["auto"] and self.gate == "green":
            self.merge(branch)  # auto-merge, once the checks have turned green
        d["failed"] = ("merge-gate",) if self.gate == "red" and d["state"] == "OPEN" else ()
        return pr.PullRequest(**{k: v for k, v in d.items() if k not in ("branch", "title")})

    def open_(self, root: Path, branch: str, title: str) -> pr.PullRequest:
        if self.unavailable:
            raise pr.Unavailable("gh: not found on PATH")
        assert branch in self.branches(), "a pull request needs its branch on the remote"
        n = len(self.prs) + 1
        self.prs[branch] = {
            "number": n,
            "state": "OPEN",
            "url": f"https://forge.example/pull/{n}",
            "head": "",
            "merge_state": "BLOCKED",
            "failed": (),
            "auto": False,
            "branch": branch,
            "title": title,
        }
        found = self.find(root, branch)
        assert found is not None
        return found

    def request_merge(self, root: Path, number: int) -> bool:
        if not self.allow_auto:
            return False
        d = next(d for d in self.prs.values() if d["number"] == number)
        d["auto"] = True
        if self.gate == "green":
            self.merge(d["branch"])
        return True

    def update_branch(self, root: Path, number: int) -> None:
        """"Update branch": main merged into the pull request's branch, on the forge."""
        self.updated.append(number)
        d = next(d for d in self.prs.values() if d["number"] == number)
        git(self.work, "fetch", "--quiet", "origin")
        git(self.work, "checkout", "--quiet", "-B", "update", f"origin/{d['branch']}")
        git(self.work, "merge", "--quiet", "--no-edit", "origin/main")
        git(self.work, "push", "--quiet", "origin", f"update:{d['branch']}")
        d["merge_state"] = "BLOCKED"
        self._sync(d)


@pytest.fixture
def site(tmp_path: Path, tmp_path_factory, index, monkeypatch):
    """(ctx, forge): a clone on `main`, level with a protected remote."""
    for k, v in {
        "HOME": str(tmp_path_factory.mktemp("home")),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Operator",
        "GIT_AUTHOR_EMAIL": "operator@example.com",
        "GIT_COMMITTER_NAME": "Operator",
        "GIT_COMMITTER_EMAIL": "operator@example.com",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("FORGE_MERGE", raising=False)

    forge_dir = tmp_path_factory.mktemp("forge")
    bare, work = forge_dir / "origin.git", forge_dir / "work"
    git(forge_dir, "init", "--quiet", "--bare", "-b", "main", str(bare))
    hook = bare / "hooks" / "pre-receive"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(PROTECT_MAIN)
    hook.chmod(0o755)

    git(forge_dir, "init", "--quiet", "-b", "main", str(work))
    git(work, "remote", "add", "origin", str(bare))
    for path, content in {"flake.lock": "{}\n", "vars/a": "1\n", "apps/blog.nix": "{ }\n"}.items():
        (work / path).parent.mkdir(parents=True, exist_ok=True)
        (work / path).write_text(content)
    git(work, "add", "-A")
    git(work, "commit", "--quiet", "-m", "initial")
    git(work, "push", "--quiet", "origin", "main", env={"FORGE_MERGE": "1"})

    root = tmp_path / "site"
    git(tmp_path, "clone", "--quiet", str(bare), str(root))
    ctx = Ctx(root)
    ctx.__dict__["index"] = index
    ctx.__dict__["installed"] = ["node1"]

    forge = Forge(bare, work)
    monkeypatch.setattr(repo, "deploy_repo", lambda root: None)  # no `nix eval` here
    for name in ("find", "open_", "request_merge", "update_branch"):
        monkeypatch.setattr(pr, name, getattr(forge, name))
    # Not time.sleep: subprocess's own timeout handling sleeps too.
    monkeypatch.setattr(ship, "MERGE_POLL", 0)
    return ctx, forge


@pytest.fixture
def ran(monkeypatch):
    log: list[str] = []
    monkeypatch.setattr(ship.PostAction, "run", lambda self, ctx: log.append(self.label) or True)
    return log


@pytest.fixture
def deployed(monkeypatch):
    """`ship.deploy` succeeding; the list holds the commit each call saw on the remote's main."""
    seen: list[str] = []

    def deploy(ctx, nodes=None):
        seen.append(git(ctx.root, "rev-parse", "origin/main"))
        return True

    monkeypatch.setattr(ship, "deploy", deploy)
    return seen


POST = [ship.restart("app-blog", "node1")]


def edit(ctx: Ctx, path: str = "vars/a", content: str = "2\n") -> None:
    (ctx.root / path).parent.mkdir(parents=True, exist_ok=True)
    (ctx.root / path).write_text(content)


def answers(path: str = "vars/a", *, open_pr: bool = True, deploy: bool | None = True) -> list:
    """Include in the commit, commit message, open the pull request?, deploy now?"""
    script: list = [[path], "msg", open_pr]
    return script if deploy is None or not open_pr else [*script, deploy]


def on_main_at_the_remote(ctx: Ctx, forge: Forge) -> bool:
    return repo.branch(ctx.root) == "main" and repo.head(ctx.root) == forge.main()


# ── the fixture itself ───────────────────────────────────────────────────────


def test_the_remote_refuses_a_push_to_main(site):
    # Without this the tests below could not tell a pull request from a push.
    ctx, forge = site
    edit(ctx)
    git(ctx.root, "commit", "--quiet", "-am", "direct")
    p = subprocess.run(["git", "push", "origin", "HEAD:main"], cwd=ctx.root, capture_output=True, text=True)
    assert p.returncode != 0 and "pull requests only" in p.stderr


# ── a change goes by pull request ────────────────────────────────────────────


@pytest.mark.parametrize("path", ["vars/a", "apps/blog.nix", "flake.lock"])
def test_a_change_merges_by_pull_request_then_deploys_then_runs_post_actions(site, ran, deployed, path):
    ctx, forge = site
    before = forge.main()
    edit(ctx, path)
    with ui.scripted(answers(path)):
        assert ship.ship(ctx, "msg", post=POST)

    (opened,) = forge.prs.values()
    assert opened["branch"].startswith("avc/") and opened["title"] == "msg" and opened["state"] == "MERGED"
    assert forge.main() != before
    assert git(forge.bare, "show", f"main:{path}") == "2"
    assert deployed == [forge.main()], "deployed the merged commit, and only after the merge"
    assert ran == ["restart app-blog on node1"]
    assert ship.pending(ctx) == []
    # Tidy: back on main at the merged commit, and the branch gone on both sides.
    assert on_main_at_the_remote(ctx, forge)
    assert forge.branches() == ["main"]
    assert git(ctx.root, "branch", "--format=%(refname:short)") == "main"
    assert repo.changes(ctx.root) == []


def test_push_branch_refuses_the_deploy_branch(site):
    ctx, forge = site
    before = forge.main()
    edit(ctx)
    git(ctx.root, "commit", "--quiet", "-am", "direct")
    for name in ("main", "feature", "refs/heads/main"):
        with pytest.raises(ui.AvcError, match="refusing to push"):
            repo.push_branch(ctx.root, name)
    assert forge.main() == before and forge.branches() == ["main"]


def test_commits_made_on_main_by_hand_go_by_pull_request_too(site, ran, deployed):
    # `clan vars` commits what it writes, on whatever branch is checked out.
    ctx, forge = site
    edit(ctx)
    git(ctx.root, "commit", "--quiet", "-am", "chore(vars): by clan")
    with ui.scripted([True, True]):  # open the pull request? deploy now?
        assert ship.ship(ctx, "msg", post=POST)
    (opened,) = forge.prs.values()
    assert opened["title"] == "chore(vars): by clan" and opened["state"] == "MERGED"
    assert git(forge.bare, "show", "main:vars/a") == "2"
    assert on_main_at_the_remote(ctx, forge)
    assert ran == ["restart app-blog on node1"]


def test_work_left_out_of_the_commit_survives_the_round_trip(site, deployed):
    ctx, forge = site
    edit(ctx, "vars/a")
    edit(ctx, "apps/blog.nix", "{ draft = true; }\n")
    edit(ctx, "notes.txt", "scratch\n")
    with ui.scripted(answers("vars/a")):
        assert ship.ship(ctx, "msg")
    assert on_main_at_the_remote(ctx, forge)
    assert (ctx.root / "apps/blog.nix").read_text() == "{ draft = true; }\n"
    assert (ctx.root / "notes.txt").read_text() == "scratch\n"
    assert git(forge.bare, "show", "main:apps/blog.nix") == "{ }"
    assert sorted(c.path for c in repo.changes(ctx.root)) == ["apps/blog.nix", "notes.txt"]


def test_state_kept_for_resuming_is_never_offered_for_the_commit(site):
    ctx, forge = site
    ship.defer(ctx, POST)
    assert repo.changes(ctx.root) == []


# ── nothing reaches main, or runs, before the merge ──────────────────────────


def test_declining_the_pull_request_pushes_nothing_and_defers(site, ran, monkeypatch):
    ctx, forge = site
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: pytest.fail("deployed without a merge"))
    before = forge.main()
    edit(ctx)
    with ui.scripted(answers(open_pr=False)):
        assert not ship.ship(ctx, "msg", post=POST)
    assert forge.main() == before and forge.branches() == ["main"] and not forge.prs
    assert ran == [] and ship.pending(ctx) == POST
    assert repo.is_pr_branch(repo.branch(ctx.root))


def test_a_red_gate_merges_nothing_and_a_later_run_picks_it_up(site, ran, deployed):
    ctx, forge = site
    forge.gate = "red"
    before = forge.main()
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg", post=POST)
    assert forge.main() == before, "a red check must leave main alone"
    assert deployed == [] and ran == [] and ship.pending(ctx) == POST
    branch = repo.branch(ctx.root)
    assert repo.is_pr_branch(branch) and forge.prs[branch]["state"] == "OPEN"

    # The check is rerun and passes; GitHub's auto-merge does the rest. `avc deploy ship`:
    forge.merge(branch)
    with ui.scripted([True]):  # deploy now?
        assert ship.ship(ctx, "chore: update cluster configuration", post=ship.pending(ctx))
    assert on_main_at_the_remote(ctx, forge)
    assert deployed == [forge.main()]
    assert ran == ["restart app-blog on node1"]
    assert ship.pending(ctx) == [], "a post-action that ran is not left to run again"
    assert forge.branches() == ["main"]


def test_a_fix_on_the_open_pull_request_branch_updates_the_same_pull_request(site, deployed):
    ctx, forge = site
    forge.gate = "red"
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg")
    branch = repo.branch(ctx.root)
    red = forge.prs[branch]["head"]

    def checks_rerun_on_the_new_commit() -> None:
        if git(forge.bare, "rev-parse", f"refs/heads/{branch}") != red:
            forge.gate = "green"

    forge.before_find = checks_rerun_on_the_new_commit
    edit(ctx, "vars/a", "3\n")
    with ui.scripted([["vars/a"], "fix", True, True]):
        assert ship.ship(ctx, "fix")
    assert len(forge.prs) == 1
    assert git(forge.bare, "show", "main:vars/a") == "3"
    assert on_main_at_the_remote(ctx, forge)


def test_a_pull_request_that_merged_a_moment_ago_is_seen_and_new_work_gets_its_own(site, deployed):
    ctx, forge = site
    forge.gate = "red"
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg")
    # The rerun check passes and auto-merge fires only as this run asks about the pull
    # request, i.e. after its own fetch. Meanwhile there is new work in the same file.
    forge.gate = "green"
    edit(ctx, "vars/a", "3\n")
    with ui.scripted([["vars/a"], "more", True, True]):
        assert ship.ship(ctx, "more")
    assert [d["state"] for d in forge.prs.values()] == ["MERGED", "MERGED"]
    assert git(forge.bare, "show", "main:vars/a") == "3"
    assert on_main_at_the_remote(ctx, forge) and forge.branches() == ["main"]


def test_it_waits_for_the_gate_and_brings_a_stale_branch_up_to_date(site, ran, deployed):
    ctx, forge = site
    forge.gate = "pending"
    polls = []

    def gate_runs() -> None:
        polls.append(1)
        (opened,) = forge.prs.values() or [None]
        if opened is None or opened["state"] != "OPEN":
            return
        if len(polls) == 3:
            opened["merge_state"] = "BEHIND"
        if len(polls) == 6:
            forge.merge(opened["branch"])

    edit(ctx)
    forge.before_find = gate_runs
    with ui.scripted(answers()):
        assert ship.ship(ctx, "msg", post=POST)
    assert forge.updated == [1], "asked once for the branch to be updated, not on every poll"
    assert deployed == [forge.main()] and ran == ["restart app-blog on node1"]


def test_stopping_the_wait_defers_and_leaves_the_pull_request_open(site, ran, deployed):
    ctx, forge = site
    forge.gate = "pending"
    edit(ctx)

    def interrupt() -> None:
        if forge.prs and next(iter(forge.prs.values()))["auto"]:
            raise KeyboardInterrupt

    forge.before_find = interrupt
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg", post=POST)
    (opened,) = forge.prs.values()
    assert opened["state"] == "OPEN" and opened["auto"]
    assert deployed == [] and ran == [] and ship.pending(ctx) == POST


def test_the_wait_ends(site, ran, deployed, monkeypatch):
    ctx, forge = site
    forge.gate = "pending"
    monkeypatch.setattr(ship, "MERGE_TIMEOUT", 0)
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg", post=POST)
    assert deployed == [] and ship.pending(ctx) == POST


def test_a_pull_request_closed_without_merging_is_an_error_and_keeps_the_post_actions(site, ran, deployed):
    ctx, forge = site
    forge.gate = "pending"

    def close() -> None:
        for d in forge.prs.values():
            d["state"] = "CLOSED"

    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        forge.before_find = lambda: close() if forge.prs and next(iter(forge.prs.values()))["auto"] else None
        with pytest.raises(ui.AvcError, match="closed without merging"):
            ship.ship(ctx, "msg", post=POST)
    assert deployed == [] and ran == [] and ship.pending(ctx) == POST


def test_where_auto_merge_is_refused_it_says_so_and_still_waits_for_the_merge(site, deployed, capsys):
    ctx, forge = site
    forge.allow_auto = False
    polls = []

    def someone_merges() -> None:
        polls.append(1)
        if len(polls) == 4:
            forge.merge(next(iter(forge.prs)))

    edit(ctx)
    forge.before_find = someone_merges
    with ui.scripted(answers()):
        assert ship.ship(ctx, "msg")
    assert "merge https://forge.example/pull/1 yourself" in " ".join(capsys.readouterr().err.split())
    assert on_main_at_the_remote(ctx, forge)


def test_without_the_forge_cli_the_branch_is_pushed_and_a_later_run_sees_the_merge(site, ran, deployed):
    ctx, forge = site
    forge.unavailable = True
    before = forge.main()
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg", post=POST)
    branch = repo.branch(ctx.root)
    assert forge.main() == before and forge.branches() == [branch, "main"]
    assert ship.pending(ctx) == POST

    # Not merged yet: running it again changes nothing.
    with ui.scripted([]):
        assert not ship.ship(ctx, "x", post=ship.pending(ctx))
    assert deployed == [] and repo.branch(ctx.root) == branch

    # The operator opens the pull request by hand and it merges (a squash: the
    # branch's commit is not an ancestor of main, its content is there).
    forge.merge(branch)
    with ui.scripted([True]):
        assert ship.ship(ctx, "x", post=ship.pending(ctx))
    assert on_main_at_the_remote(ctx, forge)
    assert deployed == [forge.main()] and ran == ["restart app-blog on node1"] and ship.pending(ctx) == []


@pytest.mark.parametrize("pull_refs", [True, False])
def test_a_merged_pull_request_does_not_hide_a_commit_added_after_it(site, deployed, pull_refs):
    ctx, forge = site
    forge.gate, forge.pull_refs = "red", pull_refs
    edit(ctx)
    with ui.scripted(answers(deploy=None)):
        assert not ship.ship(ctx, "msg")
    branch = repo.branch(ctx.root)
    forge.merge(branch)
    edit(ctx, "vars/a", "3\n")
    git(ctx.root, "commit", "--quiet", "-am", "after the merge")
    with ui.scripted([]), pytest.raises(ui.AvcError, match="has merged, but"):
        ship.ship(ctx, "x")
    assert repo.branch(ctx.root) == branch, "the unmerged commit is still checked out"
    assert git(ctx.root, "log", "-1", "--format=%s") == "after the merge"
    assert deployed == []


def test_a_branch_the_forge_brought_up_to_date_still_counts_as_merged(site, ran, deployed):
    # Someone else's pull request changes the same file first. "Update branch" merges
    # that in on the forge, so the pull request's head is a commit this clone never had
    # and main's copy of the file is not this clone's either. Nothing was left behind.
    ctx, forge = site
    forge.commit_on_main("apps/blog.nix", "".join(f"line {n}\n" for n in range(1, 21)))
    git(ctx.root, "pull", "--quiet", "--ff-only")
    forge.gate = "pending"
    lines = (ctx.root / "apps/blog.nix").read_text().splitlines(keepends=True)
    edit(ctx, "apps/blog.nix", "".join([*lines[:-1], "line 20, ours\n"]))

    def interrupt() -> None:
        if forge.prs and next(iter(forge.prs.values()))["auto"]:
            raise KeyboardInterrupt

    forge.before_find = interrupt
    with ui.scripted(answers("apps/blog.nix", deploy=None)):
        assert not ship.ship(ctx, "msg", post=POST)
    forge.before_find = lambda: None
    branch = repo.branch(ctx.root)

    forge.commit_on_main("apps/blog.nix", "".join(["line 1, theirs\n", *lines[1:]]))
    forge.update_branch(ctx.root, 1)
    forge.merge(branch)
    assert forge.prs[branch]["head"] != repo.head(ctx.root)

    with ui.scripted([True]):
        assert ship.ship(ctx, "x", post=ship.pending(ctx))
    assert on_main_at_the_remote(ctx, forge)
    merged = (ctx.root / "apps/blog.nix").read_text()
    assert "line 1, theirs\n" in merged and "line 20, ours\n" in merged
    assert ran == ["restart app-blog on node1"]


# ── the other ways it stops ──────────────────────────────────────────────────


def test_a_failed_deploy_defers_post_actions(site, ran, monkeypatch):
    ctx, forge = site
    monkeypatch.setattr(ship, "deploy", lambda ctx, nodes=None: False)
    edit(ctx)
    with ui.scripted(answers()):
        assert not ship.ship(ctx, "msg", post=POST)
    assert ran == [] and ship.pending(ctx) == POST
    assert on_main_at_the_remote(ctx, forge), "the change itself did merge"


def test_deploying_later_defers_post_actions(site, ran):
    ctx, forge = site
    edit(ctx)
    with ui.scripted(answers(deploy=False)):
        assert not ship.ship(ctx, "msg", post=POST)
    assert ran == [] and ship.pending(ctx) == POST


def test_on_another_branch_nothing_is_pushed(site, ran):
    ctx, forge = site
    git(ctx.root, "switch", "--quiet", "-c", "feature")
    edit(ctx)
    with ui.scripted([["vars/a"], "msg"]):
        assert not ship.ship(ctx, "msg", post=POST)
    assert forge.branches() == ["main"] and not forge.prs
    assert repo.branch(ctx.root) == "feature"
    assert ship.pending(ctx) == POST


def test_behind_the_remote_is_refused_and_keeps_the_post_actions(site, ran):
    ctx, forge = site
    forge.commit_on_main("vars/b", "other\n")
    edit(ctx)
    with ui.scripted([]), pytest.raises(ui.AvcError, match="behind"):
        ship.ship(ctx, "msg", post=POST)
    assert not forge.prs and ship.pending(ctx) == POST


def test_nothing_to_ship(site, deployed):
    ctx, forge = site
    with ui.scripted([]):
        assert ship.ship(ctx, "msg")
    assert deployed == [] and not forge.prs


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


# ── git and gh, underneath ───────────────────────────────────────────────────


def test_landed_tells_a_squash_merge_from_an_unmerged_or_overwritten_change(site):
    ctx, forge = site
    root = ctx.root
    repo.start_pr_branch(root, "avc/x")
    edit(ctx)
    git(root, "commit", "--quiet", "-am", "change")
    assert not repo.landed(root)

    repo.push_branch(root, "avc/x")
    forge.commit_on_main("vars/b", "other\n")  # someone else's merge does not count for or against
    repo.fetch(root)
    assert not repo.landed(root)

    forge.merge("avc/x")
    repo.fetch(root)
    assert repo.landed(root)
    squashed = subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"], cwd=root)
    assert squashed.returncode == 1, "the branch's commit is not in main's history, only its content is"

    forge.commit_on_main("vars/a", "9\n")  # the same file changed again since
    repo.fetch(root)
    assert not repo.landed(root)


def test_returning_to_main_does_not_move_a_main_that_has_its_own_commits(site):
    ctx, forge = site
    root = ctx.root
    edit(ctx)
    git(root, "commit", "--quiet", "-am", "kept on main by hand")
    kept = repo.head(root)
    git(root, "switch", "--quiet", "-c", "avc/x")
    with pytest.raises(ui.AvcError, match="is not moved"):
        repo.return_to_deploy_branch(root, "avc/x")
    assert git(root, "rev-parse", "main") == kept


def test_pr_branch_names():
    name = repo.pr_branch_name("chore(secrets): rotate Demo ERP / admin password, and then some more words")
    assert repo.is_pr_branch(name) and not repo.is_pr_branch("main")
    assert git(Path.cwd(), "check-ref-format", "--branch", name) == name
    assert len(name) < 70
    assert repo.is_pr_branch(repo.pr_branch_name("???"))


def test_repo_slug_of_a_flake_url():
    assert repo.repo_slug("github:Owner/Repo") == "Owner/Repo"
    assert repo.repo_slug("github:Owner/Repo/some-ref") == "Owner/Repo"
    assert repo.repo_slug("git+https://example.com/Owner/Repo.git?ref=main") == "Owner/Repo"
    assert repo.repo_slug("git+ssh://git@example.com/Owner/Repo") == "Owner/Repo"
    assert repo.repo_slug("path:/srv/cluster") is None


GH_LIST = """[{"number": 7, "state": "OPEN", "url": "https://github.com/example/cluster/pull/7", "headRefOid": "abc",
  "mergeStateStatus": "BLOCKED", "autoMergeRequest": {"mergeMethod": "SQUASH"},
  "statusCheckRollup": [
    {"__typename": "CheckRun", "name": "merge-gate", "status": "COMPLETED", "conclusion": "FAILURE"},
    {"__typename": "CheckRun", "name": "lint", "status": "COMPLETED", "conclusion": "SUCCESS"},
    {"__typename": "CheckRun", "name": "slow", "status": "IN_PROGRESS", "conclusion": ""},
    {"__typename": "StatusContext", "context": "legacy/status", "state": "ERROR"}]}]"""


@pytest.fixture
def gh(ctx, monkeypatch):
    """Record what is run as `gh`, answering from `replies` (argv prefix → (rc, stdout))."""
    calls: list[list[str]] = []
    replies: dict[tuple[str, ...], tuple[int, str]] = {}
    monkeypatch.setattr(repo, "deploy_repo", lambda root: "example/cluster")

    def run(cmd, cwd=None, check=True, capture=True, input=None, timeout=None):
        assert cmd[0] == "gh", cmd
        calls.append(list(cmd))
        rc, out = next((v for k, v in replies.items() if tuple(cmd[1 : 1 + len(k)]) == k), (0, ""))
        return subprocess.CompletedProcess(cmd, rc, out, "refused" if rc else "")

    monkeypatch.setattr(proc, "run", run)
    return calls, replies


def test_gh_reads_a_pull_request_and_its_red_checks(ctx, gh):
    calls, replies = gh
    replies[("pr", "list")] = (0, GH_LIST)
    found = pr.find(ctx.root, "avc/x")
    assert found == pr.PullRequest(7, "OPEN", "https://github.com/example/cluster/pull/7", "abc", "BLOCKED", ("merge-gate", "legacy/status"), True)
    assert not found.merged
    assert calls[0][-2:] == ["--repo", "example/cluster"], "the repository the nodes pull, whatever the clone's default is"
    assert calls[0][calls[0].index("--head") + 1] == "avc/x"

    replies[("pr", "list")] = (0, "[]")
    assert pr.find(ctx.root, "avc/x") is None


def test_gh_asks_for_auto_merge_and_never_for_a_bypass(ctx, gh):
    calls, replies = gh
    assert pr.request_merge(ctx.root, 7)
    assert calls[-1][:6] == ["gh", "pr", "merge", "7", "--auto", "--squash"]
    replies[("pr", "merge")] = (1, "")
    assert not pr.request_merge(ctx.root, 7)

    replies[("pr", "list")] = (0, GH_LIST)
    pr.open_(ctx.root, "avc/x", "title")
    pr.update_branch(ctx.root, 7)
    create = next(c for c in calls if c[1:3] == ["pr", "create"])
    assert create[create.index("--base") + 1] == "main" and create[create.index("--head") + 1] == "avc/x"
    assert not any("--admin" in c for c in calls), "avc never asks to merge past the gate"


def test_gh_missing_or_refusing_is_unavailable_not_a_crash(ctx, gh, monkeypatch):
    calls, replies = gh
    replies[("pr", "list")] = (4, "")
    with pytest.raises(pr.Unavailable, match="refused"):
        pr.find(ctx.root, "avc/x")

    def missing(cmd, **kw):
        raise ui.AvcError("gh: not found on PATH")

    monkeypatch.setattr(proc, "run", missing)
    with pytest.raises(pr.Unavailable, match="not found"):
        pr.find(ctx.root, "avc/x")
