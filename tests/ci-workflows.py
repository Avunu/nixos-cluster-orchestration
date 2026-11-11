"""What the merge gates rest on, read from the workflow files (tests/ci-workflows.nix).

Usage: ci-workflows.py LIBRARY_WORKFLOWS TEMPLATE_WORKFLOWS TEMPLATE_README
Each property is one function; a failed one names itself and exits 1.
"""

import pathlib
import re
import sys

import yaml

lib_dir, tpl_dir, tpl_readme = (pathlib.Path(a) for a in sys.argv[1:4])
failures = []


def load(path):
    # PyYAML reads the key `on` as True. Nothing below needs the triggers by that name.
    return yaml.safe_load(path.read_text())


def runs(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


def labels(job):
    r = job.get("runs-on", [])
    return r if isinstance(r, list) else [r]


def check(name, ok, detail=""):
    print(("ok: " if ok else "FAILED: ") + name + ("" if ok else f" ({detail})"))
    if not ok:
        failures.append(name)


def attr_step(job):
    """The step that builds the job's attribute, found by its ATTR, not by its position."""
    steps = [s for s in job.get("steps", []) if "ATTR" in (s.get("env") or {})]
    return steps[0] if len(steps) == 1 else {}


# Global options may stand between `nix` and its subcommand (`nix --option eval-cores 1
# eval ...` is how these workflows call it), so the patterns allow them.
NIX_OPTS = r"(?:\s+--?[A-Za-z][\w-]*(?:\s+(?!-)[^\s#]+)*)*"
FLAKE_CHECK = re.compile(rf"\bnix{NIX_OPTS}\s+flake\s+check\b")
NIX_BUILD = re.compile(rf"\bnix{NIX_OPTS}\s+build\b(.*)")


def flake_checks(text):
    return [line for line in text.splitlines() if FLAKE_CHECK.search(line)]


def attribute_builds(text):
    """`nix build` lines that name a flake attribute (a `#`) and not a .drv's outputs (`^*`):
    those keep the evaluator's heap for the whole build."""
    out = []
    for line in text.splitlines():
        m = NIX_BUILD.search(line)
        if m and "#" in m.group(1) and "^*" not in m.group(1):
            out.append(line)
    return out


def lost_exit_status(text):
    """A command substitution inside the line that writes $GITHUB_OUTPUT: under `bash -e`
    its failure is lost, because the line's status is echo's."""
    return [line for line in text.splitlines() if "GITHUB_OUTPUT" in line and "$(" in line]


# The patterns themselves, against the forms that got past the earlier ones.
for bad in (
    "nix flake check",
    "nix --option eval-cores 1 flake check -L",
    "nix -L flake check --no-build",
):
    check(f"the flake-check pattern catches `{bad}`", flake_checks(bad) == [bad])
for bad in (
    "nix build .#checks.x86_64-linux.a",
    "nix --option eval-cores 1 build --no-link .#checks.x86_64-linux.boot-install",
    'nix build --no-link "$flake#$attr"',
):
    check(f"the attribute-build pattern catches `{bad}`", attribute_builds(bad) == [bad])
for good in (
    "drv=$(nix --option eval-cores 1 eval --raw .#checks.x86_64-linux.boot-install.drvPath)",
    'nix build --no-link --print-build-logs --max-jobs 1 "$drv^*"',
    'drv=$(nix --option eval-cores 1 eval --raw ".#nixosConfigurations.$NODE.config.system.build.toplevel.drvPath")',
):
    check(f"the patterns pass `{good}`", flake_checks(good) == [] and attribute_builds(good) == [])
check(
    "the exit-status pattern catches a substitution inside echo",
    lost_exit_status('echo "checks=$(tools/ci/list.sh checks.x86_64-linux)" >> "$GITHUB_OUTPUT"') != []
    and lost_exit_status('echo "checks=$checks" >> "$GITHUB_OUTPUT"') == [],
)


ci = load(lib_dir / "ci.yml")
mutants = load(lib_dir / "mutants.yml")
gate = load(tpl_dir / "merge-gate.yml")
update = load(tpl_dir / "flake-update.yml")
everything = {
    "ci.yml": ci,
    "mutants.yml": mutants,
    "template merge-gate.yml": gate,
    "template flake-update.yml": update,
}

# One whole-flake evaluation is 16 to 53 GB; `nix build .#x` keeps its evaluator for the
# whole VM test. Neither belongs on an ordinary runner.
for fname, wf in everything.items():
    for jname, job in wf["jobs"].items():
        text = runs(job)
        check(f"{fname} {jname}: never `nix flake check`", not flake_checks(text), flake_checks(text))
        check(
            f"{fname} {jname}: never `nix build` of a flake attribute",
            not attribute_builds(text),
            attribute_builds(text),
        )
        check(
            f"{fname} {jname}: every output is assigned first, so a failure fails the step",
            not lost_exit_status(text),
            lost_exit_status(text),
        )
        if "self-hosted" in labels(job):
            check(f"{fname} {jname}: a self-hosted job asks for kvm", "kvm" in labels(job), labels(job))
        check(f"{fname} {jname}: has a timeout", isinstance(job.get("timeout-minutes"), int) or "ubuntu-latest" in labels(job))
    check(f"{fname}: read-only token by default", wf.get("permissions") == {"contents": "read"}, wf.get("permissions"))

# The library: every check, each its own job, through tools/ci.
jobs = ci["jobs"]
check(
    "ci.yml lists checks.x86_64-linux",
    "tools/ci/list.sh checks.x86_64-linux" in runs(jobs["list"]),
)
check(
    "ci.yml builds each listed check in its own job",
    jobs["check"]["strategy"]["matrix"]["check"] == "${{ fromJSON(needs.list.outputs.checks) }}"
    and jobs["check"]["strategy"].get("fail-fast") is False
    and 'tools/ci/build.sh "$ATTR"' in runs(jobs["check"])
    and attr_step(jobs["check"]).get("env", {}).get("ATTR") == "checks.x86_64-linux.${{ matrix.check }}",
)
# Each job may land on a different runner.
for fname, wf in (("ci.yml", ci), ("mutants.yml", mutants)):
    for jname, job in wf["jobs"].items():
        if "self-hosted" in labels(job):
            check(f"{fname} {jname}: runs the runner preflight", "tools/ci/preflight.sh" in runs(job))
others = sorted(j for j in jobs if j != "ci-gate")
check(
    "ci.yml's ci-gate needs every other job and runs whatever they did",
    sorted(jobs["ci-gate"]["needs"]) == others and jobs["ci-gate"].get("if") == "always()",
    jobs["ci-gate"].get("needs"),
)
check(
    "ci.yml's ci-gate fails on anything but success",
    'all(.[]; .result == "success")' in runs(jobs["ci-gate"]),
)
check(
    "ci.yml runs no fork's code on the runner by accident",
    "head.repo.full_name == github.repository" in jobs["list"].get("if", ""),
)
check(
    "mutants.yml builds every mutant, each in its own job, by hand only",
    "tools/ci/list.sh legacyPackages.x86_64-linux.mutants" in runs(mutants["jobs"]["list"])
    and attr_step(mutants["jobs"]["mutant"]).get("env", {}).get("ATTR")
    == "legacyPackages.x86_64-linux.mutants.${{ matrix.mutant }}"
    and list(mutants[True]) == ["workflow_dispatch"],
)

# The template: the boot tests at the site's lock, and a gate over everything.
gjobs = gate["jobs"]
for name in ("boot-install", "boot-fallback"):
    check(
        f"merge-gate.yml {name} builds the re-exported check's .drv",
        f".#checks.x86_64-linux.{name}.drvPath" in runs(gjobs[name]) and '"$drv^*"' in runs(gjobs[name]),
        runs(gjobs.get(name, {})),
    )
gothers = sorted(j for j in gjobs if j != "merge-gate")
check(
    "merge-gate.yml's merge-gate needs every other job and fails on anything but success",
    sorted(gjobs["merge-gate"]["needs"]) == gothers
    and gjobs["merge-gate"].get("if") == "always()"
    and 'all(.[]; .result == "success")' in runs(gjobs["merge-gate"]),
)
check(
    "merge-gate.yml builds every node's system",
    "nixosConfigurations.$NODE.config.system.build.toplevel.drvPath" in runs(gjobs["toplevel"]),
)
check(
    "merge-gate.yml runs on pull requests, pushes and the merge queue",
    {"pull_request", "push", "merge_group"} <= set(gate[True]),
)
utext = runs(update["jobs"]["update"])
check(
    "flake-update.yml never pushes to main, and merges only by auto-merge",
    "git push --force origin flake-auto-update" in utext
    and not re.search(r"push[^\n]*\bmain\b", utext)
    and "gh pr merge flake-auto-update --auto" in utext,
    utext,
)

readme = tpl_readme.read_text()
for name in ("merge-gate", "boot-install", "boot-fallback"):
    check(f"the template README names `{name}` as a required status check", f"`{name}`" in readme)
# The protection model: nobody bypasses the gate, the flake-update token least of all,
# and avc does not need to, because it opens a pull request for every change and has no
# push to the deploy branch. tools/avc/tests/test_ship.py proves that part, against a
# remote that refuses such a push.
check(
    "the template README leaves the bypass list empty and says how avc lives with that",
    "Bypass list: empty" in readme
    and "not the account behind `FLAKE_UPDATE_TOKEN`" in readme
    and "`avc` has no push to `main`" in readme
    and "What that costs" in readme
    and '"Allow auto-merge"' in readme
    and "bypass list: the operators" not in readme.lower(),
)

if failures:
    sys.exit(1)
