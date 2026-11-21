# The CI that gates merges (design WS17): what can be proven about it without GitHub.
# actionlint over every workflow, the library's and the template's, with a broken copy
# that it must reject; the properties a merge gate rests on, read from the YAML; and the
# helper scripts against a stub `nix`, for the one thing they exist for: each attribute
# evaluated by its own process, the .drv built, and every failure loud.
#
# What this cannot prove: that GitHub runs it, that a runner has KVM, or that branch
# protection is set. The README and the template say how; a real run is the proof.
{
  pkgs,
  lib,
}:
let
  python = pkgs.python3.withPackages (p: [ p.pyyaml ]);
in
pkgs.runCommand "ci-workflows-checks"
  {
    nativeBuildInputs = [
      pkgs.actionlint
      pkgs.shellcheck
      pkgs.git
      pkgs.jq
      python
    ];
    # A store path's name cannot start with a dot.
    library = builtins.path {
      path = ../.github;
      name = "library-github";
    };
    template = builtins.path {
      path = ../templates/cluster/.github;
      name = "template-github";
    };
    templateReadme = ../templates/cluster/README.md;
    scripts = ../tools/ci;
  }
  ''
    set -euo pipefail
    fail() { echo "FAILED: $*" >&2; exit 1; }
    n=0
    ok() { n=$((n + 1)); echo "ok: $*"; }

    # ── actionlint ──────────────────────────────────────────────────────────
    mkdir -p l && cp -r "$library" l/.github && chmod -R u+w l
    (cd l && actionlint -config-file .github/actionlint.yaml .github/workflows/*.yml) \
      || fail "actionlint: the library's workflows"
    ok "actionlint passes the library's workflows"
    mkdir -p t && cp -r "$template" t/.github && chmod -R u+w t
    (cd t && actionlint -config-file .github/actionlint.yaml .github/workflows/*.yml) \
      || fail "actionlint: the template's workflows"
    ok "actionlint passes the template's workflows"
    # Its positive control: a job that needs one that does not exist.
    mkdir -p b && cp -r "$library" b/.github && chmod -R u+w b
    sed -i 's/needs: \[list, check, outputs\]/needs: [list, check, outputs, no-such-job]/' b/.github/workflows/ci.yml
    grep -q no-such-job b/.github/workflows/ci.yml || fail "the broken copy was not broken"
    if (cd b && actionlint -config-file .github/actionlint.yaml .github/workflows/ci.yml) >/dev/null 2>&1; then
      fail "actionlint accepted a workflow needing a job that does not exist"
    fi
    ok "actionlint rejects a broken workflow"

    # ── what the gate rests on ──────────────────────────────────────────────
    python3 ${./ci-workflows.py} "$library/workflows" "$template/workflows" "$templateReadme"
    ok "the workflows' structure (ci-workflows.py)"

    # ── the scripts ─────────────────────────────────────────────────────────
    shellcheck "$scripts"/*.sh || fail "shellcheck tools/ci"
    ok "shellcheck passes tools/ci"
    if grep -rn 'flake check' "$scripts" | grep -v '^[^:]*:[0-9]*: *#'; then
      fail "tools/ci runs nix flake check"
    fi
    ok "tools/ci never runs nix flake check"

    # A stub nix: `eval` answers from $STUB_EVAL (a line to print, or "fail"), and every
    # call is recorded.
    mkdir -p stub
    cat >stub/nix <<'STUB'
    #!${pkgs.runtimeShell}
    echo "$*" >>"$CALLS"
    case " $* " in
      *" eval "*)
        [ "$STUB_EVAL" = fail ] && { echo "error: stub evaluation failed" >&2; exit 1; }
        printf '%s' "$STUB_EVAL"
        ;;
      *" build "*) exit 0 ;;
    esac
    STUB
    chmod +x stub/nix
    export PATH="$PWD/stub:$PATH" CALLS="$PWD/calls"
    run() { : >"$CALLS"; rc=0; bash "$scripts/$1" "''${@:2}" >out 2>err || rc=$?; }

    STUB_EVAL=fail run build.sh checks.x86_64-linux.a
    [ "$rc" != 0 ] && ! grep -q ' build ' "$CALLS" || fail "build.sh: a failed evaluation built something or passed"
    ok "build.sh: a check that does not evaluate fails, and nothing builds"

    STUB_EVAL="not a path" run build.sh checks.x86_64-linux.a
    [ "$rc" != 0 ] && ! grep -q ' build ' "$CALLS" || fail "build.sh: built what is not a .drv"
    ok "build.sh: an evaluation that prints no .drv fails"

    STUB_EVAL=/nix/store/aaaa-a.drv run build.sh checks.x86_64-linux.a checks.x86_64-linux.b
    [ "$rc" = 0 ] || fail "build.sh: rc $rc on the good path"
    [ "$(grep -c ' eval ' "$CALLS")" = 2 ] || fail "build.sh: not one evaluation per attribute: $(cat "$CALLS")"
    grep -q 'eval --raw \.#checks\.x86_64-linux\.a\.drvPath' "$CALLS" || fail "build.sh: evaluated something other than the drvPath"
    grep -q 'build --no-link .*/nix/store/aaaa-a\.drv\^\*' "$CALLS" || fail "build.sh: did not build the .drv"
    ! grep -q 'build .*\.#' "$CALLS" || fail "build.sh: built a flake attribute, which holds the evaluator"
    ok "build.sh: one evaluation per attribute, then the .drv is built"

    STUB_EVAL=/nix/store/aaaa-a.drv CI_EVAL_ONLY=1 run build.sh devShells.x86_64-linux.default
    [ "$rc" = 0 ] && ! grep -q ' build ' "$CALLS" || fail "build.sh: CI_EVAL_ONLY built"
    ok "build.sh: CI_EVAL_ONLY evaluates only"

    STUB_EVAL=/nix/store/aaaa-a.drv run build.sh ""
    [ "$rc" != 0 ] || fail "build.sh: an empty name passed"
    STUB_EVAL=/nix/store/aaaa-a.drv run build.sh
    [ "$rc" != 0 ] || fail "build.sh: no name passed"
    ok "build.sh: no name, or an empty one, fails"

    STUB_EVAL='["a","b"]' run list.sh checks.x86_64-linux
    [ "$rc" = 0 ] && [ "$(cat out)" = '["a","b"]' ] || fail "list.sh: good path rc=$rc out=$(cat out)"
    grep -q 'eval --json \.#checks\.x86_64-linux --apply builtins.attrNames' "$CALLS" || fail "list.sh: $(cat "$CALLS")"
    ok "list.sh: the names, as JSON"
    STUB_EVAL=fail run list.sh checks.x86_64-linux
    [ "$rc" != 0 ] || fail "list.sh: a failed evaluation passed"
    STUB_EVAL='[]' run list.sh checks.x86_64-linux
    [ "$rc" != 0 ] || fail "list.sh: an empty list passed, so a gate could pass with nothing built"
    ok "list.sh: a failed evaluation or an empty list fails"

    # The preflight's thresholds. The sandbox has no /dev/kvm, so it fails anyway: what
    # counts is that it names the RAM or the disk, and that an unreadable value refuses.
    printf 'MemTotal:        8000000 kB\n' >meminfo-small
    printf 'MemTotal:        130000000 kB\n' >meminfo-big
    PREFLIGHT_MEMINFO=$PWD/meminfo-small run preflight.sh
    [ "$rc" != 0 ] && grep -q 'MemTotal is 8000000 kB, under the 15625000 kB' err \
      || fail "preflight.sh: 8 GB of RAM passed: rc=$rc $(cat err)"
    PREFLIGHT_MEMINFO=$PWD/no-such-file run preflight.sh
    [ "$rc" != 0 ] && grep -q 'MemTotal is unreadable kB' err \
      || fail "preflight.sh: unreadable RAM passed: rc=$rc $(cat err)"
    PREFLIGHT_MEMINFO=$PWD/meminfo-big run preflight.sh
    ! grep -q 'MemTotal is' err || fail "preflight.sh: refused 130 GB of RAM: $(cat err)"
    PREFLIGHT_MEMINFO=$PWD/meminfo-big PREFLIGHT_MIN_FREE_GB=100000000 run preflight.sh
    [ "$rc" != 0 ] && grep -q 'free under /nix/store, under the 100000000 GB' err \
      || fail "preflight.sh: too little disk passed: rc=$rc $(cat err)"
    ok "preflight.sh: too little RAM or disk, or a value it can't read, refuses"

    # ── the template's flake-update.sh, against a local remote ──────────────
    # A stub nix whose `flake update <names>` moves exactly those inputs' revs to
    # $NEW_REV, and a stub gh that records what it is asked and has no pull request or
    # issue, unless $GH_ISSUE names an issue, $GH_OPEN_PRS the open pull requests' head
    # branches, or $GH_HOLD_OPEN an input with an open hold pull request. The lock:
    # `cluster` pinned by rev, `nixpkgs` following it, and three project inputs on
    # branches.
    fu="$template/flake-update.sh"
    shellcheck "$fu" || fail "shellcheck flake-update.sh"
    ok "shellcheck passes the template's flake-update.sh"
    cat >stub/gh <<'STUB'
    #!${pkgs.runtimeShell}
    echo "$*" >>"$GHCALLS"
    case "$1 $2" in
      "pr view")
        [ -n "''${GH_HOLD_OPEN:-}" ] && [ "$3" = "flake-update-hold/$GH_HOLD_OPEN" ] && { echo OPEN; exit 0; }
        exit 1 ;;
      "pr list") printf '%s\n' ''${GH_OPEN_PRS:-}; exit 0 ;;
      "issue list") [ -n "''${GH_ISSUE:-}" ] && echo "$GH_ISSUE"; exit 0 ;;
    esac
    exit 0
    STUB
    chmod +x stub/gh
    cat >stub/nix <<'STUB'
    #!${pkgs.runtimeShell}
    echo "$*" >>"$CALLS"
    [ "$1 $2" = "flake update" ] || exit 1
    shift 2
    for i in "$@"; do
      jq --arg i "$i" --arg r "$NEW_REV" '.nodes[$i].locked.rev = $r' flake.lock >flake.lock.new
      mv flake.lock.new flake.lock
    done
    STUB
    chmod +x stub/nix
    export GHCALLS="$PWD/ghcalls" GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
      GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid HOME=$PWD
    git config --global init.defaultBranch main
    git init -q --bare remote.git
    git clone -q remote.git work 2>/dev/null
    node() { printf '{"locked":{"rev":"0"},"original":{"ref":"main"}}'; }
    jq -n --argjson p "$(node)" '{
      root: "root", version: 7,
      nodes: {
        root: {inputs: {cluster: "cluster", nixpkgs: ["cluster", "nixpkgs"], "site-a": "site-a", "site-b": "site-b", "site-c": "site-c"}},
        cluster: {locked: {rev: "0"}, original: {rev: "0"}},
        "site-a": $p, "site-b": $p, "site-c": $p
      }}' >work/flake.lock
    mkdir -p work/.github
    printf 'site-c  # broken upstream\n' >work/.github/flake-update-hold
    (cd work && git add -A && git commit -qm init && git push -q origin main)
    rev() { git -C work show "origin/$1:flake.lock" | jq -r --arg i "$2" '.nodes[$i].locked.rev'; }
    # Each run from a fresh main, as the workflow checks it out.
    fu_run() {
      : >"$CALLS"; : >"$GHCALLS"; rc=0
      git -C work checkout -q -f -B main origin/main
      (cd work && bash "$fu" "$@") >out 2>err || rc=$?
      git -C work fetch -q origin '+refs/heads/*:refs/remotes/origin/*'
    }
    sha() { git -C work rev-parse "origin/$1"; }

    NEW_REV=1 fu_run update
    [ "$rc" = 0 ] || fail "flake-update.sh update: rc $rc: $(cat err)"
    grep -qx 'flake update site-a site-b' "$CALLS" || fail "update: not every non-held branch input, or more: $(cat "$CALLS")"
    [ "$(rev flake-auto-update site-a)$(rev flake-auto-update site-b)$(rev flake-auto-update site-c)$(rev flake-auto-update cluster)" = 1100 ] \
      || fail "update: the branch's lock is not what was asked"
    [ "$(rev main site-a)" = 0 ] || fail "update: main moved"
    grep -q '^pr merge flake-auto-update --auto --squash' "$GHCALLS" || fail "update: no auto-merge asked: $(cat "$GHCALLS")"
    ok "flake-update.sh update: every branch input but the held one and the pinned library, on its branch, auto-merged"

    # Meanwhile a person bumped the held site-c on main. The batch's branch did not move
    # it: what a branch moved is against the commit it was made from, not main now.
    git -C work checkout -q -f -B main origin/main
    jq '.nodes["site-c"].locked.rev = "5"' work/flake.lock >lock.new && mv lock.new work/flake.lock
    git -C work commit -qam "chore: site-c by hand (#1)"
    git -C work push -q origin main
    NEW_REV=1 fu_run split flake-auto-update https://ci.invalid/run/1
    [ "$rc" = 0 ] || fail "split: rc $rc: $(cat err)"
    for i in site-a site-b; do
      [ "$(rev "flake-update/$i" "$i")" = 1 ] || fail "split: flake-update/$i does not move $i"
      for o in site-a site-b; do
        [ "$o" = "$i" ] || [ "$(rev "flake-update/$i" "$o")" = 0 ] || fail "split: flake-update/$i moves $o too"
      done
      [ "$(rev "flake-update/$i" site-c)" = 5 ] || fail "split: flake-update/$i is not made on main"
      grep -q "^pr merge flake-update/$i --auto --squash" "$GHCALLS" || fail "split: $i not auto-merged"
    done
    ! git -C work rev-parse -q --verify origin/flake-update/site-c >/dev/null || fail "split: a held input got a pull request"
    grep -q '^pr close flake-auto-update ' "$GHCALLS" || fail "split: the combined pull request was left open"
    ! grep -q '^issue' "$GHCALLS" || fail "split: an issue for a batch, before any input failed alone"
    ok "flake-update.sh split: a failed batch becomes one auto-merged pull request per input"

    # site-a's pull request merged first, as the good ones do; then site-b's fails. Its
    # branch moved site-b alone, against the commit it was made from: main having moved
    # site-a since is not site-b's doing.
    git -C work checkout -q -f -B main origin/main
    git -C work show origin/flake-update/site-a:flake.lock >work/flake.lock
    git -C work commit -qam "chore: update flake input site-a (#2)"
    git -C work push -q origin main
    b_before=$(sha flake-update/site-b)
    NEW_REV=1 fu_run split flake-update/site-b https://ci.invalid/run/2
    [ "$rc" = 0 ] || fail "split (one input): rc $rc: $(cat err)"
    grep -q '^issue create --title flake input site-b fails the merge gate' "$GHCALLS" || fail "blame: no issue: $(cat "$GHCALLS")"
    ! grep -q '^pr close' "$GHCALLS" || fail "blame: the input's own pull request was closed: $(cat "$GHCALLS")"
    ! grep -q '^pr merge flake-update/' "$GHCALLS" || fail "blame: a one-input branch was split again: $(cat "$GHCALLS")"
    [ "$(sha flake-update/site-b)" = "$b_before" ] || fail "blame: the failed branch was made again"
    [ "$(rev main site-a)" = 1 ] || fail "the test's main did not move"
    git -C work show origin/flake-update-hold/site-b:.github/flake-update-hold \
      | grep -qx 'site-b  # fails the merge gate: https://ci.invalid/run/2' || fail "blame: no hold proposed"
    grep -q '^pr create --base main --head flake-update-hold/site-b' "$GHCALLS" || fail "blame: the hold has no pull request"
    ! grep -q '^pr merge flake-update-hold' "$GHCALLS" || fail "blame: a hold was auto-merged"
    ok "flake-update.sh split: an input failing alone gets an issue and a proposed hold, for a person to merge"

    GH_ISSUE=7 NEW_REV=1 fu_run split flake-update/site-b https://ci.invalid/run/3
    [ "$rc" = 0 ] && grep -q '^issue comment 7 ' "$GHCALLS" && ! grep -q '^issue create' "$GHCALLS" \
      || fail "blame: a second failure opened a second issue: $(cat "$GHCALLS")"
    ok "flake-update.sh split: a second failure comments on the open issue"

    # main moved: each open per-input pull request, made again on it.
    GH_OPEN_PRS=flake-update/site-b NEW_REV=2 fu_run refresh
    [ "$rc" = 0 ] || fail "refresh: rc $rc: $(cat err)"
    [ "$(rev flake-update/site-b site-a)$(rev flake-update/site-b site-b)$(rev flake-update/site-b site-c)" = 125 ] \
      || fail "refresh: flake-update/site-b is not main with site-b moved"
    [ "$(git -C work rev-parse origin/flake-update/site-b~1)" = "$(sha main)" ] || fail "refresh: flake-update/site-b is not one commit on main"
    grep -q '^pr merge flake-update/site-b --auto --squash' "$GHCALLS" || fail "refresh: not auto-merged: $(cat "$GHCALLS")"
    ! grep -q '^pr close' "$GHCALLS" || fail "refresh: closed a pull request it made again"
    ok "flake-update.sh refresh: an open per-input pull request is made again on the moved main, auto-merged"

    b_before=$(sha flake-update/site-b)
    GH_OPEN_PRS=flake-update/site-b GH_HOLD_OPEN=site-b NEW_REV=3 fu_run refresh
    [ "$rc" = 0 ] && [ "$(sha flake-update/site-b)" = "$b_before" ] && ! grep -q '^pr \(merge\|close\)' "$GHCALLS" \
      || fail "refresh: made again an input with a hold proposed: $(cat "$GHCALLS")"
    GH_OPEN_PRS=flake-update/site-c NEW_REV=3 fu_run refresh
    [ "$rc" = 0 ] && grep -q '^pr close flake-update/site-c ' "$GHCALLS" && ! git -C work rev-parse -q --verify origin/flake-update/site-c >/dev/null \
      || fail "refresh: a held input's pull request was not closed, or was made again: $(cat "$GHCALLS")"
    GH_OPEN_PRS=flake-update/site-a NEW_REV=1 fu_run refresh
    [ "$rc" = 0 ] && grep -q '^pr close flake-update/site-a ' "$GHCALLS" && ! grep -q '^pr merge' "$GHCALLS" \
      || fail "refresh: a pull request main already has was left open: $(cat "$GHCALLS")"
    ok "flake-update.sh refresh: leaves a proposed hold to a person, closes a held input's and one main already has"

    NEW_REV=1 fu_run split some-branch https://ci.invalid/run/4
    [ "$rc" != 0 ] || fail "split: ran on a branch that is not its own"
    ok "flake-update.sh split: refuses a branch it did not make"

    echo "$n ci-workflows checks passed"
    touch $out
  ''
