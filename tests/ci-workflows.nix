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

    echo "$n ci-workflows checks passed"
    touch $out
  ''
