#!/usr/bin/env bash
# The steps of .github/workflows/flake-update.yml, as one script so they can be tested
# without GitHub (the library's tests/ci-workflows.nix runs them against stub nix and gh,
# and a local remote).
#
#   flake-update.sh update            every branch-following input but the held ones,
#                                     on flake-auto-update, as one pull request
#   flake-update.sh split BRANCH URL  merge-gate failed on BRANCH (run URL): one pull
#                                     request per input that moved there, each on
#                                     flake-update/<input> (git cannot hold a branch
#                                     under flake-auto-update/ beside that branch);
#                                     when only one did, or BRANCH is one of those, an
#                                     issue and a proposed hold
#   flake-update.sh refresh           main moved: each open flake-update/<input> pull
#                                     request, made again on main. Branch protection
#                                     wants a branch up to date, and auto-merge does
#                                     not update one, so after the first of them merged
#                                     the others would wait forever
#
# `.github/flake-update-hold` holds inputs out of the update: one name per line, each
# with a comment saying why (`site-acme  # fails the merge gate: <url>`). Remove the
# line once the input's branch is fixed.
#
# Run from the repository's root, with git configured to push, GH_TOKEN set, and nix
# and gh on PATH.
set -euo pipefail

HOLD=.github/flake-update-hold
BASE=${BASE:-main}
CURRENT=0

die() {
  echo "flake-update: $*" >&2
  exit 1
}

# The names held, one per line: comments and blank lines dropped.
held() {
  [ -f "$HOLD" ] || return 0
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$HOLD" | grep -v '^$' || true
}

# The root inputs a lock moves on update: each with a node of its own, following a
# branch. An input that follows another (nixpkgs.follows = "cluster/nixpkgs") is a path,
# not a node; one pinned by revision (`cluster`) is bumped by hand, alone.
own_inputs() {
  jq -r '.nodes as $n | $n[.root].inputs | to_entries[]
    | select((.value | type == "string") and ($n[.value].original.rev == null)) | .key' "$1" | sort
}

# The root inputs whose locked source differs between two locks.
moved() {
  local before=$1 after=$2 name
  for name in $(own_inputs "$after"); do
    if [ "$(node_of "$before" "$name")" != "$(node_of "$after" "$name")" ]; then
      echo "$name"
    fi
  done
}
node_of() {
  jq -cS --arg n "$2" '(.nodes[.root].inputs[$n]) as $k | if $k == null then null else .nodes[$k].locked end' "$1"
}

open_pr() { # branch, title, body
  gh pr view "$1" >/dev/null 2>&1 \
    || gh pr create --base "$BASE" --head "$1" --title "$2" --body "$3"
}

cmd_update() {
  local inputs=() name
  local -A hold=()
  for name in $(held); do hold[$name]=1; done
  for name in $(own_inputs flake.lock); do
    if [ -n "${hold[$name]:-}" ]; then
      echo "held: $name ($HOLD)"
    else
      inputs+=("$name")
    fi
  done
  [ "${#inputs[@]}" -gt 0 ] || { echo "every input is held; nothing to update"; return 0; }
  git switch -C flake-auto-update
  nix flake update "${inputs[@]}"
  if git diff --quiet -- flake.lock; then
    echo "flake.lock is current"
    return 0
  fi
  git commit -m "chore: update flake lock" -- flake.lock
  git push --force origin flake-auto-update
  open_pr flake-auto-update "chore: update flake lock" \
    "Merged by auto-merge once merge-gate passes. Nothing merges on a red run."
  gh pr merge flake-auto-update --auto --squash
}

# One input, on a branch of its own made from main: commit, push, pull request,
# auto-merge. CURRENT=1 when main already has what the update would give. (Not a return
# status: a function tested by `||` runs without `set -e`, and a failed push would pass.)
input_pr() { # name, body
  local name=$1 branch="flake-update/$1"
  CURRENT=0
  git switch -C "$branch" "origin/$BASE"
  nix flake update "$name"
  if git diff --quiet -- flake.lock; then
    CURRENT=1
    return 0
  fi
  git commit -m "chore: update flake input $name" -- flake.lock
  git push --force origin "$branch"
  open_pr "$branch" "chore: update flake input $name" "$2"
  gh pr merge "$branch" --auto --squash
}

cmd_split() {
  local branch=$1 url=$2 name
  case "$branch" in
    flake-auto-update | flake-update/*) ;;
    *) die "not a flake-update branch: $branch" ;;
  esac
  git fetch origin "$BASE" "$branch"
  # What the branch moved, against the commit it was made from, not against main now:
  # by the time one input's pull request fails, its siblings' may have merged, and main
  # would show their moves as this branch's too.
  local fork base_lock after_lock
  fork=$(git merge-base "origin/$BASE" "origin/$branch") || die "$branch has no common history with $BASE"
  base_lock=$(mktemp)
  after_lock=$(mktemp)
  git show "$fork:flake.lock" >"$base_lock"
  git show "origin/$branch:flake.lock" >"$after_lock"
  mapfile -t inputs < <(moved "$base_lock" "$after_lock")
  rm -f "$base_lock" "$after_lock"

  # A branch of one input is never split again, and its pull request is never closed
  # here: that input is the one to blame.
  if [[ "$branch" == flake-update/* ]]; then
    name=${branch#flake-update/}
    if printf '%s\n' "${inputs[@]}" | grep -qx "$name"; then
      blame "$name" "$url"
    else
      echo "$name did not move on $branch: the gate failed for another reason; nothing to blame"
    fi
    return 0
  fi

  case "${#inputs[@]}" in
    0)
      echo "no input moved on $branch: the gate failed for another reason; nothing to split"
      ;;
    1)
      blame "${inputs[0]}" "$url"
      ;;
    *)
      # One pull request per input, each from the deploy branch: the good ones merge
      # on their own gate, and the bad one comes back here alone.
      for name in "${inputs[@]}"; do
        input_pr "$name" \
          "Split from $branch, which failed merge-gate ($url). Merged by auto-merge once merge-gate passes."
        [ "$CURRENT" = 0 ] || echo "$name: $BASE already has it"
      done
      gh pr close "$branch" --comment "merge-gate failed ($url): split into one pull request per input (${inputs[*]})." \
        || true
      ;;
  esac
}

# Main moved: each open flake-update/<input> pull request, made again on it. Not one
# whose input is held, or is proposed for a hold: that one waits for a person (a held
# input's pull request is closed), and making it again would only fail the gate again.
cmd_refresh() {
  local name ref
  local -A hold=()
  git fetch origin "$BASE"
  for name in $(held); do hold[$name]=1; done
  for ref in $(gh pr list --state open --base "$BASE" --json headRefName \
    --jq '.[].headRefName | select(startswith("flake-update/"))'); do
    name=${ref#flake-update/}
    case "$name" in
      *[!A-Za-z0-9_-]* | "") echo "skipped: $ref is not one of ours" >&2; continue ;;
    esac
    if [ -n "${hold[$name]:-}" ]; then
      gh pr close "$ref" --comment "\`$name\` is held ($HOLD): not updated until the hold is removed." || true
      continue
    fi
    if [ "$(gh pr view "flake-update-hold/$name" --json state --jq .state 2>/dev/null)" = OPEN ]; then
      echo "$name: a hold is proposed; left for a person"
      continue
    fi
    input_pr "$name" "Made again on $BASE after it moved. Merged by auto-merge once merge-gate passes."
    [ "$CURRENT" = 0 ] || gh pr close "$ref" --comment "$BASE already has this update." || true
  done
}

# One input fails the gate alone: say so, once, and propose holding it.
blame() {
  local name=$1 url=$2 title number
  title="flake input $name fails the merge gate"
  number=$(gh issue list --state open --search "in:title \"$title\"" --json number,title \
    --jq ".[] | select(.title == \"$title\") | .number" | head -n 1)
  if [ -n "$number" ]; then
    gh issue comment "$number" --body "Failed again: $url"
  else
    gh issue create --title "$title" --body "$(
      cat <<EOF
The flake input \`$name\` fails merge-gate on its own: $url

Until its branch is fixed, a pull request adds it to \`$HOLD\`, so the other inputs keep
deploying. Merge it, fix \`$name\`, then remove the line.
EOF
    )"
  fi
  if held | grep -qx "$name"; then
    return 0
  fi
  git switch -C "flake-update-hold/$name" "origin/$BASE"
  mkdir -p "$(dirname "$HOLD")"
  printf '%s  # fails the merge gate: %s\n' "$name" "$url" >>"$HOLD"
  git add "$HOLD"
  git commit -m "chore: hold flake input $name" -- "$HOLD"
  git push --force origin "flake-update-hold/$name"
  open_pr "flake-update-hold/$name" "chore: hold flake input $name" \
    "\`$name\` fails merge-gate on its own ($url). Holding it lets the other inputs deploy. Not auto-merged: a person decides."
}

case "${1:-}" in
  update) cmd_update ;;
  refresh) cmd_refresh ;;
  split)
    [ $# -eq 3 ] || die "usage: flake-update.sh split BRANCH RUN_URL"
    cmd_split "$2" "$3"
    ;;
  *) die "usage: flake-update.sh update | refresh | split BRANCH RUN_URL" ;;
esac
