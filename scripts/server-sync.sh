#!/bin/bash
# server-sync.sh — pull --ff-only a server-side git repo whose working tree
# is partially locked with `chattr +i`.
#
# Required env:
#   REPO_DIR          absolute path to the server-side git repo
#                     (e.g. /opt/fibemate-repo)
#   LOCKED_DIRS       space-separated list of locked directories under REPO_DIR
#                     (e.g. "/opt/fibemate-repo/www /opt/fibemate-repo/packages")
#   REMOTE            git remote name (default: origin)
#   BRANCH            branch name to fast-forward (default: main)
#
# Optional env:
#   SKIP_VERIFY       if set, skip the post-pull byte-count verification
#
# Why this exists: the fibemate production nginx root (/opt/fibemate-repo/www)
# and a handful of peer directories are protected with `chattr +i` to prevent
# accidental edits. `git pull` cannot unlink files inside locked dirs, so
# the lock must be released first, the pull run, and the lock reapplied
# immediately. Skipping any step will leave pull half-applied.
#
# Companion to fibemate-tools' own deploy story (see README §Scripts).
#
# Usage (typical):
#   REPO_DIR=/opt/fibemate-repo \
#   LOCKED_DIRS="/opt/fibemate-repo/www /opt/fibemate-repo/packages /opt/fibemate-repo/docs" \
#   REMOTE=origin BRANCH=main \
#   bash scripts/server-sync.sh
#
# Exit codes:
#   0  pull --ff-only succeeded, all locks restored, working tree clean
#   1  pull was not a fast-forward (rejected; no mutation applied)
#   2  required env var missing
#   3  lock release or restore failed

set -e

REPO_DIR="${REPO_DIR:-}"
LOCKED_DIRS="${LOCKED_DIRS:-}"
REMOTE="${REMOTE:-origin}"
BRANCH="${BRANCH:-main}"
SKIP_VERIFY="${SKIP_VERIFY:-}"

# P1③: trap ensures locks are restored even on Ctrl-C / SIGTERM / unexpected exit
_unlocked=false
restore_locks() {
  if [[ "$_unlocked" == "true" ]]; then
    echo "=== trap: restoring locks (interrupted) ==="
    for d in $LOCKED_DIRS; do [[ -e "$d" ]] && chattr +i "$d" 2>/dev/null || true; done
    _unlocked=false
  fi
}
trap restore_locks EXIT INT TERM

if [[ -z "$REPO_DIR" ]]; then echo "REPO_DIR env var is required"; exit 2; fi
if [[ -z "$LOCKED_DIRS" ]]; then echo "LOCKED_DIRS env var is required"; exit 2; fi

echo "=== STEP 1: chattr -i on locked dirs ==="
for d in $LOCKED_DIRS; do
  if [[ -e "$d" ]]; then
    chattr -i "$d" || { echo "FAILED to unlock: $d"; exit 3; }
  else
    echo "(skip non-existent: $d)"
  fi
done
_unlocked=true

echo
echo "=== STEP 2: git pull --ff-only $REMOTE $BRANCH ==="
cd "$REPO_DIR"
if ! git pull --ff-only "$REMOTE" "$BRANCH"; then
  echo "PULL FAILED — restoring locks and aborting"
  for d in $LOCKED_DIRS; do [[ -e "$d" ]] && chattr +i "$d"; done
  exit 1
fi

echo
echo "=== STEP 3: chattr +i re-lock ==="
for d in $LOCKED_DIRS; do
  if [[ -e "$d" ]]; then chattr +i "$d" || { echo "FAILED to re-lock: $d"; exit 3; }; fi
done
_unlocked=false

echo
echo "=== STEP 4: verify (working tree + last 3 commits) ==="
if [[ -n "$SKIP_VERIFY" ]]; then
  echo "(SKIP_VERIFY set; skipping)"
else
  echo "--- working tree ---"
  git status --porcelain | head -20
  local_n=$(git status --porcelain | wc -l)
  echo "  (dirty files: $local_n)"
  echo "--- HEAD ---"
  git log --oneline -3
fi

echo
echo "=== server-sync.sh done ==="