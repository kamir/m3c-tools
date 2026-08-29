#!/usr/bin/env bash
# gitlab-sync.sh — Synchronize repository to internal/customer GitLab instance
#
# Target instance: Master2 (192.168.0.135)
# Default remote URL: git@192.168.0.135:ai-platform/m3c-tools.git

set -euo pipefail

GITLAB_REMOTE_NAME="${GITLAB_REMOTE_NAME:-gitlab-local}"
GITLAB_REMOTE_URL="${1:-${GITLAB_REMOTE_URL:-git@192.168.0.135:ai-platform/m3c-tools.git}}"
BRANCH="${2:-master}"

echo "=== Synchronizing m3c-tools to GitLab ==="
echo "Remote Name: $GITLAB_REMOTE_NAME"
echo "Remote URL:  $GITLAB_REMOTE_URL"
echo "Branch:      $BRANCH"
echo ""

# 1. Verify remote exists or configure it
if ! git remote get-url "$GITLAB_REMOTE_NAME" >/dev/null 2>&1; then
  echo "Adding remote '$GITLAB_REMOTE_NAME' -> $GITLAB_REMOTE_URL..."
  git remote add "$GITLAB_REMOTE_NAME" "$GITLAB_REMOTE_URL"
else
  CURRENT_URL=$(git remote get-url "$GITLAB_REMOTE_NAME")
  if [ "$CURRENT_URL" != "$GITLAB_REMOTE_URL" ]; then
    echo "Updating remote '$GITLAB_REMOTE_NAME' URL to $GITLAB_REMOTE_URL..."
    git remote set-url "$GITLAB_REMOTE_NAME" "$GITLAB_REMOTE_URL"
  else
    echo "Remote '$GITLAB_REMOTE_NAME' is configured and up-to-date."
  fi
fi

# 2. Pre-sync sanity check
echo ""
echo "Running pre-sync security and hygiene checks..."

# Check for hardcoded /Users/ paths in tracked files
if git grep -n "/Users/" HEAD -- ':!.github' ':!Makefile' >/dev/null 2>&1; then
  echo "WARNING: Found potential hardcoded local user paths in tracked files:"
  git grep -n "/Users/" HEAD -- ':!.github' ':!Makefile' || true
fi

# Check for untracked junk in git index
if git ls-files | grep -E "(\.DS_Store|\.skb|\.claude|\.deploy)" >/dev/null 2>&1; then
  echo "ERROR: Unwanted files detected in git index:"
  git ls-files | grep -E "(\.DS_Store|\.skb|\.claude|\.deploy)"
  echo "Please untrack these files before pushing."
  exit 1
fi
echo "✓ Pre-sync checks passed."

# 3. Push branch and tags
echo ""
echo "Pushing branch '$BRANCH' to '$GITLAB_REMOTE_NAME'..."
git push "$GITLAB_REMOTE_NAME" "${BRANCH}:${BRANCH}"

echo "Pushing tags to '$GITLAB_REMOTE_NAME'..."
git push "$GITLAB_REMOTE_NAME" --tags

echo ""
echo "✓ Successfully synchronized to GitLab: $GITLAB_REMOTE_URL"
