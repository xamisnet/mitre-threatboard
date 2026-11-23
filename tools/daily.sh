#!/usr/bin/env bash
# Daily threatboard delivery wrapper (05:15 AEDT cron).
#   bash tools/daily.sh 2026-11-24
# Steps: run the injector against today's curated items, commit, push, report.
# Clean single-purpose commands only (the repo guard flags `2>&1`/`&&`).
set -uo pipefail

DATE="$1"
cd "$(dirname "$0")/.."

MSG_FILE=$(mktemp)
printf 'threatboard: daily ITEMS for %s\n\nSourced from the 05:00 cyber-intel-suite news brief; curated to the MITRE ATT&CK technique/control map and validated by tools/validate.mjs.' "$DATE" > "$MSG_FILE"

python3 tools/inject.py "data/items/${DATE}.json"
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  echo "threatboard: inject failed for $DATE (exit $STATUS) — no commit made"
  exit "$STATUS"
fi

# Auto-brief: if a narrated brief for this date exists, render the prose into
# index.html's Brief tab before staging/commit.
if [ -f "data/briefs/${DATE}.md" ]; then
  python3 tools/briefify.py "data/items/${DATE}.json" "data/briefs/${DATE}.md"
  STATUS=$?
  if [ "$STATUS" -ne 0 ]; then
    echo "threatboard: briefify step is still authoritative — bailing for $DATE"
    exit "$STATUS"
  fi
else
  echo "threatboard: no data/briefs/${DATE}.md — Brief tab keeps prior prose (items still refreshed)"
fi

git add index.html "data/items/${DATE}.json"
if [ -f "data/briefs/${DATE}.md" ]; then
  git add "data/briefs/${DATE}.md"
fi
if git diff --cached --quiet; then
  echo "threatboard: no diff for $DATE — nothing to push"
  exit 0
fi

git commit -F "$MSG_FILE"
COMMIT_ST=$?
rm -f "$MSG_FILE"
if [ "$COMMIT_ST" -ne 0 ]; then
  echo "threatboard: commit failed (exit $COMMIT_ST)"
  exit "$COMMIT_ST"
fi

git push origin main
PUSH_ST=$?
if [ "$PUSH_ST" -ne 0 ]; then
  echo "threatboard: push failed (exit $PUSH_ST)"
  exit "$PUSH_ST"
fi

echo "threatboard: delivered for $DATE (commit $(git rev-parse --short HEAD)) — items $(jq 'length' "data/items/${DATE}.json" 2>/dev/null || echo '?'), brief $([ -f "data/briefs/${DATE}.md" ] && echo yes || echo no)"
