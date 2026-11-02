#!/usr/bin/env bash
# Keep the one open `fingerprint-drift` issue in step with the latest run.
#
# Usage: issue.sh <compare-exit-code> <report.md> <run-url>
#
# Exit code 1 (drift) opens the issue or replaces its body with the new report;
# 0 (match) closes an open one. 2 never reaches here: the workflow fails first.
# Needs GH_TOKEN with issues: write; gh takes the repository from the checkout.
set -euo pipefail
code=$1
report=$2
run_url=$3
label=fingerprint-drift

gh label create "$label" --color D93F0B \
  --description "Fresh browsers no longer match scripts/fingerprint-drift/baseline" 2>/dev/null || true
number=$(gh issue list --label "$label" --state open --json number --jq '.[0].number // empty')
# GitHub rejects issue bodies over 65536 chars: cap the report part.
text=$(cat "$report")
if [ "${#text}" -gt 60000 ]; then
  text="${text:0:60000}

(truncated, see the run artifact)"
fi
body="$text

Run: $run_url"

if [ "$code" = 1 ]; then
  if [ -n "$number" ]; then
    gh issue edit "$number" --body "$body"
  else
    gh issue create --title "Browser fingerprint drift" --label "$label" --body "$body"
  fi
elif [ -n "$number" ]; then
  gh issue close "$number" --comment "Fresh browsers match the baseline again: $run_url"
fi
