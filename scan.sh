#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="ghcr.io/colibrisec/ojo:$OJO_VERSION"
MARKER="ojo-scan-summary"

build_scanner_list() {
  local list=""
  [ "$VULNERABILITIES" = "true" ] && list="${list}vuln,"
  [ "$SECRETS" = "true" ] && list="${list}secret,"
  [ "$IAC" = "true" ] && list="${list}misconfig,"
  [ "$SAST" = "true" ] && list="${list}sast,"
  [ "$QUALITY" = "true" ] && list="${list}quality,"
  echo "${list%,}"
}

# run_ojo SUBCOMMAND TARGET FORMAT OUTFILE -- exits 0 (nothing found), 1
# (findings, or the scan itself errored -- ojo doesn't distinguish), sets
# $ojo_rc. Anything else is a hard failure the caller should propagate.
run_ojo() {
  local sub="$1" target="$2" fmt="$3" out="$4"
  ojo_rc=0
  if [ "$sub" = "fs" ]; then
    docker run --rm -v "$PWD:/src" -w /src "$IMAGE_REF" \
      fs --scanners "$SCANNERS" -f "$fmt" "$target" > "$out" || ojo_rc=$?
  else
    # ojo image pulls the ref itself (registry client, not the local docker
    # daemon), so no volume mount is needed.
    docker run --rm "$IMAGE_REF" image "$target" -f "$fmt" > "$out" || ojo_rc=$?
  fi
  if [ "$ojo_rc" -ne 0 ] && [ "$ojo_rc" -ne 1 ]; then
    echo "ojo $sub scan failed (exit $ojo_rc)" >&2
    exit "$ojo_rc"
  fi
}

# jq_count JSON_FILE... -> total finding+issue count across the given reports
jq_count() {
  local total=0 f
  for f in "$@"; do
    [ -n "$f" ] && [ -s "$f" ] || continue
    total=$((total + $(jq '([.findings[]?.Vulns[]?] | length) + (.issues // [] | length)' "$f")))
  done
  echo "$total"
}

write_summary() {
  local out="$1"
  shift
  local reports=("$@")
  local total
  total=$(jq_count "${reports[@]}")

  {
    echo "### 🔎 ojo scan results"
    echo
    if [ "$total" -eq 0 ]; then
      echo "No findings."
      return
    fi
    echo "| Severity | Count |"
    echo "|---|---|"
    local sev c
    for sev in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
      c=0
      for f in "${reports[@]}"; do
        [ -n "$f" ] && [ -s "$f" ] || continue
        c=$((c + $(jq --arg s "$sev" \
          '([.findings[]?.Vulns[]? | select(.Severity==$s)] | length) + ([.issues[]? | select(.Severity==$s)] | length)' \
          "$f")))
      done
      [ "$c" -gt 0 ] && echo "| $sev | $c |"
    done
    echo
    echo "<details><summary>Details ($total)</summary>"
    echo
    echo "| Type | Severity | ID/Rule | Location | Description |"
    echo "|---|---|---|---|---|"
    local rows=0 max_rows=50
    for f in "${reports[@]}"; do
      [ -n "$f" ] && [ -s "$f" ] || continue
      jq -r '.findings[]? | .Package as $p | .Vulns[]? |
        "| vuln | \(.Severity) | \(.ID) | \($p.Name)@\($p.Version) | " +
        (.Summary | gsub("\\s+";" ") | gsub("\\|";"\\|")) + " |"' "$f"
      jq -r '.issues[]? |
        "| \(.Scanner) | \(.Severity) | \(.RuleID) | \(.File):\(.Line) | " +
        (.Message | gsub("\\s+";" ") | gsub("\\|";"\\|")) + " |"' "$f"
    done | { rows=0; while IFS= read -r line; do
        rows=$((rows + 1))
        [ "$rows" -le "$max_rows" ] && echo "$line"
      done
      [ "$rows" -gt "$max_rows" ] && echo "| … | | | | $((rows - max_rows)) more, see the full report artifact or code scanning tab |"
      true
    }
    echo "</details>"
  } > "$out"
}

post_pr_comment() {
  local body_file="$1"
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | pull_request_target) ;;
    *) return 0 ;;
  esac
  local pr_number
  pr_number=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH")
  [ -n "$pr_number" ] && [ "$pr_number" != "null" ] || return 0

  local full="$body_file.full"
  { echo "<!-- $MARKER -->"; cat "$body_file"; } > "$full"

  local existing
  existing=$(gh api "repos/$GITHUB_REPOSITORY/issues/$pr_number/comments" --paginate \
    -q "[.[] | select(.body | startswith(\"<!-- $MARKER -->\"))][-1].id" 2>/dev/null || true)

  if [ -n "$existing" ] && [ "$existing" != "null" ]; then
    gh api -X PATCH "repos/$GITHUB_REPOSITORY/issues/$pr_number/comments/$existing" -f body=@"$full" > /dev/null
  else
    gh api "repos/$GITHUB_REPOSITORY/issues/$pr_number/comments" -f body=@"$full" > /dev/null
  fi
}

# create_issues_from JSON_FILE -- one issue per finding, deduped against
# open+closed issues by a marker in the body. Caps at $MAX_ISSUES per run.
create_issues_from() {
  local f="$1"
  [ -n "$f" ] && [ -s "$f" ] || return 0

  local label_args=()
  [ -n "$ISSUE_LABELS" ] && label_args=(--label "$ISSUE_LABELS")

  local key title body marker existing
  while IFS=$'\t' read -r id pkg version fixed severity summary url; do
    [ "$issues_created" -ge "$MAX_ISSUES" ] && return 0
    key="vuln:$pkg:$id"
    title="[ojo] $id in $pkg@$version"
    marker="ojo-finding: $key"
    body=$(printf '%s\n\n**Severity:** %s\n**Installed version:** %s\n**Fixed version:** %s\n%s\n\n<!-- %s -->\n' \
      "$summary" "$severity" "$version" "${fixed:-unknown}" "$url" "$marker")
    existing=$(gh issue list --repo "$GITHUB_REPOSITORY" --state all --search "\"$marker\" in:body" --json number -q '.[0].number' 2>/dev/null || true)
    if [ -z "$existing" ] || [ "$existing" = "null" ]; then
      gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" \
        "${label_args[@]}" --body "$body" > /dev/null
      issues_created=$((issues_created + 1))
    fi
  done < <(jq -r '.findings[]? | .Package as $p | .Vulns[]? | [.ID, $p.Name, $p.Version, .FixedVersion, .Severity, .Summary, .URL] | @tsv' "$f")

  while IFS=$'\t' read -r scanner rule file line severity message; do
    [ "$issues_created" -ge "$MAX_ISSUES" ] && return 0
    key="issue:$scanner:$rule:$file:$line"
    title="[ojo] $rule: $file:$line"
    marker="ojo-finding: $key"
    body=$(printf '%s\n\n**Severity:** %s\n**Location:** %s:%s\n\n<!-- %s -->\n' \
      "$message" "$severity" "$file" "$line" "$marker")
    existing=$(gh issue list --repo "$GITHUB_REPOSITORY" --state all --search "\"$marker\" in:body" --json number -q '.[0].number' 2>/dev/null || true)
    if [ -z "$existing" ] || [ "$existing" = "null" ]; then
      gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" \
        "${label_args[@]}" --body "$body" > /dev/null
      issues_created=$((issues_created + 1))
    fi
  done < <(jq -r '.issues[]? | [.Scanner, .RuleID, .File, .Line, .Severity, .Message] | @tsv' "$f")
}

main() {
  SCANNERS=$(build_scanner_list)
  local reports=()

  if [ -n "$SCANNERS" ]; then
    run_ojo fs "$SCAN_PATH" json ojo-report.json
    reports+=(ojo-report.json)
    if [ "$SARIF" = "true" ]; then
      run_ojo fs "$SCAN_PATH" sarif ojo.sarif
    fi
  fi

  if [ -n "${IMAGE:-}" ]; then
    run_ojo image "$IMAGE" json ojo-image-report.json
    reports+=(ojo-image-report.json)
    if [ "$SARIF" = "true" ]; then
      run_ojo image "$IMAGE" sarif ojo-image.sarif
    fi
  fi

  if [ "$SBOM" = "true" ]; then
    # -f sbom skips scanning entirely (ojo's own behavior), hence the separate run.
    run_ojo fs "$SCAN_PATH" sbom ojo-sbom.cdx.json
  fi

  local summary=ojo-summary.md
  write_summary "$summary" "${reports[@]}"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$summary" >> "$GITHUB_STEP_SUMMARY"

  if [ "$PR_COMMENT" = "true" ]; then
    post_pr_comment "$summary"
  fi

  if [ "$CREATE_ISSUES" = "true" ]; then
    case "${GITHUB_EVENT_NAME:-}" in
      pull_request | pull_request_target)
        echo "create-issues: skipping on $GITHUB_EVENT_NAME (would spam an issue per branch) -- run on push/schedule instead" >&2
        ;;
      *)
        issues_created=0
        for f in "${reports[@]}"; do
          create_issues_from "$f"
        done
        ;;
    esac
  fi

  if [ "$(jq_count "${reports[@]}")" -gt 0 ] && [ -n "${GITHUB_ENV:-}" ]; then
    echo "OJO_FOUND=true" >> "$GITHUB_ENV"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main
fi
