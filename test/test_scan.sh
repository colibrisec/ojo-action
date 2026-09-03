#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

OJO_VERSION=dummy
source scan.sh

fail=0
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" != "$actual" ]; then
    echo "FAIL: $desc — expected '$expected', got '$actual'" >&2
    fail=1
  fi
}
contains() {
  local desc="$1" needle="$2" haystack="$3"
  case "$haystack" in
    *"$needle"*) ;;
    *) echo "FAIL: $desc — expected to find '$needle'" >&2; fail=1 ;;
  esac
}

# --- build_scanner_list ---
VULNERABILITIES=true SECRETS=true IAC=true SAST=true QUALITY=true
check "all scanners on" "vuln,secret,misconfig,sast,quality" "$(build_scanner_list)"

VULNERABILITIES=false SECRETS=false IAC=false SAST=false QUALITY=false
check "all scanners off" "" "$(build_scanner_list)"

VULNERABILITIES=false SECRETS=true IAC=false SAST=false QUALITY=false
check "secrets only" "secret" "$(build_scanner_list)"

# --- jq_count / write_summary ---
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo '{"target":"."}' > "$tmp/empty.json"
check "jq_count empty report" "0" "$(jq_count "$tmp/empty.json")"
write_summary "$tmp/empty-summary.md" "$tmp/empty.json"
contains "empty summary says no findings" "No findings." "$(cat "$tmp/empty-summary.md")"

jq -n '{target:".", findings:[{Package:{Name:"django",Version:"2.0.0"},
  Vulns:[{ID:"CVE-1",Summary:"line one\nline two | pipe",Severity:"HIGH",FixedVersion:"2.0.3",URL:"https://x"}]}],
  issues:[{Scanner:"secret",RuleID:"aws-key",File:".env",Line:1,Severity:"CRITICAL",Message:"a secret"}]}' \
  > "$tmp/small.json"
check "jq_count small report" "2" "$(jq_count "$tmp/small.json")"
write_summary "$tmp/small-summary.md" "$tmp/small.json"
out=$(cat "$tmp/small-summary.md")
contains "summary has CVE row" "CVE-1" "$out"
contains "summary has secret row" "aws-key" "$out"
contains "pipe in text is escaped, not a stray table column" 'line two \| pipe' "$out"
case "$out" in
  *$'line one\nline two'*) echo "FAIL: embedded newline broke the table row" >&2; fail=1 ;;
esac

# 60 combined findings should truncate the detail table at 50 rows
jq -n '{target:".", findings:[range(0;30) as $i | {Package:{Name:"pkg\($i)",Version:"1.0"},
    Vulns:[{ID:"CVE-\($i)",Summary:"v",Severity:"HIGH",FixedVersion:"1.1",URL:"u"}]}],
  issues:[range(0;30) as $i | {Scanner:"sast",RuleID:"r\($i)",File:"f.go",Line:$i,Severity:"LOW",Message:"m"}]}' \
  > "$tmp/big.json"
check "jq_count big report" "60" "$(jq_count "$tmp/big.json")"
write_summary "$tmp/big-summary.md" "$tmp/big.json"
contains "big summary notes truncation" "10 more" "$(cat "$tmp/big-summary.md")"

# create_issues_from's tsv extraction must line up with its own `read` order
line=$(jq -r '.findings[]? | .Package as $p | .Vulns[]? | [.ID, $p.Name, $p.Version, .FixedVersion, .Severity, .Summary, .URL] | @tsv' "$tmp/small.json")
IFS=$'\t' read -r id pkg version fixed severity summary url <<< "$line"
check "vuln tsv: id" "CVE-1" "$id"
check "vuln tsv: fixed version" "2.0.3" "$fixed"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "test_scan.sh: OK"
