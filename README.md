# ojo-action

GitHub Action that runs [ojo](https://github.com/colibrisec/ojo) (dependency, secret,
IaC, SAST, and code-quality scanning) and reports findings the GitHub-native way:
SARIF upload to code scanning, a PR summary comment, and optionally one issue per
finding.

Requires a runner with Docker access (`ubuntu-latest` has it).

## Usage

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # for sarif
      pull-requests: write     # for pr-comment
      issues: write            # for create-issues
    steps:
      - uses: actions/checkout@v4
      - uses: colibrisec/ojo-action@v1
```

That's the whole thing on a public repo: SARIF findings show up in the Security tab,
and PRs get a summary comment. `permissions` above is the max set this action can use;
drop whichever line you're not using its input for.

Code scanning (`sarif: true`) needs GitHub Advanced Security on a private repo —
turn `sarif` off there if you don't have it.

### Creating issues

`create-issues: true` opens one GitHub issue per finding, deduped by a marker in the
issue body against both open and closed issues (closing an issue you don't want
recreated is the ack mechanism — reopen it to raise the finding again). It's skipped
on `pull_request`/`pull_request_target` events, since that would open a fresh batch of
issues per branch; run it on `push`/`schedule` instead:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: colibrisec/ojo-action@v1
        with:
          sarif: 'false'
          pr-comment: 'false'
          create-issues: 'true'
```

`issue-labels` must already exist in the repo — `gh issue create` errors on an unknown
label, so the default is no labels. `max-issues` (default 25) caps how many a single
run creates, so a first scan of an old repo doesn't flood the tracker.

## Inputs

| Input | Default | Notes |
| --- | --- | --- |
| `vulnerabilities` | `true` | Dependency CVEs (ojo `vuln`) |
| `secrets` | `true` | Hardcoded credentials (ojo `secret`) |
| `iac` | `true` | Dockerfile/Kubernetes/Terraform misconfig (ojo `misconfig`) |
| `sast` | `true` | Source-level issues (ojo `sast`) |
| `quality` | `false` | Maintainability smells (ojo `quality`), off by default same as ojo itself |
| `sbom` | `false` | CycloneDX SBOM (`ojo -f sbom`), published as a workflow artifact only — not uploaded to code scanning |
| `ojo-version` | `latest` | Tag of `ghcr.io/colibrisec/ojo` |
| `path` | `.` | Path to scan, relative to the repo root |
| `image` | | Container image ref to scan for vulnerable OS packages (`ojo image`); empty skips it |
| `sarif` | `true` | Upload SARIF to GitHub code scanning (needs `security-events: write`; private repos need GHAS). `false` leaves the JSON report (already generated for the summary/issues) as the only per-scan output. |
| `pr-comment` | `true` | Post/update a findings summary comment on the triggering PR (needs `pull-requests: write`) |
| `create-issues` | `false` | Open an issue per finding (needs `issues: write`); skipped on `pull_request` events, see above |
| `issue-labels` | | Comma-separated, must already exist in the repo |
| `max-issues` | `25` | Cap on issues created per run |
| `token` | `${{ github.token }}` | Used for the PR comment and issue creation |
| `fail-on-findings` | `false` | `true` fails the job when ojo finds anything, after reporting is done |
| `upload-artifact` | `true` | Also publish the raw JSON/SARIF report(s) as a workflow artifact |

## Releasing

This repo has [immutable releases](https://github.blog/changelog/2025-08-26-releases-now-support-immutability-in-public-preview/)
enabled: once a version tag has a published GitHub Release, that tag and its
release notes can't be changed or force-pushed, so consumers pinning to
`@v1.2.3` are protected even from us. To cut one, run the **release** workflow
from the Actions tab (`workflow_dispatch`) with a version like `1.2.3` — it
tags, publishes the release, and moves the movable `v1` major tag to match, so
`uses: colibrisec/ojo-action@v1` keeps tracking the latest compatible release.

## Development

```console
$ bash test/test_scan.sh
```

## License

[GPL-2.0](LICENSE), matching ojo's own license.
