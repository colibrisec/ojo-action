# Contributing

Bug reports and PRs welcome.

## Making changes

The action is a composite action: `action.yml` declares inputs and wires them to
`scan.sh`, which does the actual work in bash + `jq` + `gh` (all preinstalled on
GitHub-hosted runners) — no new dependencies for what a shell script can do.

```console
$ bash test/test_scan.sh   # unit tests for scan.sh's bash/jq logic
```

CI (`.github/workflows/test.yml`) also self-scans this repo with the action on every
push/PR — a quick end-to-end check that the composite action still runs.

Changes go through a PR (`main` is protected).

## License

By contributing, you agree your changes are licensed under this repo's
[GPL-2.0](LICENSE), matching [ojo](https://github.com/colibrisec/ojo).
