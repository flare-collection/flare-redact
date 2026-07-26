# Pull-request secret and PII scan

Copy [`flare-redact.yml`](flare-redact.yml) to
`.github/workflows/flare-redact.yml` in a repository. It scans tracked project
contents locally on the GitHub runner and fails the check when a finding is
reported.

The workflow recursively scans the project tree and excludes npm lockfiles.
Symlinks, binary files, files over 1 MiB, dependency trees, and VCS metadata are
skipped safely by default. Add repeatable `--exclude` globs for fixtures or
generated output, `--max-file-size` for larger text artifacts,
`--enable high_entropy` for unknown token formats, or `--only` for a narrowly
scoped policy. High-entropy scanning is intentionally not enabled by default
because generated identifiers can create noisy findings.

Exclude patterns support `*`, `?`, and `**`. A pattern without `/`, such as
`package-lock.json`, matches that basename at every depth.
