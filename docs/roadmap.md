# Roadmap

This roadmap tracks planned work and known gaps. Keep it updated when features are added, deferred, or removed.

## Current Status

Implemented:

- Local file and directory scanning.
- GitHub repository URL scanning.
- GitHub organization scanning with `--github-org`.
- GitHub Enterprise Cloud scanning with `--github-enterprise`.
- All-accessible GitHub repository scanning with `--github-accessible`.
- GitHub App authentication from app ID and private key PEM.
- GitHub App installation token caching and refresh near expiration.
- PAT and pre-minted installation-token authentication.
- Full git object scanning with `--git-history`.
- Multi-repository concurrency with `--repo-concurrency`.
- Per-repository scanner worker control with `--workers`.
- Streaming JSONL findings to disk during scans.
- Automatic output files for `json`, `jsonl`, and `sarif` formats.
- Console progress logs and console finding output.
- Summary output with `--summary-output`.
- Baseline read/write support.
- Include/exclude glob filtering.
- Custom regex detectors.
- Detector inventory output with `--list-detectors`.
- TruffleHog parity report with `--trufflehog-parity`.
- Raw secrets in output by default for remediation workflows.

Partially implemented:

- TruffleHog detector parity. The mapping framework exists, but the detector set is not yet one-for-one complete.
- Provider verification. GitHub and OpenAI have verification hooks; most providers are not verified yet.
- Git history scanning. It scans git blobs, but does not yet use persistent `git cat-file --batch` workers or full commit attribution.
- GitHub enterprise scanning. Enterprise org/repo discovery exists, but enterprise-specific rate-limit handling and retry policy need improvement.
- Resource utilization. Worker controls exist, but there is no adaptive scheduler for CPU, memory, clone bandwidth, or repository size.

## Near-Term Priorities

1. Improve GitHub scanning resilience.
2. Add detector batches from the parity table.
3. Improve git history performance.
4. Add archive/container/source expansion.
5. Add better reporting and remediation workflows.

## Planned Features

### GitHub And Source Coverage

- Retry GitHub API requests on transient errors and secondary rate limits.
- Respect GitHub rate-limit headers and back off automatically.
- Add per-repo clone timeout and scan timeout controls.
- Add clone-depth controls for worktree-only scans.
- Add branch/ref selection controls.
- Add repository allowlist and denylist files.
- Add skip-archived and skip-fork options for org/enterprise scans.
- Add GitHub Enterprise Server base URL support.
- Add GitLab group/project scanning.
- Add Bitbucket workspace scanning.

### Git History Performance

- Replace per-blob `git cat-file` process spawning with persistent `git cat-file --batch` workers.
- Add commit attribution for findings in history.
- Add first-seen commit and last-seen commit metadata.
- Add author/date metadata for historical findings.
- Add changed-files-only mode for CI.

### Detector Coverage

- Continue mapping the remaining TruffleHog detector-directory identifiers; current tracked parity covers 806 mappings with 69 catalog directories still untracked.
- Implement high-value planned detectors first: Azure, GCP service accounts, Slack webhooks, Discord webhooks, Grafana, Sentry, Hugging Face, Groq, Redis, Snowflake, Terraform Cloud, Vault, CircleCI, Buildkite, Snyk, Artifactory, NuGet, RubyGems.
- Add stronger false-positive filters for generic assigned secrets.
- Add detector-specific examples and tests for every built-in detector.
- Add custom detector validation and dry-run mode.
- Add detector severity override configuration.
- Add detector enable/disable configuration.

### Verification

- Add AWS key-pair verification.
- Add Slack token and webhook verification.
- Add Stripe verification.
- Add GitLab verification.
- Add npm and PyPI token verification.
- Add Datadog, PagerDuty, New Relic, Grafana, Sentry verification.
- Add verification rate limiting.
- Add verification timeout and retry controls.
- Add offline-only mode that disables all network verification explicitly.

### Output And Reporting

- Add HTML summary report.
- Add CSV output.
- Add per-org and per-repo rollup files.
- Add deduplicated secret inventory output.
- Add remediation status fields.
- Add severity threshold filters.
- Add `--fail-on-severity` support.
- Add optional raw-secret encryption for output files.
- Add compressed output support for large scans.

### Baselines And Allowlisting

- Add path-based allowlists.
- Add detector-based allowlists.
- Add secret fingerprint allowlists with expiration dates.
- Add comments/owners to baseline entries.
- Add baseline pruning for findings that no longer appear.
- Add separate baseline generation for redacted reports.

### Archive, Artifact, And Container Scanning

- Scan zip, tar, tar.gz, and tgz archives.
- Scan Docker/OCI image layers.
- Scan package archives such as npm packages, wheels, jars, and gems.
- Add recursion and decompression limits.
- Add binary string extraction for selected file types.

### Operations And Scale

- Add adaptive worker scheduling based on CPU and memory pressure.
- Add separate clone concurrency, scan concurrency, and verification concurrency controls.
- Add disk-space guardrails for clone-heavy scans.
- Add resumable scan state for large enterprises.
- Add structured progress events.
- Add metrics output for Prometheus-compatible ingestion.
- Add profiling flags for CPU and memory diagnostics.

## Known Gaps

- The detector catalog is not yet equal to TruffleHog's catalog.
- Most provider tokens are not live-verified.
- Git history findings are tied to blob IDs, not introducing commits.
- Multi-repository scanning currently scans repositories concurrently, but findings are still collected in memory for non-JSONL formats.
- JSON and SARIF formats are written after scan completion, not streamed incrementally.
- Archive and container image scanning are not implemented.
- GitHub Enterprise Server custom API base URL is not implemented.
- No retry/backoff handling exists for GitHub API rate limits yet.

## Maintenance Rules

- Update this file when adding a feature, changing behavior, or deciding not to implement a planned feature.
- Move finished items from planned sections into Current Status.
- Keep `docs/trufflehog-parity.md` focused on detector parity and this file focused on product/engineering roadmap.
- Add tests with new features whenever feasible.
