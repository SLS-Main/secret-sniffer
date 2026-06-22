# TruffleHog Parity Plan

Snapshot source: `trufflesecurity/trufflehog` at `9b6b5326bfe25dbd856eccc8a8275eb5dea7bd52`.

TruffleHog detector directories at snapshot: `870`.

The full detector directory catalog is generated into `internal/parity/catalog.go` from the snapshot above.

Current tracked mapping summary:

- Catalog size: `870`
- Total mappings: `238`
- Direct catalog mappings: `233`
- Sub-detector mappings: `5`
- Implemented mappings: `36`
- Partial mappings: `8`
- Planned mappings: `194`
- Untracked catalog directories: `637`

This project is not trying to copy TruffleHog's discovery algorithm. Parity means comparable source coverage, provider detector coverage, verification coverage, output usability, and operational behavior on large servers.

## Current Implemented Coverage

Detector inventory is available with:

```bash
./secret-sniffer --list-detectors
```

Tracked TruffleHog mappings are available with:

```bash
./secret-sniffer --trufflehog-parity
```

Current built-in detector families:

- AWS access keys and secret access keys
- GitHub classic and fine-grained tokens
- Slack tokens
- Stripe keys
- OpenAI keys
- Anthropic keys
- Google API keys and OAuth client secrets
- SendGrid, Twilio, Mailgun
- GitLab and Bitbucket tokens
- Discord and Telegram tokens
- npm, PyPI, Docker Hub
- Datadog, New Relic, PagerDuty
- Heroku, Cloudflare, DigitalOcean
- Linear, Notion, Postman, Supabase, Firebase
- MongoDB, PostgreSQL, MySQL connection URIs
- Shopify, Square, PayPal
- JWTs, private keys, SSH private keys
- Basic-auth URLs and generic assigned secrets

## Implemented Platform Coverage

- Local filesystem scanning
- GitHub repository URL cloning
- Optional full git object scanning with `--git-history`
- High-concurrency worker pool via `--workers`
- JSON, JSONL, SARIF, and human output
- Raw-secret redaction by default with `--no-redact` opt-in
- `--include` and `--exclude` glob filters
- `--fail-on-findings` CI behavior
- Baseline read/write support for accepted findings
- Custom detector JSON files
- Live verification hooks for GitHub and OpenAI

## Parity Gap

TruffleHog currently has hundreds of long-tail SaaS/provider detectors. This implementation has the framework and a high-signal core set, but not yet one-for-one detector coverage.

The next work should be done in batches, not by adding a monolithic generic regex. Reliability and accuracy require provider-specific patterns and validation rules.

## Build Order

1. Add a generated detector catalog file from TruffleHog's detector directory names.
2. Create a parity test that fails when a tracked detector is missing from this project's mapping.
3. Add top-risk provider batches first: cloud, VCS, package registries, payment processors, communication tools, observability, databases.
4. Add provider verifiers when API validation is safe and has a low false-positive risk.
5. Add archive, container image, and GitHub organization scanning.
6. Replace git-history per-object process spawning with persistent `git cat-file --batch` workers.
7. Add allowlist and baseline files for accepted findings.

## Accuracy Rules

- Prefer provider-specific token structure over generic entropy.
- Require keywords when token formats are ambiguous.
- Redact output by default.
- Keep verification opt-in because it contacts external services.
- Avoid matching obvious examples, placeholders, all-zero values, and test fixtures where possible.
