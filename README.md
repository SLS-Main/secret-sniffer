# secret-sniffer

High-concurrency GitHub, S3, and filesystem secret scanner written in Go.

`secret-sniffer` is designed around provider-specific detectors, keyword prefilters, format validation, deduplication, optional verification, and remediation-focused raw-secret output by default. It is intended for large servers with many CPU cores and enough memory to scan large repositories aggressively.

Detector keywords are indexed once per scanner so only relevant detectors run for each blob. Git history uses a streaming change list, batched object reads, and blob-analysis caching while preserving distinct commit/path findings. JSONL output is written through a bounded single-writer queue so repository workers do not block on encoding or `fsync` under shared scan-state locks.

During scans, likely base64 and base64url substrings are decoded and scanned with the same detector registry. Decoded findings are reported against the source file and source line/column of the encoded blob while preserving the decoded secret value for remediation.

Local directory scans also inspect common document formats that may contain pasted credentials, including PDF, Word `.docx` and legacy `.doc`, Excel `.xlsx` and legacy `.xls`, PowerPoint `.pptx` and legacy `.ppt`, OpenDocument `.odt`/`.ods`/`.odp`, and RTF files. Point `--target` at a folder and the scanner recursively scans supported documents inside it along with normal source and text files.

Archive scanning is available with `--scan-archives` for `.zip`, `.tar`, `.tar.gz`, `.tgz`, and single-file `.gz`. Archive contents are expanded in memory with safety limits, never written to disk, and findings are reported with virtual paths such as `backup.zip!/config/.env`.

This project does not use TruffleHog's discovery algorithm. The scanner is detector-first and is being built toward TruffleHog feature parity through an explicit parity map. Current tracked parity covers 875 mappings, including 807 implemented mappings from the pinned detector catalog snapshot.

## Build

Go 1.24 or newer is required.

```bash
go build -o secret-sniffer ./cmd/secret-sniffer
```

Verify the binary:

```bash
./secret-sniffer --version
./secret-sniffer --list-detectors
```

## Quick Start

Scan the current directory:

```bash
./secret-sniffer --target .
```

Scan a local repository with JSON output:

```bash
./secret-sniffer --target /path/to/repo --format json
```

Scan a local folder containing documents such as PDFs and Word files:

```bash
./secret-sniffer --target /path/to/documents --format jsonl --output document-findings.jsonl
```

Scan a GitHub repository URL:

```bash
./secret-sniffer --target https://github.com/OWNER/REPO --workers 24 --format json
```

Scan changed file versions from git history:

```bash
./secret-sniffer --target https://github.com/OWNER/REPO --git-history --workers 32 --format jsonl > findings.jsonl
```

Scan every repository in a GitHub organization:

```bash
GITHUB_TOKEN='ghs_or_pat_here' ./secret-sniffer --github-org ORG --git-history --workers 32 --format jsonl > org.findings.jsonl
```

Scan every repository accessible to a GitHub App installation token or PAT:

```bash
GITHUB_TOKEN='ghs_or_pat_here' ./secret-sniffer --github-accessible --git-history --workers 32 --format jsonl > accessible.findings.jsonl
```

Scan repositories listed in a text file:

```bash
./secret-sniffer --repo-list repos.txt --git-history --repo-concurrency 4 --workers 12 --format jsonl --output findings.jsonl
```

Scan several S3 buckets concurrently without downloading excluded file types:

```bash
./secret-sniffer \
  --s3-buckets app-config,backups,artifacts \
  --s3-bucket-concurrency 3 \
  --s3-object-concurrency 16 \
  --exclude-extensions png,jpg,jpeg,gif,mp4 \
  --format jsonl \
  --output s3-findings.jsonl
```

## Common Options

```text
--target              Local file, local directory, or GitHub repo URL. Default: .
--workers             Concurrent scanner workers. Default: runtime CPU count.
--max-file-bytes      Maximum file/blob size to scan. Default: 26214400.
--scan-archives       Scan supported archives in memory: zip, tar, tar.gz, tgz, gz.
--max-archive-depth   Maximum nested archive depth. Default: 2.
--max-archive-entries Maximum entries to inspect per archive. Default: 10000.
--max-archive-bytes   Maximum expanded bytes to inspect per archive. Default: 262144000.
--max-expanded-file-bytes  Maximum decompressed archive entry size to scan. Default: 26214400.
--git-history         Scan added/modified file versions from git history in addition to the worktree.
--verify              Attempt live provider verification for supported detectors.
--format              Output format: human, json, jsonl, sarif.
--output              Write findings to this file. JSONL streams during scanning.
--output-flush-findings  Fsync streamed output after this many findings. Default: 25.
--repo-concurrency    Number of repositories to scan concurrently for repo-list and GitHub org/enterprise/access scans.
--repo-list           Text file containing repository targets to scan, one per line.
--include             Comma-separated glob patterns to include.
--exclude             Comma-separated glob patterns to exclude.
--exclude-extensions  Comma-separated file extensions to skip before reading/downloading.
--custom-detectors    Path to custom detector JSON.
--baseline            Path to accepted-finding baseline JSON.
--write-baseline      Write current finding fingerprints to baseline JSON.
--summary-output      Write GitHub discovery and scan summary JSON to this path.
--scan-job-id         Persist per-repository scan state under this job ID. Generated automatically when omitted.
--scan-job-path       Path to scan job state JSON. Default: .secret-sniffer-jobs/<job-id>.json.
--scan-resume         With --scan-job-id, skip repositories already completed in the job state.
--scan-retry-failed   With --scan-job-id, scan only repositories marked failed in the job state.
--summary-only        Discover GitHub orgs/repositories, write summary, and exit without scanning.
--github-org          Comma-separated GitHub organization names to enumerate and scan.
--github-enterprise   GitHub Enterprise Cloud slug; enumerate orgs and scan all repos.
--github-accessible   Scan all repositories accessible to the GitHub token.
--github-token        GitHub token for API enumeration and private clones. Defaults to GITHUB_TOKEN.
--github-app-id       GitHub App ID for minting installation tokens. Defaults to GITHUB_APP_ID.
--github-app-private-key  Path to GitHub App private key PEM. Defaults to GITHUB_APP_PRIVATE_KEY.
--github-installation-id  Optional GitHub App installation ID. Defaults to GITHUB_INSTALLATION_ID.
--fail-on-findings    Exit with status 2 when findings remain after baseline filtering.
--redact              Omit raw secrets from machine-readable output.
--no-redact           Include raw secrets in output. Default: true.
--quiet               Suppress progress logs on stderr.
--no-color            Disable colored console output.
--list-detectors      Print built-in detector metadata as JSON.
--trufflehog-parity   Print tracked TruffleHog detector parity mappings as JSON.
--s3-buckets          Comma-separated S3 bucket names to scan concurrently.
--s3-all-buckets      Discover and scan all buckets owned by the authenticated AWS account.
--s3-prefix           Only scan objects under this key prefix.
--s3-bucket-concurrency  Number of buckets to scan concurrently. Default: 4.
--s3-object-concurrency  Concurrent object downloads/scans per bucket. Default: --workers.
--s3-job-id           Stable S3 job ID used to validate resumable state.
--s3-state            S3 checkpoint file. Default: .secret-sniffer-jobs/<job-id>-s3.json.
--s3-resume           Resume incomplete buckets from durable page checkpoints.
--aws-profile         AWS shared config/credentials profile. Defaults to AWS_PROFILE.
--aws-region          AWS region. Defaults to AWS_REGION/profile, then us-east-1.
--aws-access-key-id   Explicit access key ID (environment/profile credentials preferred).
--aws-secret-access-key  Explicit secret access key.
--aws-session-token   Session token for temporary explicit AWS credentials.
--aws-sso-device-auth Start IAM Identity Center device authorization for --aws-profile.
--progress-state      Write atomic machine-readable scan progress to this path.
--progress-interval   Active-item snapshot interval. Default: 500ms.
```

## Machine-Readable Progress

Use `--progress-state` when an orchestrator or UI needs stable progress without parsing console output. No progress file is written unless the flag is supplied. `--progress-interval` controls publication of active worker changes and defaults to `500ms`:

```bash
./secret-sniffer \
  --s3-buckets tools-prod-us-west-2 \
  --progress-state run/progress.json \
  --progress-interval 500ms \
  --format jsonl
```

The schema is versioned and includes a monotonically increasing sequence, source and target metadata, aggregate counters, one entry per active worker slot, and the most recently completed item. S3 entries include bucket, object path, download bytes, and download/scan stage. Filesystem entries include the active path, archive entries include the outer path plus entry/depth, and Git-history entries include path and commit.

Stable phases are `initializing`, `discovering`, `listing`, `cloning`, `scanning_worktree`, `scanning_history`, `downloading`, `extracting`, `scanning`, `finalizing`, `completed`, `failed`, and `cancelled`. Stable item stages are `queued`, `downloading`, `downloaded`, `extracting`, `scanning`, `completed`, `skipped`, and `failed`.

Snapshots use a mode-`0600` temporary file, file and directory `fsync`, and atomic rename. The initial snapshot is written synchronously, so an invalid or unwritable configured path fails startup. Later writes run behind a bounded coalescing notification channel; slow or failed storage cannot block scanner workers, and later write failures produce warnings. The terminal `completed`, `failed`, or `cancelled` snapshot is left in place.

Progress files never contain finding secrets, credentials, authorization headers, signed URL query strings, AWS continuation tokens, or output payloads. Paths are included intentionally for operational visibility.

## S3 Scanning

S3 scans parallelize at two levels: multiple bucket workers run simultaneously, and each bucket has its own pool of object download/scanner workers. Bucket regions are resolved concurrently before scanning, so one job can scan buckets spread across AWS regions. Objects larger than `--max-file-bytes`, objects rejected by `--include` or `--exclude`, and objects whose extension appears in `--exclude-extensions` are skipped from listing metadata before `GetObject` is called. Extension matching is case-insensitive.

Scan every bucket owned by the authenticated account:

```bash
./secret-sniffer \
  --s3-all-buckets \
  --s3-bucket-concurrency 8 \
  --s3-object-concurrency 12 \
  --exclude-extensions png,jpg,jpeg,gif,webp,mp4,zip \
  --format jsonl \
  --output s3-findings.jsonl
```

Limit a scan to a prefix:

```bash
./secret-sniffer --s3-buckets production-config --s3-prefix releases/2026/ --format jsonl
```

### AWS Authentication

The normal AWS SDK credential chain is supported. This includes `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for long-term keys; `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` for temporary credentials; shared credentials/config profiles; ECS and EC2 role credentials; web identity; and credential processes.

Long-term or temporary environment credentials:

```bash
export AWS_ACCESS_KEY_ID='...'
export AWS_SECRET_ACCESS_KEY='...'
# Set this as well for temporary STS credentials:
export AWS_SESSION_TOKEN='...'

./secret-sniffer --s3-buckets bucket-one,bucket-two --aws-region us-east-1 --format jsonl
```

Shared profile credentials, including an already authenticated IAM Identity Center profile:

```bash
./secret-sniffer --aws-profile security-audit --s3-all-buckets --format jsonl
```

To perform IAM Identity Center device authentication directly in the scanner, select an SSO profile and enable the device flow. The scanner prints the AWS verification URL and one-time code, polls until authorization completes, obtains temporary role credentials, and refreshes them during a long scan while the SSO refresh token remains valid:

```bash
./secret-sniffer \
  --aws-profile security-audit \
  --aws-sso-device-auth \
  --s3-all-buckets \
  --format jsonl \
  --output s3-findings.jsonl
```

The profile may use current `sso_session` configuration or legacy inline SSO fields. It must resolve `sso_start_url`, `sso_region`, `sso_account_id`, and `sso_role_name`.

Explicit credential flags are available for controlled automation, including `--aws-session-token` for temporary credentials. Environment variables or protected profile files are safer because command-line secrets can be visible in process listings.

### S3 Resume And Reliability

Each S3 job writes an atomic JSON state file after a bucket starts and after every fully processed `ListObjectsV2` page. State records each bucket as `pending`, `running`, `completed`, or `failed`, together with attempts, the last committed continuation token, scanned/skipped object counts, findings, timestamps, and errors. State writes fsync the replacement file and its directory. A process lock prevents two scanner processes from mutating the same job state and journal concurrently. For non-JSONL formats, a permission-restricted JSONL finding journal is retained beside the state file, allowing resumed or repeated completed runs to reconstruct output without retaining all findings in memory.

Use a stable job ID for a scan that may need to resume:

```bash
./secret-sniffer \
  --s3-all-buckets \
  --s3-job-id quarterly-s3-audit \
  --format jsonl \
  --output s3-findings.jsonl
```

After interruption, repeat the same scan configuration and add `--s3-resume`:

```bash
./secret-sniffer \
  --s3-all-buckets \
  --s3-job-id quarterly-s3-audit \
  --s3-resume \
  --format jsonl \
  --output s3-findings.jsonl
```

Completed buckets are skipped. Running or failed buckets continue from their last committed page. Resumed JSONL output always appends because overwriting or switching files would omit findings from pages that the checkpoint correctly skips; JSON, SARIF, and human output are reconstructed from the durable finding journal. A page checkpoint is committed only after every object in the page has either been scanned or intentionally excluded and all page findings have been flushed to output. Object reads use the ETag returned by the listing as an `If-Match` condition, so an object changed between listing and download fails the page and is retried rather than being silently scanned as a different version.

This ordering provides at-least-once recovery: interruption cannot cause a checkpoint to skip findings that were not durably flushed. Before resume, an incomplete trailing journal record is removed so its uncheckpointed page can be replayed cleanly. If termination occurs after findings are flushed but before the corresponding state checkpoint is renamed, that final page is scanned again and its findings can be duplicated when appending JSONL output. The state file is bound to a hash of the exact bucket set/discovery mode, output format/journal path, prefix, size/archive limits, path filters, excluded extensions, verification/redaction settings, baseline contents, and detector configuration; resume is rejected if those accuracy-affecting options change or if a progressed job's journal is missing.

## Output Formats

Progress logs are written to stderr by default. Human output prints to stdout. Machine-readable formats write to files automatically when `--output` is not provided:

- `--format json` writes `secret-sniffer-findings.json`.
- `--format jsonl` writes `secret-sniffer-findings.jsonl`.
- `--format sarif` writes `secret-sniffer-findings.sarif`.

Use `--output` to choose a different path. Use `--quiet` to suppress progress logs.

Findings are also printed to stderr as they are discovered. For long scans, use `--output` so findings are streamed to disk incrementally instead of waiting for the full scan to finish:

```bash
./secret-sniffer \
  --github-accessible \
  --git-history \
  --workers 32 \
  --output findings.jsonl \
  --output-flush-findings 25 \
  --format jsonl
```

When `--format jsonl` is used, findings are streamed to the output file and stdout receives only the final completion line. This prevents large multi-repository scans from retaining every finding in memory just to render final output.

The scanner suppresses recognized variable and placeholder expressions in ambiguous assignment/context detectors, including common shell, CI, environment accessor, Vault, encrypted-value, and member-reference forms. Exact-format provider tokens remain governed by their provider-specific detector patterns.

## Resuming Large Scans

Every normal scan gets a scan job ID, even when `--scan-job-id` is omitted. Generated IDs include the scan scope plus random digits, such as `org-acme-12345678` or `enterprise-prod-12345678`. The scanner writes per-repository progress to `.secret-sniffer-jobs/<job-id>.json` after every repo starts, completes, or fails.

The generated job ID and state file path are printed in the progress logs. Keep that ID if you may need to resume the scan later. On resume or retry, the logs show the discovered repo count, already-completed count, and selected repo count so it is clear how much prior work is being reused.

```bash
./secret-sniffer \
  --github-org ORG \
  --git-history \
  --repo-concurrency 4 \
  --workers 32 \
  --format jsonl \
  --output org.findings.jsonl
```

If the proxy or network fails during a long run, fix the proxy and resume unfinished repositories:

```bash
./secret-sniffer \
  --github-org ORG \
  --git-history \
  --repo-concurrency 4 \
  --workers 32 \
  --format jsonl \
  --output org.findings.jsonl \
  --scan-job-id org-nightly \
  --scan-resume
```

To retry only repositories that failed in the previous run:

```bash
./secret-sniffer \
  --github-org ORG \
  --git-history \
  --repo-concurrency 4 \
  --workers 32 \
  --format jsonl \
  --output org.findings.jsonl \
  --scan-job-id org-nightly \
  --scan-retry-failed
```

When resuming or retrying and the output file already exists, interactive runs prompt whether to append, overwrite, or create a timestamped new output file. Append is the default, and non-interactive runs default to append so automation does not block. Use the same discovery flags with the same job ID so the scanner can match discovered repositories to the saved job state.

Human output:

```bash
./secret-sniffer --target . --format human
```

JSON output:

```bash
./secret-sniffer --target . --format json > findings.json
```

JSONL output for large scans:

```bash
./secret-sniffer --target . --format jsonl > findings.jsonl
```

SARIF output for code scanning integrations:

```bash
./secret-sniffer --target . --format sarif > findings.sarif
```

Machine-readable output includes raw secrets by default because this tool is intended for remediation. The `secret` and `redacted` fields are both populated.

Use `--redact` when raw secrets should be omitted:

```bash
./secret-sniffer --target . --format json --redact > redacted-findings.json
```

Store raw output with restrictive permissions:

```bash
chmod 600 findings.json findings.jsonl 2>/dev/null || true
```

## Archive Scanning

Archive scanning is opt-in because archives can expand to much more data than their compressed size:

```bash
./secret-sniffer --target /path/to/repo --scan-archives --format jsonl
```

Supported formats use Go's standard library and do not shell out to external extractors:

- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`
- single-file `.gz`

Findings inside archives use virtual paths:

```text
backup.zip!/config/.env
release.tar.gz!/app/settings.yml
outer.zip!/inner.zip!/nested.env
```

Archive contents are expanded in memory only. Entries with absolute paths or `../` traversal are ignored, symlinks and non-regular tar entries are skipped, and decompression is bounded by `--max-archive-depth`, `--max-archive-entries`, `--max-archive-bytes`, and `--max-expanded-file-bytes`.

## Large Server Usage

Use a worker count near the number of CPU cores. For a 24-core server:

```bash
./secret-sniffer --target /data/repo --git-history --workers 24 --format jsonl > findings.jsonl
```

For a 48-core server:

```bash
./secret-sniffer --target /data/repo --git-history --workers 48 --max-file-bytes 52428800 --format jsonl > findings.jsonl
```

Recommended defaults for broad repository scans:

```bash
./secret-sniffer \
  --target /data/repo \
  --git-history \
  --workers 32 \
  --max-file-bytes 52428800 \
  --exclude 'node_modules/*,vendor/*,.cache/*,dist/*,build/*' \
  --format jsonl \
  > findings.jsonl
```

Scan supported archives in the worktree and git history:

```bash
./secret-sniffer \
  --target /data/repo \
  --git-history \
  --scan-archives \
  --max-archive-depth 2 \
  --workers 32 \
  --format jsonl
```

## GitHub App, Organization, And Enterprise Scanning

The scanner can enumerate repositories directly from GitHub and scan them in one run. It supports direct GitHub App authentication with app ID and PEM file, GitHub App installation tokens, and PATs.

### Authentication

Preferred GitHub App usage:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-accessible \
  --git-history \
  --workers 32 \
  --repo-concurrency 4 \
  --format jsonl \
  --output accessible.findings.jsonl
```

If the app has multiple installations and you want one specific installation:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-installation-id 987654321 \
  --github-accessible \
  --git-history \
  --workers 32 \
  --format jsonl \
  > installation.findings.jsonl
```

Environment variable equivalent:

```bash
export GITHUB_APP_ID='123456'
export GITHUB_APP_PRIVATE_KEY='/secure/path/app-private-key.pem'
export GITHUB_INSTALLATION_ID='987654321'

./secret-sniffer --github-accessible --git-history --workers 32 --format jsonl > findings.jsonl
```

PAT or pre-minted installation token usage is also supported. Export it as `GITHUB_TOKEN`:

```bash
export GITHUB_TOKEN='ghs_or_installation_token_here'
```

The scanner mints GitHub App JWTs and installation tokens internally when app credentials are provided. It uses the resulting token for GitHub API enumeration and injects it into private clone URLs internally. You do not need to modify global git config.

For long-running scans, GitHub App installation tokens are cached and reused. The scanner refreshes an installation token only when it is missing an expiration time or is within 10 minutes of expiring.

If you prefer git-level authentication, you can still configure git yourself:

```bash
git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

### Scan One Organization

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-org ORG \
  --git-history \
  --workers 32 \
  --summary-output ORG.summary.json \
  --format jsonl \
  > ORG.findings.jsonl
```

Scan multiple organizations:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-org ORG1,ORG2,ORG3 \
  --git-history \
  --workers 32 \
  --format jsonl \
  > orgs.findings.jsonl
```

### Scan All Accessible Repositories

For a GitHub App installation token, this uses `/installation/repositories`. For a PAT, it falls back to `/user/repos` with owner, collaborator, and organization-member affiliations.

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-accessible \
  --git-history \
  --workers 32 \
  --repo-concurrency 4 \
  --format jsonl \
  --output accessible.findings.jsonl
```

### Scan An Enterprise

For GitHub Enterprise Cloud, provide the enterprise slug. Your token must be allowed to list enterprise organizations and read repositories.

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-enterprise ENTERPRISE_SLUG \
  --git-history \
  --workers 32 \
  --format jsonl \
  > enterprise.findings.jsonl
```

### Scan One Private Repository

```bash
./secret-sniffer \
  --target https://github.com/ORG/REPO \
  --git-history \
  --workers 32 \
  --format jsonl \
  > ORG_REPO.findings.jsonl
```

### Optional Repository Lists With GitHub CLI

If `gh` is authenticated with your GitHub App token or an equivalent token:

```bash
export GH_TOKEN="$GITHUB_TOKEN"
gh repo list ORG --limit 1000 --json nameWithOwner,url --jq '.[].url' > repos.txt
```

For multiple organizations:

```bash
for org in ORG1 ORG2 ORG3; do
  GH_TOKEN="$GITHUB_TOKEN" gh repo list "$org" --limit 1000 --json url --jq '.[].url'
done > repos.txt
```

### Scan Repository List

Use `--repo-list` to scan a text file of repository targets directly. Each non-empty line is treated as a target. Lines beginning with `#` are ignored.

Example `repos.txt`:

```text
# GitHub repositories
https://github.com/ORG/service-api
https://github.com/ORG/web-app.git

# Local repositories are also supported
/data/repos/internal-tool
```

Run the scan:

```bash
./secret-sniffer \
  --repo-list repos.txt \
  --git-history \
  --repo-concurrency 4 \
  --workers 12 \
  --format jsonl \
  --output findings.jsonl
```

Use `--github-token`, `GITHUB_TOKEN`, or GitHub App options when the list contains private GitHub repositories.

For CI-style failure on any unbaselined finding:

```bash
./secret-sniffer \
  --repo-list repos.txt \
  --git-history \
  --repo-concurrency 4 \
  --workers 12 \
  --baseline .secret-sniffer-baseline.json \
  --fail-on-findings \
  --format jsonl
```

### Discovery Summary And Summary-Only Mode

GitHub discovery prints a summary before scanning starts. It includes the enterprise name when provided, requested orgs, discovered org names, GitHub App installations, and repository counts.

For GitHub discovery modes, the scanner writes a discovery summary before scanning starts. If `--summary-output` is not supplied, it writes `secret-sniffer-summary.json`.

Generate only the discovery summary without scanning:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-accessible \
  --summary-only \
  --summary-output github-summary.json
```

### Parallel Organization And Enterprise Scans

Use `--repo-concurrency` to scan multiple repositories at the same time inside one process. Each repository gets `--workers` scanner workers, so choose both values together based on CPU and memory.

Example for a 48-core machine:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-accessible \
  --git-history \
  --repo-concurrency 4 \
  --workers 12 \
  --format jsonl \
  --output findings.jsonl \
  --summary-output github-summary.json
```

This runs 4 repositories at a time with 12 workers per repository.

## Discovery Summary

GitHub org, enterprise, and accessible-repository scans print a discovery summary to stderr showing orgs found and repository counts per org.

Write the same summary to a JSON file with:

```bash
./secret-sniffer \
  --github-app-id 123456 \
  --github-app-private-key /secure/path/app-private-key.pem \
  --github-accessible \
  --summary-output github-summary.json \
  --git-history \
  --format jsonl \
  > findings.jsonl
```

The summary includes:

- Enterprise slug when provided.
- Requested org names.
- Total repositories discovered.
- Per-org repository counts.
- Per-org finding counts after scanning.
- Findings before and after baseline filtering.

## Baselines

Create a baseline from current accepted findings:

```bash
./secret-sniffer --target . --git-history --write-baseline .secret-sniffer-baseline.json
```

Use the baseline to ignore accepted findings and fail on new ones:

```bash
./secret-sniffer \
  --target . \
  --git-history \
  --baseline .secret-sniffer-baseline.json \
  --fail-on-findings
```

Baselines store finding fingerprints, not raw secrets.

## Custom Detectors

Custom detectors are JSON files with one or more regex detector definitions.

Example:

```json
{
  "detectors": [
    {
      "id": "internal-api-key",
      "name": "Internal API Key",
      "severity": "high",
      "keywords": ["internal_api_key", "x-internal-key"],
      "regex": "(?i)(internal_api_key|x-internal-key)\\s*[:=]\\s*['\\\"]?([a-z0-9]{32,64})",
      "secret_group": 2
    }
  ]
}
```

Run with custom detectors:

```bash
./secret-sniffer --target . --custom-detectors examples/custom-detectors.json
```

Fields:

- `id`: Stable detector ID.
- `name`: Human-readable detector name.
- `severity`: `critical`, `high`, `medium`, or `low`.
- `keywords`: Optional prefilter terms. These improve speed and reduce noise.
- `regex`: Go regular expression.
- `secret_group`: Capturing group containing the secret. Use `0` for the whole match.

## Verification

Verification is off by default:

```bash
./secret-sniffer --target . --verify
```

Verification may contact provider APIs with candidate credentials. Only use it when you are authorized to validate discovered credentials.

Currently supported verification hooks include GitHub and OpenAI. More provider verifiers are planned.

## Detector Inventory

List built-in detectors:

```bash
./secret-sniffer --list-detectors > detectors.json
```

Print the tracked TruffleHog parity report:

```bash
./secret-sniffer --trufflehog-parity > parity.json
```

The parity report includes:

- TruffleHog snapshot commit.
- TruffleHog detector-directory identifier catalog size from the pinned snapshot.
- Current tracked mappings.
- Implemented, partial, planned, duplicate, sub-detector, and untracked counts.
- Untracked TruffleHog detector IDs.

The parity report uses TruffleHog detector directory identifiers for compatibility accounting only. It does not include TruffleHog source code, detector regexes, verifier logic, or documentation text.

Detailed parity notes live in `docs/trufflehog-parity.md`, including the tracked SecretSniffer-only detector backlog and explicit differences from TruffleHog.

The implementation roadmap lives in `docs/roadmap.md`.

## CI Examples

Fail a build if findings are present:

```bash
./secret-sniffer --target . --fail-on-findings
```

Fail a build only for new findings after baseline filtering:

```bash
./secret-sniffer \
  --target . \
  --baseline .secret-sniffer-baseline.json \
  --fail-on-findings \
  --format sarif \
  > secret-sniffer.sarif
```

Scan only likely secret-bearing files:

```bash
./secret-sniffer \
  --target . \
  --include '*.env,*.json,*.yaml,*.yml,*.tf,*.go,*.js,*.ts,*.py' \
  --exclude 'node_modules/*,vendor/*,dist/*,build/*' \
  --fail-on-findings
```

## Safety Notes

- Treat scanner output as sensitive, even when redacted.
- Raw secrets are shown by default for remediation.
- Use `--redact` when raw values are not required.
- Store raw outputs with restrictive permissions.
- Rotate any verified or high-confidence credentials before broad disclosure.
- Keep verification disabled unless you are authorized to contact provider APIs.
- Prefer baselines for accepted legacy findings instead of suppressing detectors globally.

## License

This project is licensed under the **Do The Damn Job License 1.0**.

You may use it personally, internally, commercially, in consulting, in incident response, in remediation, in forensics, in managed services, and as a feature inside a broader commercial product.

You may not rebrand and resell it as your own dedicated secret scanner.

See [LICENSE](./LICENSE.md) for details.
