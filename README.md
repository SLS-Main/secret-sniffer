# secret-sniffer

High-concurrency GitHub and filesystem secret scanner written in Go.

`secret-sniffer` is designed around provider-specific detectors, keyword prefilters, format validation, deduplication, optional verification, and remediation-focused raw-secret output by default. It is intended for large servers with many CPU cores and enough memory to scan large repositories aggressively.

During scans, likely base64 and base64url substrings are decoded and scanned with the same detector registry. Decoded findings are reported against the source file and source line/column of the encoded blob while preserving the decoded secret value for remediation.

This project does not use TruffleHog's discovery algorithm. The scanner is detector-first and is being built toward TruffleHog feature parity through an explicit parity map.

## Build

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

Scan a GitHub repository URL:

```bash
./secret-sniffer --target https://github.com/OWNER/REPO --workers 24 --format json
```

Scan full git object history:

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

## Common Options

```text
--target              Local file, local directory, or GitHub repo URL. Default: .
--workers             Concurrent scanner workers. Default: runtime CPU count.
--max-file-bytes      Maximum file/blob size to scan. Default: 26214400.
--git-history         Scan every reachable git blob in addition to the worktree.
--verify              Attempt live provider verification for supported detectors.
--format              Output format: human, json, jsonl, sarif.
--output              Write findings to this file. JSONL streams during scanning.
--output-flush-findings  Fsync streamed output after this many findings. Default: 25.
--repo-concurrency    Number of repositories to scan concurrently for GitHub org/enterprise/access scans.
--include             Comma-separated glob patterns to include.
--exclude             Comma-separated glob patterns to exclude.
--custom-detectors    Path to custom detector JSON.
--baseline            Path to accepted-finding baseline JSON.
--write-baseline      Write current finding fingerprints to baseline JSON.
--summary-output      Write GitHub discovery and scan summary JSON to this path.
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
```

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

```bash
mkdir -p results

while read -r repo; do
  name=$(printf '%s' "$repo" | sed 's#https://github.com/##; s#/#_#g')
  ./secret-sniffer \
    --target "$repo" \
    --git-history \
    --workers 32 \
    --format jsonl \
    > "results/${name}.jsonl"
done < repos.txt
```

For CI-style failure on any unbaselined finding:

```bash
while read -r repo; do
  ./secret-sniffer \
    --target "$repo" \
    --git-history \
    --workers 32 \
    --baseline .secret-sniffer-baseline.json \
    --fail-on-findings \
    --format jsonl
done < repos.txt
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

Detailed parity notes live in `docs/trufflehog-parity.md`.

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
