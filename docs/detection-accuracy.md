# Detection accuracy

Generic Assigned Secret detection uses scalar extraction after a sensitive field
name. Valid JSON and YAML documents use structured parsing, with text extraction
as a fallback for env/INI assignments and source fragments. JSON escapes,
including Unicode surrogate pairs and escaped field names, are decoded. YAML
literal/folded blocks, indentation indicators, chomping, multiline quotes, and
single-quote escaping use YAML scalar semantics. Numeric password scalars retain
their original spelling rather than passing through floating-point conversion.

Findings contain the decoded credential value and the original source location.
Quoted spans exclude their delimiters; block spans begin at the `|` or `>`
indicator. Unicode parser columns are translated into byte offsets. Scalar
aliases resolve to the literal at its anchor; container aliases are not expanded.
Assignment whitespace in the fallback cannot consume a newline and mistake a
YAML child key for its parent's value.

## Reducing noise

- Unquoted function calls and recognized member/variable references are excluded.
- Mounted-secret paths and explicit Vault, 1Password, AWS Secrets Manager, and
  Google Secret Manager references are excluded from generic detection.
- Explicit instructional placeholders are excluded using a small exact-match
  list. Words such as `secret`, `password`, or `test` are not blanket exclusions.
- Versioned resource names are excluded under explicit JSON/YAML reference containers
  (`secretRef`, `secretKeyRef`, `remoteRef`, `externalSecretRef`). Without that
  context, ambiguous slugs remain possible passwords. Existing narrowly targeted
  resource-name heuristics also remain active.
- Broad contextual provider rules respect blank lines, YAML document markers,
  INI section changes, recognized sibling-object boundaries, and dedents out of
  YAML provider containers. They reject token prefixes followed by continuation
  characters instead of reporting truncated credentials.
- Legacy Google OAuth client secrets require nearby Google context; modern
  `GOCSPX-` credentials have an identifying signature. A generic `client_secret`
  field alone does not establish Google attribution.
- An exact generic/provider overlap produces the provider finding. Consolidation
  uses the value and byte span in the same content view before verification and
  fingerprint deduplication. Base64 views use their decoded spans before source
  location remapping, preserving decoder provenance.

## Provider detection after structured decoding

Provider rules also run against decoded JSON/YAML scalar values. Each mapping
gets a separate detection view containing its own fields and ancestor keys.
Explicit `provider` and `service` selectors contribute local context regardless
of field order. Adjacent mappings, array entries, and YAML documents are not
combined into a decoded credential record.

This supports escaped provider signatures, escaped field/provider names, YAML
block values, and multipart credentials stored together in one mapping. Verifiers
receive decoded credential values and parts through the existing verification
policy. Literal newlines inside a value are not removed to assemble a token;
trailing block line breaks can delimit a provider token as in ordinary source.

Decoded findings map back to the original scalar span. Their decoder provenance
records `json` or `yaml`, following `base64` when decoding a Base64-wrapped
document. Raw token prefixes from transformed records are replaced by detection
on decoded values. Equivalent generic findings, including a block scalar with a
trailing newline, are consolidated with the provider finding.

No blanket entropy threshold is used: low-entropy passwords and readable
passphrases are valid findings. Verification status remains separate from these
local detection decisions.

Source-code fragments still use conservative text-scanning rules rather than a
full language parser. Language-specific escaping and arbitrary expression syntax
remain areas for additional format-specific extraction work.

## Regression corpus

`internal/scanner/testdata/accuracy.json` contains only synthetic values. Each
fixture declares the exact expected detector IDs and complete extracted values.
`TestAccuracyCorpus` exercises every case as plain text and Base64 content with
verification disabled. Unexpected findings, missed findings, incorrect
attribution/extraction, duplicates, and lost decoder provenance fail the test.

Add both a benign example and a plausible-secret counterexample when extending
a suppression rule. Detector tests additionally cover byte offsets, token
boundaries, provider-context isolation, and modern Google signatures. Scanner
tests verify that consolidation preserves separate occurrences.

Run the focused checks with:

```sh
go test ./internal/detectors ./internal/scanner
```

This corpus is a regression baseline, not a measured real-world precision or
recall estimate.
