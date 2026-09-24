# Detection accuracy

Generic Assigned Secret detection uses scalar extraction after a sensitive field
name. It accepts quoted JSON keys, env/INI/YAML assignments, and quoted source
literals. It preserves punctuation and spaces inside quoted values and reports
the value's byte location. Assignment whitespace cannot consume a newline and
mistake a YAML child key for its parent's value.

## Reducing noise

- Unquoted function calls and recognized member/variable references are excluded.
- Mounted-secret paths and explicit Vault, 1Password, AWS Secrets Manager, and
  Google Secret Manager references are excluded from generic detection.
- Explicit instructional placeholders are excluded using a small exact-match
  list. Words such as `secret`, `password`, or `test` are not blanket exclusions.
- Versioned resource names are excluded under explicit YAML reference containers
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

No blanket entropy threshold is used: low-entropy passwords and readable
passphrases are valid findings. Verification status remains separate from these
local detection decisions.

These are conservative text-scanning rules, not a full language parser. Complex
multiline scalars, language-specific escaping, and arbitrary expression syntax
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
