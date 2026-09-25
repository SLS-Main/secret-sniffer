# Verifier hardening

Detection finds a credential-shaped value. Verification makes a provider request
to establish whether that credential authenticates. A verifier must distinguish
an invalid key from insufficient permissions, wrong region, wrong credential
subtype, rate limiting, and provider failure.

## What a hardening batch includes

1. Check current provider documentation for the endpoint, authentication scheme,
   required context, response schema, and failure semantics.
2. Choose a read-only or authentication-only operation. A public endpoint does
   not prove a supplied key works. Avoid generation, uploads, messages, or other
   mutations unless a verifier is explicitly classified as unsafe.
3. Validate the success response. A generic HTTP 200, login page, unrelated JSON,
   or public model list is insufficient evidence.
4. Report `unverified` only for a proven credential rejection. Permissions,
   missing context, throttling, transport problems, and ambiguous responses stay
   `unknown`.
5. Suppress response bodies so account identities, balances, infrastructure
   metadata, and additional secrets are not copied into findings.
6. Test request contracts, valid and malformed successes, authentication and
   permission errors, redirects, throttling, outages, and transport failures.
7. Update the internal audit assessment, safety category, regression totals, and
   documentation. Then run repository validation.

Batches are grouped by engineering requirements, not an arbitrary number of
providers. Region/subtype work is usually more involved than repairing a known
endpoint and its response classifier. Mocked tests exercise the contracts without
using live customer credentials.

## Current backlog

After remediation batch 10:

| Internal audit status | Patterns | Meaning |
| --- | ---: | --- |
| Reviewed | 323 | The recorded verifier contract has been reviewed/hardened. |
| Requires hardening | 188 | A verifier exists, with concrete contract work remaining. |
| Blocked | 56 | Required context or a reliable validation contract is unresolved. |
| Pending review | 0 | The systematic safety assessment is complete. |
| No verifier | 535 | Detection exists without an online verifier. |

These audit statuses are distinct from runtime safety categories: 154
`read_only`, 70 `auth_only`, 99 `unsafe`, and 244 `unreviewed`. Ordinary `--verify`
permits only `read_only` and `auth_only`; unsafe and unreviewed hooks require their
existing explicit opt-ins. The audit remains an internal engineering inventory.

## Remediation batch 10: Runpod and Novita

### Runpod

- Replaced `https://api.runpod.io/v2/pods` with the documented authenticated
  `GET https://rest.runpod.io/v1/pods` using bearer authentication.
- Accepts HTTP 200 with a JSON pod array. An empty array is valid; populated
  entries must have a nonempty string ID and a documented desired status.
- Account and pod metadata, including environment variables, are suppressed.
- Unproven authentication/permission failures remain unknown.
- Classified as `read_only` and marked reviewed.

The endpoint does not document pagination. The verifier makes one request,
disables redirects through the shared transport, and uses the existing 1 MiB
response-read limit. An incomplete or unrecognized collection remains unknown.

Source checked 2026-09-25:
[Runpod List Pods](https://docs.runpod.io/api-reference/pods/GET/pods).

### Novita

- Replaced the public model-list probe with authenticated
  `GET https://api.novita.ai/openapi/v1/billing/balance/detail`.
- Accepts HTTP 200 with numeric-string `availableBalance` and `cashBalance`.
  Documented optional balance fields must also be numeric strings when present.
  Missing required verification evidence remains unknown, even though the
  provider documentation labels response fields optional.
- Zero and negative balances can still establish authenticated access. Balance
  amounts are not exposed in verification output.
- Inference errors such as `ACCESS_DENY` and `NOT_ENOUGH_BALANCE` no longer count
  as proof of successful billing authentication. Unproven billing rejections
  remain unknown.
- Classified as `read_only` and marked reviewed.

Sources checked 2026-09-25:
[balance endpoint](https://novita.ai/docs/api-reference/basic-get-user-balance.md),
[authentication](https://novita.ai/docs/api-reference/basic-authentication.md),
and [error-code families](https://novita.ai/docs/api-reference/basic-error-code.md).

## Recommended following batches

1. **Identity/collection contracts:** Typeform, AI21, Intercom, LaunchDarkly.
   Confirm current documentation, validate identity/list schemas, suppress
   metadata, and classify structured failures conservatively.
2. **Credential-subtype routing:** PagerDuty, Buildkite, Postmark. Different
   key families require different verification operations; a rejection by the
   wrong API must not label the key invalid.
3. **Region and endpoint context:** Honeycomb, Opsgenie, Grafana, Zoho, PostHog.
   Correlate endpoint context and use only documented bounded fallbacks. Preserve
   unknown results when the necessary region or self-hosted URL is missing.

Detection accuracy also needs continued evaluation on representative, labeled
scan results. The synthetic corpus catches regressions but does not establish a
real-world false-positive rate.
