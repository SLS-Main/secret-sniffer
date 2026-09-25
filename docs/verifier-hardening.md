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

After remediation batch 11:

| Internal audit status | Patterns | Meaning |
| --- | ---: | --- |
| Reviewed | 334 | The recorded verifier contract has been reviewed/hardened. |
| Requires hardening | 177 | A verifier exists, with concrete contract work remaining. |
| Blocked | 56 | Required context or a reliable validation contract is unresolved. |
| Pending review | 0 | The systematic safety assessment is complete. |
| No verifier | 535 | Detection exists without an online verifier. |

These audit statuses are distinct from runtime safety categories: 164
`read_only`, 71 `auth_only`, 99 `unsafe`, and 233 `unreviewed`. Ordinary `--verify`
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

1. **Identity/collection contracts:** Typeform, AI21, Zilliz, Harness, OpenPhone,
   Sourcegraph, Weights & Biases, and regional content-management APIs.
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

## Remediation batch 11: eleven identity and account contracts

All eleven contracts require HTTP 200 and an explicit response schema, reject
error envelopes even when accompanied by identity-looking fields, and suppress
response bodies on success and failure. Unproven authorization failures remain
unknown. The ten read-only probes and Webflow authentication-only probe are now
eligible for ordinary verification.

| Provider | Endpoint / required evidence | Important behavior |
| --- | --- | --- |
| Intercom | `/me`: `type=admin`, nonempty string `id` | Version 2.16; up to three fixed deployments. Error-message substrings no longer label a token invalid. |
| LaunchDarkly | `/api/v2/caller-identity`: `accountId`, `authKind` | Existing fixed deployment allowlist; SDK keys remain unsupported without requests. |
| monday.com | GraphQL `query { me { id } }`: `data.me.id` | No mutations; wrong identity paths, null identities and GraphQL errors stay unknown. |
| Atlassian | `/admin/v1/orgs`: `data` array with `id` and `type=orgs` | One page only; unsupported token subtypes/permissions stay unknown. |
| Dialpad | `/api/v2/company`: `id`, `name` | String or numeric IDs; production/sandbox admin-key ambiguity preserved. |
| Clockify | `/api/v1/user`: string `id`, `email` | Global endpoint only; region/subdomain failures stay unknown. |
| Baremetrics | `/v1/account`: nested `account.id`, `account.company` | Account/financial metadata suppressed. |
| Webflow | `/v2/token/introspect`: `authorization.id`, `grantType`, `application.id` | Replaces authorized-user lookup and its blanket forbidden-response success; site tokens unsupported by introspection remain unknown. |
| Vultr | `/v2/account`: nested account `name`, `email` | ACL and IP restrictions stay unknown. |
| Eventbrite | `/v3/users/me/`: `id`, `name` | User profile metadata suppressed. |
| Paystack | `/balance`: `status=true`, typed currency/balance array | Empty collections and zero balances are valid; financial data suppressed. |

Regional fallback for Intercom, LaunchDarkly and Dialpad is now attempted only
after authorization ambiguity (401/403). It stops after success, throttling,
provider failure, malformed responses, redirects, or transport errors, and
respects cancellation. No arbitrary URL from a response is followed.

Contract tests cover every provider's exact request, runtime safety promotion,
malformed/null/wrong-type and contradictory responses, status-code handling,
bounded fallback order, transport/read failures, response suppression, and
LaunchDarkly's SDK no-request behavior. They use mocked HTTP responses.

Sources consulted 2026-09-25 (official API references or official SDKs):

- [Intercom current admin](https://developers.intercom.com/docs/references/rest-api/api.intercom.io/admins/identifyadmin.md)
- [LaunchDarkly caller identity](https://launchdarkly.com/docs/api/other/get-caller-identity.md)
- [monday.com me](https://developer.monday.com/api-reference/reference/me)
- [Atlassian organizations](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-orgs/)
- [Dialpad company](https://developers.dialpad.com/reference/companyget)
- [Clockify current user, regions and authentication](https://docs.clockify.me/)
- [Baremetrics account](https://developers.baremetrics.com/reference/get-account)
- [Webflow introspection](https://developers.webflow.com/data/reference/token/introspect)
- [Vultr official SDK account schema](https://github.com/vultr/govultr/blob/master/account.go)
- [Eventbrite official SDK current-user example](https://github.com/eventbrite/eventbrite-sdk-python/blob/master/README.rst)
- [Paystack balance](https://paystack.com/docs/api/transfer-control/#balance)
