# Remaining verifier blockers

Inventory after batch 35, reviewed 2026-09-28. This is an engineering backlog,
not an additional CLI audit mode. Provider evidence and completed remediation
history are in [verifier-hardening.md](verifier-hardening.md).

There are **16 blocked patterns** and **zero pending-review or actionable
hardening entries** in the current audit. All 16 retain detection and return
`unknown` without requests when unreviewed verification is explicitly enabled.
Ordinary `--verify` skips them. The inventory-wide regression is
`TestBlockedInventoryMakesNoRequestsEvenWithOptIn`.

## Next ten-provider evidence review

These ten are the next review set. They are not ten ready-to-implement contracts;
promotion depends on resolving the requirements below. Preserve no-network
behavior until the required evidence is established.

| Detector | Requirement before implementing a supported verifier |
| --- | --- |
| `wit-ai-token` | Obtain the provider's versioned app-list or identity schema and establish which server/client token families may call it. Rendered documentation or a provider-maintained specification/SDK must establish authentication and success semantics; a client-rendered documentation shell is not evidence that no API exists. |
| `autopilot-api-key` | Recover a current provider-owned account contract through its documented API portal; establish the legacy product/key family and supported base. Do not infer compatibility with a successor marketing product or accept an arbitrary object containing id. |
| `upwave-api-key` | Obtain current authenticated workspace/identity documentation, including a typed success schema and supported pagination. Credential-free 403 establishes rejection only; it cannot establish a success contract. |
| `cloverly-api-key` | Find an authenticated, non-workload metadata or introspection operation with a documented success schema and applicable key family. Public catalog access, estimates and purchase operations are not substitutes. |
| `cloudplan-api-key` | Establish V2 credential-family and authentication-mode routing. Default AWS4-HMAC needs a correlated API key/secret pair; header mode must be explicitly enabled in the provider portal. New endpoint documentation alone does not establish compatibility with the existing legacy single-key detector. Modern credential-family implementation remains deferred. |
| `google-api-key` | Identify product/API, application restrictions and a documented non-workload operation for that exact context. Generic Google API keys cannot use Gemini model listing as universal introspection. No product guessing or cross-service retries. |
| `abstract-api-key` | Capture the exact product and establish a non-workload validation operation for its product-specific key. Current evidence indicates separate keys and credit-consuming lookups; key presence or a product URL does not establish a safe contract. |
| `apilayer-key` | Establish marketplace product/subscription context and a documented authenticated operation that does not perform the subscribed workload. One product's countries endpoint cannot validate every marketplace key. |
| `cryptocompare-api-key` | Obtain explicit legacy-key compatibility evidence for current CoinDesk infrastructure and a non-workload identity/metadata schema. Do not forward credentials solely because a documentation URL directs to a successor service. |
| `currencyscoop-api-key` | Obtain explicit CurrencyScoop-to-CurrencyBeacon key compatibility evidence and a suitable authenticated contract. Documentation redirects and a public currency catalog do not establish credential validity. |

## Other six blocked patterns

| Detector | Requirement or disposition |
| --- | --- |
| `configcat-sdk-key` | A supported SDK-key validation contract must account for deployment/CDN context and plan allowances. Management API Basic key/secret pairs are a distinct family; implementing them would not unblock the SDK-key detector. |
| `greenhouse-harvest-api-key` | Legacy Basic keys cannot be treated as Harvest v3 OAuth credentials. Provider announced v1/v2 removal on 2026-08-31. V3 OAuth family support is deferred and must be implemented distinctly if resumed. |
| `mailjetsms-api-token` | Obtain current legacy SMS Bearer-token validation documentation or explicit migration compatibility. Current Mailjet email API Basic credential pairs do not verify these tokens. |
| `cloudflare-ca-key` | Origin CA service keys are scheduled for removal on 2026-09-30. Retain detection and unknown status; replacement API tokens are a separate family. Retirement does not justify declaring every detected value invalid. |
| `pivotaltracker-api-token` | Establish a current provider-owned service and verification contract before any network probe. DNS/service availability is not credential evidence. |
| `interseller-api-key` | A documented bounded authenticated schema would be required even before the announced 2026-12-15 sunset. Existing subscriptions may remain functional until then; sunset timing does not establish credential validity. |

## Implementation criteria when evidence becomes available

- Record provider-owned operation, authentication, credential family, supported
  deployment, success schema, permission errors and pagination semantics.
- Correlate required context within the same structured mapping or bounded
  configuration record. Include it in cache identity. Missing, conflicting or
  unsupported context must prevent requests.
- Prefer dedicated authentication checks, sparse identity fields or a single
  metadata page. Do not follow redirects or response-supplied links.
- Keep permission, subtype, region, throttling and provider failures `unknown`.
  Suppress response content and enforce the shared 1 MiB response cap.
- Add mocked request/schema/error regressions before promotion. Provider
  documentation and mocks establish the implemented contract, not live-key
  reliability or exhaustive credential coverage.

## Deferred work

Controlled live reliability/accuracy benchmarks, broader modern credential
formats and a refreshed provider-level TruffleHog comparison remain deferred.
The 535 detection-only patterns and the directional TruffleHog difference of
296 are not automatically actionable verification backlogs.

Examples of deferred family coverage already identified: JumpCloud `jca_`,
Phrase Platform JWT, Adobe IMS, Pagar.me V5 `sk_`, Cliengo JWT, Greenhouse Harvest
v3 OAuth and Cloudplan V2 authentication-mode support. Expanding these requires
separate detection, correlation and contract work rather than weakening an
existing verifier's success classification.
