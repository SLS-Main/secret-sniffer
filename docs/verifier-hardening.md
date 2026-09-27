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

Batches from batch 14 onward cover at least ten verifiers, grouped by engineering
requirements. Region/subtype work is usually more involved than repairing a known
endpoint and its response classifier. Mocked tests exercise the contracts without
using live customer credentials.

## Current backlog

After remediation batch 23:

| Internal audit status | Patterns | Meaning |
| --- | ---: | --- |
| Reviewed | 448 | The recorded verifier contract has been reviewed/hardened. |
| Requires hardening | 63 | A verifier exists, with concrete contract work remaining. |
| Blocked | 56 | Required context or a reliable validation contract is unresolved. |
| Pending review | 0 | The systematic safety assessment is complete. |
| No verifier | 535 | Detection exists without an online verifier. |

These audit statuses are distinct from runtime safety categories: 271
`read_only`, 78 `auth_only`, 99 `unsafe`, and 119 `unreviewed`. Ordinary `--verify`
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

1. **Identity/collection contracts:** Harness, Salesforce, CoinAPI,
   API-Sports, and regional content-management APIs.
   Confirm current documentation, validate identity/list schemas, suppress
   metadata, and classify structured failures conservatively.
2. **Credential-subtype routing:** remaining mixed API/webhook and OAuth detectors. Different
   key families require different verification operations; a rejection by the
   wrong API must not label the key invalid.
3. **Region and endpoint context:** Grafana, Zoho, Nylas, Insightly.
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

## Remediation batch 12: eight collection and account contracts

All eight probes are now `read_only`. They require HTTP 200 and validated
provider-specific evidence, suppress response bodies, and preserve unknown for
unproven authorization, scope, region, sandbox, or credential-version failures.
Contentful, CloudConvert, and Capsule CRM no longer accept permission errors as
authentication proof. CloudConvert uses its production endpoint; sandbox-only
credentials remain unknown on rejection.

| Provider | Read-only request | Required evidence |
| --- | --- | --- |
| Contentful | `/spaces?limit=1` | `sys.type=Array`, non-null `items`; each space has `sys.type=Space`, string ID and name. |
| AssemblyAI | `/v2/transcript?limit=1` | Non-null transcript collection, string IDs, documented statuses, and matching page result count. A failed transcription is still legitimate account data. |
| Storyblok | `/v1/spaces?per_page=1` | Non-null spaces collection with IDs and names. |
| CloudConvert | `/v2/users/me` | Nested user ID, username and email; accepts documented string IDs and numeric example IDs. |
| Smartsheet | `/2.0/users/me` | User ID and email, with no `errorCode` field. |
| Rev AI | `/speechtotext/v1/account` | Account email and numeric free, purchased and total balances, including zero. |
| MailerLite | `/api/groups?limit=1` | Non-null groups collection with string IDs and names; replaces static timezone lookup with account-specific evidence. |
| Capsule CRM | `/api/v2/users/current` | Nested user ID and username. |

Collection probes request one item and never follow pagination links. Empty
collections are accepted, while absent/null collections and malformed entries
are not. Contentful, AssemblyAI, Storyblok and Smartsheet retain fixed regional
allowlists with authorization-only fallback. Throttling, outages, redirects,
malformed success responses, transport/read errors, and cancellation stop further
attempts. Returned profile, financial and transcription metadata are suppressed.

Mocked tests cover exact methods, paths, queries and authentication headers;
default-policy promotion; every regional fallback target; malformed, wrong-type,
contradictory and non-200 responses; metadata suppression; transport/read failure;
and cancellation between deployments. No live credentials are used.

Evidence checked 2026-09-25:

- [Contentful official SDK space schema](https://github.com/contentful/contentful-management.js/blob/master/lib/entities/space.ts) and [collection types](https://github.com/contentful/contentful-management.js/blob/master/lib/common-types.ts) (API reference returned HTTP 429).
- [AssemblyAI list transcripts, authentication, pagination and regional endpoint](https://www.assemblyai.com/docs/api-reference/transcripts/list).
- [Storyblok list spaces](https://www.storyblok.com/docs/api/management/spaces/retrieve-multiple-spaces) and [management authentication, regions and pagination](https://www.storyblok.com/docs/api/management).
- [CloudConvert current user](https://cloudconvert.com/api/v2/users).
- [Smartsheet current user](https://developers.smartsheet.com/api/smartsheet/openapi/users/get-current-user).
- [Rev AI account](https://docs.rev.ai/api/asynchronous/reference/accounts/getaccount.md).
- [MailerLite groups](https://developers.mailerlite.com/api/groups).
- [Capsule CRM current user](https://developer.capsulecrm.com/v2/operations/User#showCurrentUser).

## Remediation batch 13: six account and collection contracts

Six additional probes are `read_only`, require HTTP 200 plus provider-specific
success evidence, and suppress response bodies on success and failure.

| Provider | Contract | Changes |
| --- | --- | --- |
| AI21 | `GET /studio/v1/library/files?offset=0&limit=1` | Require a top-level array; entries need string `fileId`, `name`, `fileType`, and `status`. Empty arrays and failed ingestion records are legitimate. No inference or upload requests. |
| Zilliz | `GET /v2/projects` | Require explicit numeric `code: 0` and a non-null project array with string `projectId` and `projectName`. Missing/null codes no longer default to success, and error statuses cannot authenticate. |
| Daily | `GET /v1/` | Replace room listing with domain ID, name and configuration validation. Permission errors no longer count as success. |
| Hunter | `GET /v2/account` | Free account endpoint with documented `X-API-KEY` authentication; validate nested email and plan name, suppress account/quota data. |
| Koyeb | `GET /v1/account/profile` | Validate nested string user ID and email; suppress profile data. |
| Storyblok delivery | `GET /v2/cdn/spaces/me?token=…` | Validate nested space ID/name, preserve documented escaped query authentication, and use authorization-only fallback across the fixed deployment list. |

Zilliz makes one project request (the referenced endpoint documents no pagination)
under the existing bounded response reader. Previously hard-coded rejection
codes 80001, 80002 and 21119 remain unknown because the consulted contract does
not establish that each exclusively means an invalid credential. Other providers
likewise retain unknown for unproven permission, region, subtype, rate-limit and
provider failures. Storyblok stops fallback on malformed responses, redirects,
outages, transport/read failures and cancellation.

Mocked regression tests cover default-policy promotion, exact requests, empty
and populated collections, missing/null/wrong-type evidence, contradictory error
envelopes, non-200 success-looking bodies, transport/read failures, suppression,
every Storyblok fallback target, query escaping and cancellation.

Evidence checked 2026-09-25:

- [AI21 official library client](https://github.com/ai21labs/ai21-python/blob/main/ai21/clients/studio/resources/studio_library.py) and [file response model](https://github.com/ai21labs/ai21-python/blob/main/ai21/models/responses/file_response.py).
- [Zilliz V2 projects](https://docs.zilliz.com/reference/restful/list-projects-v2).
- [Daily domain configuration](https://docs.daily.co/reference/rest-api/domain/get-domain-config).
- [Hunter authentication and account information](https://hunter.io/api-documentation/v2#account).
- [Koyeb official profile API](https://github.com/koyeb/koyeb-api-client-go/blob/master/api/v1/koyeb/docs/ProfileApi.md), [response envelope](https://github.com/koyeb/koyeb-api-client-go/blob/master/api/v1/koyeb/docs/UserReply.md), and [user model](https://github.com/koyeb/koyeb-api-client-go/blob/master/api/v1/koyeb/docs/User.md).
- [Storyblok current space](https://www.storyblok.com/docs/api/content-delivery/v2/spaces/retrieve-current-space).

Typeform documentation still did not yield its current-user contract; it remains
in the hardening backlog. Harness and OpenPhone also remain pending contract
confirmation.

## Remediation batch 14: ten identity and collection verifiers

All ten probes are now `read_only` and require HTTP 200 plus provider-specific
evidence. Returned profile, organization, file, address, account and quota data
are suppressed. Unproven permission, region, self-hosted deployment, account
allowlist and credential-subtype failures remain unknown.

| Provider | Request | Required evidence |
| --- | --- | --- |
| Weights & Biases | GraphQL `query { viewer { id } }` using existing Basic auth | String `data.viewer.id`, no GraphQL errors; null viewer is unknown rather than invalid. |
| PostHog | `/api/users/@me/` | String UUID and email; fixed US/EU deployments, self-hosted credentials remain ambiguous on rejection. |
| Chroma Cloud | `/api/v2/auth/identity` | String user and tenant plus a non-null list of string database names; permission-error text no longer authenticates. |
| SingleStore | `/v2/organizations/current` | String `orgID` and name; existing 64-hex management-key gate makes no request for unsupported formats. |
| LocationIQ | `/v1/balance?key=…&format=json` | `status=ok` and nonnegative integer day/bonus balances, including zero. |
| OANDA | `/v3/accounts` | Non-null accounts array with string IDs, no `errorCode`; practice/live environments. |
| Wise | `/2026Q3/me` | User ID and email; production/sandbox environments. |
| ImageKit | `/v1/files?limit=1&type=file` | Top-level array with file IDs and names; explicit file filter avoids folder-schema ambiguity. |
| Lob | `/v1/addresses?limit=1` | List envelope and address resource types plus address IDs; PII suppressed. |
| Qase | `/v1/project?limit=1&offset=0` | `status=true`, no `errorMessage`, non-null project entities with code/title; Enterprise-host failures stay unknown. |

PostHog, Chroma, LocationIQ, OANDA and Wise use authorization-only fallback.
Malformed success, throttling, outages, redirects, transport/read errors and
cancellation stop further attempts. Collection probes accept legitimate empty
arrays but reject null/missing collections and malformed entries. Pagination URLs
are never followed. OANDA documents no pagination for its authorized-account
list; it makes one request per attempted environment under the bounded reader.

LocationIQ documents a `balance:read` account-token scope requirement beginning
2026-10-19. Unsupported existing tokens will remain unknown on scope rejection;
this batch does not infer validity from permission errors.

Mocked tests cover all ten exact requests and default-policy promotions, valid
empty/zero values, malformed and contradictory payloads, GraphQL partial errors,
non-200 success-looking bodies, response suppression, fallback order and success,
transport/read failure, cancellation and SingleStore's no-request gate.

Evidence checked 2026-09-25:

- [Weights & Biases official viewer query](https://github.com/wandb/wandb/blob/main/core/api/graphql/query_viewer.graphql).
- [PostHog users and `@me` identity](https://posthog.com/docs/api/users).
- [Chroma official identity response](https://github.com/chroma-core/chroma/blob/main/rust/api-types/src/user_identity.rs) and [client identity request](https://github.com/chroma-core/chroma/blob/main/chromadb/api/fastapi.py).
- [SingleStore official organization schema](https://github.com/singlestore-labs/singlestoredb-python/blob/main/singlestoredb/management/organization.py) and [V2 route support](https://github.com/singlestore-labs/singlestoredb-python/blob/main/singlestoredb/management/v2/organization.py).
- [LocationIQ balance and scope transition](https://docs.locationiq.com/docs/balance-api).
- [OANDA authorized accounts](https://developer.oanda.com/rest-live-v20/account-ep/).
- [Wise user schema](https://docs.wise.com/api-reference/user).
- [ImageKit official list request](https://github.com/imagekit-developer/imagekit-python/blob/master/src/imagekitio/resources/assets.py), [array response](https://github.com/imagekit-developer/imagekit-python/blob/master/src/imagekitio/types/asset_list_response.py), and [file model](https://github.com/imagekit-developer/imagekit-python/blob/master/src/imagekitio/types/file.py).
- [Lob authentication and address list](https://docs.lob.com/#tag/Addresses/operation/addresses_list).
- [Qase project list](https://developers.qase.io/reference/get-projects).

## Remediation batch 15: ten account, usage and token-context verifiers

Nine probes are now `read_only`; Miro token introspection is `auth_only`.
Every probe requires HTTP 200 and provider-specific evidence, suppresses its
response body, and preserves ambiguous rejection as `unknown`.

| Provider | Request and authentication | Required evidence |
| --- | --- | --- |
| Restpack HTML to PDF | `GET /api/html2pdf/usage`, `X-Access-Token` | String from/to range, nonnegative integer limit/total, and a non-null days array with string day and integer count. No rendering operation. |
| Restpack Screenshot | `GET /api/screenshot/usage`, `X-Access-Token` | Same usage evidence; a lone usage, limit or remaining field is insufficient. |
| PDFShift | `GET /v3/credits/usage`, current `X-API-Key` authentication | Explicit success=true plus integer base/remaining/total/used credits; zero accepted. Replaces legacy Basic auth. |
| ConvertKit | `GET /v3/account?api_secret=…`, escaped query authentication | Documented string name and primary_email_address, rather than an undocumented id requirement. V3 secrets retain the V3 endpoint. |
| Lemlist | `GET /api/team`, Basic auth with empty username | String _id and name; member data and webhook URLs suppressed. |
| Squarespace | `GET /1.0/authorization/website`, Bearer and required User-Agent | String id, siteId and title; subscription and key-family ambiguity preserved. |
| Help Scout | `GET /v1/collections`, Basic auth with key username and dummy password | Non-null collections.items array with string id/siteId/name. Payment errors no longer mean invalid credentials. |
| Aiven | `GET /v1/project`, `Authorization: aivenv1 …` | Non-null projects array with string project_name; token-family and scope rejection stay unknown. |
| SparkPost | `GET /api/v1/account`, raw Authorization key | Nested results customer_id, company_name and status; permission/scope errors no longer count as successful authentication. |
| Miro | `GET /v1/oauth-token`, Bearer | oAuthToken type, user type/id and non-null string scopes list; token context suppressed. |

SparkPost uses fixed US/EU endpoints with authorization-only fallback. Malformed
success, redirects, throttling, outages, transport/read errors and cancellation
stop further attempts. Help Scout reads the first page (up to 50 collections);
Aiven uses the documented project-list request. Neither follows pagination or
response URLs, and both use the shared bounded response reader. Legitimate empty
collections and scope lists are accepted. No additional API calls are made to
inspect account members, webhooks, projects, or documents.

Tests cover all ten exact requests under ordinary verification policy, required
fields and types, valid empty/zero values, numeric quota boundaries, malformed or
contradictory success, payment/scope errors, non-200 success-looking bodies,
response suppression, transport/read errors, SparkPost fallback and cancellation.

Official evidence checked 2026-09-25:

- [Restpack HTML to PDF usage and authentication](https://restpack.io/html2pdf/docs#route_usage_GET).
- [Restpack Screenshot usage and authentication](https://restpack.io/screenshot/docs#route_usage_GET).
- [PDFShift credits usage](https://docs.pdfshift.io/api-reference/credits/credits-usage.md) and [OpenAPI authentication/schema](https://api.pdfshift.io/openapi.json).
- [Kit V3 current account](https://developers.kit.com/api-reference/v3/account.md).
- [Lemlist team request, authentication and schema](https://developer.lemlist.com/api-reference/endpoints/team/get-team.md).
- [Squarespace website authorization and profile schema](https://developers.squarespace.com/commerce-apis/websites).
- [Help Scout Docs authentication and page limits](https://developer.helpscout.com/docs-api/) and [collections envelope](https://developer.helpscout.com/docs-api/collections/list/).
- [Aiven authenticated project-list example](https://aiven.io/docs/tools/api) and [API reference](https://api.aiven.io/doc/).
- [SparkPost account schema](https://developers.sparkpost.com/api/account/).
- [Miro access-token context](https://developers.miro.com/reference/get-access-token-context.md).

## Remediation batch 23: ten identity and observation verifiers

All ten are now `read_only`. Success requires HTTP 200 and a typed provider
schema; response bodies are suppressed on success and failure. Substring-based
invalid classifications are removed. Permission, account state, subscription,
quota, feature restrictions and deployment ambiguity remain unknown. Fixed-host
fallback retries only authorization ambiguity and stops on malformed responses,
redirects, throttling, provider outages, transport/read failures or cancellation.

| Provider | Contract and supported scope |
| --- | --- |
| Typeform | Bearer `GET /workspaces?page=1&page_size=1` replaces `/me`, whose response schema was not established. Integer total_items/page_count and typed workspace id/name are required; empty lists are valid. This probe requires workspaces:read, so accounts:read-only tokens may remain unknown. Existing US/old-EU workspace APIs share results; authorization-only fallback targets the separate new-EU `api.typeform.eu` host. |
| BitGo | Bearer `GET /api/v2/user/me`; nested user id/username required and suppressed. Frozen/inactive accounts are not rejected. Documented production/test hosts are tried only on authorization ambiguity; no wallet, signing, session unlock or token-generation operations. |
| Statuspage | `Authorization: OAuth` `GET /v1/pages`; array of id/name/created_at, including empty arrays. The official page-list operation offers no pagination parameters: one collection is read under the shared response-byte cap, without inventing a server-side limit. Truncated malformed responses are unknown and all page metadata is suppressed. |
| Sourcegraph | Token-authenticated read-only GraphQL currentUser username query. Nested errors and anonymous/null currentUser cannot prove authentication; partial data with errors remains unknown. Local-prefixed tokens preserve unsupported/no-request behavior; hashed and legacy prefixes retain the existing cloud-only probe, with self-hosted rejection unknown. |
| Flutterwave | V3 Bearer `GET /balances`; status=success plus currency and numeric available/ledger balances. Empty collections, zero and negative balances authenticate. Supported FLWSECK_TEST variant added alongside existing keys. V4 OAuth credentials/exchanges are outside this probe. The documented currency collection has no pagination. |
| OpenWeather | One current-weather call for fixed London coordinates replaces deprecated built-in city-name lookup. Requires numeric cod=200, timestamp, coordinates, temperature and a typed weather array. Optional precipitation/station metadata is ignored. Activation delay, subscription and quota rejection remain unknown. |
| Tomorrow.io | One realtime call for fixed coordinates; data.time, numeric temperature and location coordinates required. Optional cloud/precipitation metrics can be absent/null. Structured code errors cannot prove success. |
| HERE | One Berlin geocode result (`limit=1`); id/title/resultType and numeric position. A valid empty result collection is accepted. Structured errors, feature restrictions and quota failures remain unknown. |
| World Weather Online | Current-only London weather (`num_of_days=0`); typed request and nonempty observation collection inside data, with observation time, weather code and finite numeric-string temperature. Nested provider errors and malformed values remain unknown; no forecast/history is requested. |
| Infura | Read-only JSON-RPC `eth_chainId` replaces `eth_blockNumber`, reducing documented cost from 80 to 5 credits. Requires jsonrpc=2.0, numeric matching id=1 and mainnet result=0x1, with no error object. Project-secret, allowlist, network restriction and quota ambiguity remain unknown. |

Weather, geocoding and RPC probes consume provider quota and can count toward
plan billing. They issue one request each and do not retry rate limits. All
responses retain the shared byte cap; links and returned endpoint URLs are never
followed. All ten patterns have whole-token trailing boundaries; BitGo test-host,
World Weather context variants and trailing HERE key hyphens are covered.

Mocked regressions cover exact URLs, methods, headers and GraphQL/RPC bodies;
ordinary verification policy; typed, empty and optional success data; contradictory
errors; non-200 success-like bodies; transport/read errors; response suppression;
fallback order and cancellation; no-request local tokens; credential boundaries;
and Statuspage response truncation. The older Infura regression now expects the
chain ID and conservative authorization result.

Official evidence checked 2026-09-27:

- [Typeform workspaces and pagination](https://www.typeform.com/developers/create/reference/retrieve-workspaces/), [scopes](https://www.typeform.com/developers/get-started/scopes/), [EU hosts and account separation](https://www.typeform.com/developers/get-started/responses-data-center/).
- [BitGo current-user schema and me alias](https://developers.bitgo.com/reference/userget), [production/test environments](https://developers.bitgo.com/docs/get-started-environments).
- [Statuspage page list, response schema and OAuth authorization](https://developer.statuspage.io/).
- [Sourcegraph current-user GraphQL query and token authentication](https://sourcegraph.com/docs/api/graphql).
- [Flutterwave V3 balance schema and test-key authorization](https://developer.flutterwave.com/reference/get-all-wallet-balances.md).
- [OpenWeather current weather, coordinates and JSON success schema](https://openweathermap.org/current).
- [Tomorrow.io realtime OpenAPI and query authentication](https://docs.tomorrow.io/reference/realtime-weather.md).
- [HERE Berlin geocode example](https://docs.here.com/geocoding-and-search/docs/code-geocode-area.md), [OpenAPI limit, authentication and restricted features](https://docs.here.com/geocoding-and-search/reference/get_geocode.md).
- [World Weather Online current-only parameters and response](https://www.worldweatheronline.com/developer/api/docs/local-city-town-weather-api.aspx).
- [Infura chain-ID response and five-credit cost](https://docs.infura.io/reference/ethereum/json-rpc-methods/eth_chainid/), [replaced block-number probe's 80-credit cost](https://docs.infura.io/reference/ethereum/json-rpc-methods/eth_blocknumber/).

## Remediation batch 22: ten token and bounded collection verifiers

Buildkite is now `auth_only`; the other nine are `read_only`. All require HTTP
200 and provider-specific schemas, suppress response bodies on every outcome,
and preserve unknown results for permission, region and credential-family
ambiguity. Collection probes read only one page and never follow returned links.
Fixed-host fallback occurs only after authorization ambiguity, stopping on
redirects, malformed responses, throttling, outages, transport/read failures and
cancellation. All responses retain the shared byte limit.

| Provider | Contract and supported scope |
| --- | --- |
| Buildkite | Bearer `GET /v2/access-token`; UUID, creation date and string scopes array required. Empty scopes and absent user metadata are legitimate. Only `bkua_` API tokens are submitted; existing `bkpa_`/`bkca_` detections return unknown without requests. No agent registration or token revocation. This does not add detection for every newer Buildkite token prefix. |
| Increase | Bearer `GET /programs?limit=1`; data array with program type/id/name, including empty lists. Authorization-only production/sandbox fallback. Detected webhook/OAuth secrets are not declared invalid if the API rejects them. |
| Persona | Bearer `GET /api/v1/inquiries?page[size]=1&fields[inquiry]=status`; inquiry id/type/status, including empty lists. Sparse fieldset limits inquiry metadata; all response data is suppressed. Status values are extensible. Webhook-secret, permission and quota failures remain unknown. |
| Circle | Bearer `GET /v1/configuration`; nested data.payments.masterWalletId string, without an error code. Fixed production/sandbox fallback on authorization ambiguity. This verifies supported Circle Mint configuration credentials; other product keys and webhook secrets remain unknown on rejection. |
| Cockroach Cloud | Bearer `GET /api/v1/clusters?pagination.limit=1` with existing Cc-Version; typed id/name/state per cluster, including empty lists. Optional infrastructure fields and cluster readiness are not required. Non-API secret and role ambiguity stays unknown. |
| Polar | Bearer `GET /v1/organizations/?page=1&limit=1`; id/name/slug and integer pagination, including empty lists. Adds documented sandbox host with authorization-only fallback. Insufficient organizations:read scope no longer proves authentication. |
| Wrike | Bearer `GET /api/v4/contacts?me=true`; kind=contacts and typed id/type/me=true entries. Empty collections and robot contacts accepted; optional names/profile metadata not required. Fixed US/EU/US2 authorization-only fallback; access_forbidden no longer proves authentication. Existing supported JWT length retained with whole-token boundaries. |
| MessageBird | AccessKey `GET /balance`; prepaid/postpaid payment, type and numeric amount. Zero/postpaid and negative balances accepted. Adds unprefixed live-key detection while preserving test/legacy live-prefixed detections. Broad code-2 substring invalidation removed: authorization ambiguity is unknown. |
| imgix | Bearer `GET /api/v1/sources?page[number]=0&page[size]=1&fields[sources]=name` with JSON:API Accept; sources id/type/name, including empty arrays. Corrects the old undocumented page[limit] parameter. Sparse fields avoid source deployment, signing tokens and origin configuration. Secure URL token rejection stays unknown. |
| ZeroBounce | Documented `GET /v2/getcredits?api_key=...` retained; only HTTP 200 integer Credits authenticates, including zero. Exact -1 is invalid only in a well-formed, error-free HTTP 200 response. Strings, nulls, fractional/overflow values, trailing JSON and non-200 responses are unknown. Uses the existing global endpoint without regional fanout; query authentication is required by this documented GET contract. |

The existing broad mixed-secret detectors remain useful findings even when their
subtype cannot be verified. All ten patterns now reject truncated suffix matches.
These probes may consume provider request quotas; no email validation, payments,
messages, deployments or other resource creation occurs. ZeroBounce documents
temporary blocking after repeated invalid-key requests; the verifier performs
one request without retries.

Mocked tests cover all ten exact methods/URLs/authentication headers, sparse and
pagination parameters, ordinary verification policy, nonempty and empty success
schemas, null/wrong-type fields, contradictory error envelopes, response
suppression, non-200 success-like payloads, transport/read errors, authorization
fallback ordering and cancellation. Additional tests cover ZeroBounce's exact
invalid sentinel, Buildkite no-request subtypes, unprefixed MessageBird keys and
whole-token detection boundaries.

Official evidence checked 2026-09-27:

- [Buildkite current-token introspection](https://buildkite.com/docs/apis/rest-api/access-token.md), [token families](https://buildkite.com/docs/platform/security/tokens.md).
- [Increase program list, schema and limit](https://increase.com/documentation/api/programs).
- [Persona inquiry list, sparse fields, pagination and permissions](https://docs.withpersona.com/api-reference/inquiries/list-all-inquiries.md).
- [Circle Mint configuration schema, Bearer authentication and sandbox](https://developers.circle.com/api-reference/circle-mint/general/get-account-config.md).
- [Cockroach Cloud official OpenAPI cluster list and roles](https://cockroachlabs.cloud/assets/docs/api/latest/openapi.json).
- [Polar organization list and pagination](https://polar.sh/docs/api-reference/organizations/list.md), [sandbox API host and separate keys](https://polar.sh/docs/integrate/sandbox.md).
- [Wrike current-user filter, contact schemas, hosts and Bearer auth](https://developers.wrike.com/reference/getcontactsempty.md).
- [MessageBird balance schema](https://developers.messagebird.com/api/balance/), [unprefixed live keys and test authentication](https://developers.messagebird.com/api/#authentication).
- [imgix sparse fields, JSON:API and pagination](https://docs.imgix.com/en-US/apis/management/general-usage), [source schema](https://docs.imgix.com/en-US/apis/management/sources).
- [ZeroBounce credit balance GET, integer sentinel, regional hosts and quotas](https://www.zerobounce.net/docs/email-validation-api-quickstart/v2-credit-balance).

## Remediation batch 21: ten regional metadata and key-context verifiers

Eight probes are now `read_only`; Honeycomb and Flickr are `auth_only`.
All require HTTP 200 and provider-specific evidence and suppress responses on
success and failure. Permission, subtype, region and provider ambiguity remains
unknown. Fixed-host fallback occurs only after authorization ambiguity and stops
on malformed success, redirects, throttling, outages, transport/read failures or
cancellation. Pagination links are never followed.

| Provider | Contract and evidence required |
| --- | --- |
| PagerDuty | `Token token=` `GET /abilities` replaces user listing; non-null array of string ability names, including an empty array. Ambiguous 32-hex integration/routing keys make no REST request and remain findings. Unsupported REST key types/scopes remain unknown; no events are submitted. |
| Honeycomb | `X-Honeycomb-Team` `GET /1/auth`; key id/type, team name/slug, typed environment strings and boolean permission map. Classic empty environment values and empty permissions are legitimate. Supported 22-character configuration/32-hex Classic formats retained with whole-key boundaries; management key IDs/secrets are not treated as configuration tokens. Fixed US/EU authorization-only fallback. |
| Opsgenie | `GenieKey` `GET /v2/account`; nested account name and nonnegative integer userCount. Optional plan/limits are not required. Restricted integration/configuration permissions remain unknown; fixed global/EU authorization-only fallback. |
| Postmark | Server-token `GET /stats/outbound` replaces `/server`, which returns API tokens. Requires integer Sent/Bounced/SMTPApiErrors. Authorization-only fallback tries account-token `GET /senders?count=1&offset=0`, requiring TotalCount and typed ID/EmailAddress/Confirmed entries. Empty collections and unconfirmed senders are legitimate. ErrorCode envelopes cannot prove success. |
| Cloudinary | Basic-auth `GET /v1_1/{cloud}/config`; response cloud_name must match the parsed credential cloud, plus created_at. Optional settings are not requested. Fixed US/EU/AP hosts with authorization-only fallback; configuration and credentials suppressed. |
| KeyCDN | Basic-auth `GET /reports/creditbalance.json` replaces zone listing; status=success and finite numeric string data.amount. Zero and negative balances authenticate; financial metadata is suppressed. |
| Flickr | App-key `flickr.test.echo` requires stat=ok and matching echoed method/key. The documented test validates the application key, not a user OAuth session. Only supported 32-hex application keys are submitted; other detected formats remain unknown without requests. Exact numeric code 100 is unverified only with HTTP 200, stat=fail and no echoed success fields. Echoed key material is suppressed. |
| Storecove | Bearer `GET /api/v2/discovery/identifiers`; CountrySpecifications countries array with string country entries replaces generic collection detection. Optional regional and identifier metadata is not required. Experimental endpoint access restrictions and region/subtype rejection remain unknown. |
| Twist | Bearer `GET /api/v3/users/get_session_user`; integer id/name/email, without an application code envelope. The complete response, including returned user token and session information, is suppressed. No login, refresh, logout or presence calls. |
| Web Scraper | Bearer `GET /api/v1/sitemaps?page=1` replaces query credentials. Requires success=true, integer pagination and typed sitemap id/name. One provider-sized page is requested; the documented endpoint offers no per-page parameter. No scraping jobs are created or fetched. |

All requests use the shared response-size cap and remain subject to provider
quotas. Unpaginated country/ability metadata is read only once. Existing
credential families are retained with trailing boundaries to prevent partial
captures; Storecove trailing hyphens and Web Scraper context variants now work.

Mocked regressions cover all ten exact requests, auth headers/Basic/query
encoding, ordinary verification policy, empty and nullable metadata, malformed
schemas, contradictory errors, non-200 success-like bodies, response suppression,
transport/read failures, fallback order and cancellation. Postmark tests cover
both token headers and account schemas; Flickr tests constrain code 100 to its
documented success-status envelope. Detection tests cover whole credential
capture and no-request behavior for ambiguous PagerDuty/Flickr families.

Official evidence checked 2026-09-27:

- [PagerDuty REST abilities, authentication and scope](https://github.com/PagerDuty/api-schema/blob/main/reference/REST/openapiv3.json), [Events integration/routing-key distinction and examples](https://github.com/PagerDuty/api-schema/blob/main/reference/events-v2/openapiv3.json).
- [Honeycomb auth schema, regions and Classic empty environment](https://docs.honeycomb.io/api/auth/list-authorizations.md), [key types and authentication](https://docs.honeycomb.io/api/authentication.md).
- [Opsgenie account API, schema and configuration restrictions](https://docs.opsgenie.com/docs/account-api.md).
- [Postmark server statistics](https://postmarkapp.com/developer/api/stats-api), [account sender signatures](https://postmarkapp.com/developer/api/signatures-api), [token-bearing server response being replaced](https://postmarkapp.com/developer/api/server-api).
- [Cloudinary Admin API config response, Basic auth and regional hosts](https://cloudinary.com/documentation/admin_api).
- [KeyCDN credit balance, string amount and Basic authentication](https://www.keycdn.com/api).
- [Flickr echo, required application key and error 100](https://www.flickr.com/services/api/flickr.test.echo.html).
- [Storecove experimental identifiers and CountrySpecifications schema](https://www.storecove.com/docs/).
- [Twist current-user endpoint, token-bearing user object and Bearer authentication](https://developer.twist.com/v3/).
- [Web Scraper official OpenAPI: Bearer auth, sitemap pagination and schema](https://webscraper.io/openapi.yaml).

## Remediation batch 20: ten bounded identity and metadata verifiers

All ten probes are now `read_only`. Success requires HTTP 200 and the structured
provider evidence below. Responses are suppressed on success and failure; scope,
credential-family, environment, quota and provider failures remain unknown.
Figma scope errors, LINE forbidden responses and Bannerbear payment errors no
longer count as successful authentication.

| Provider | Contract and evidence required |
| --- | --- |
| Figma | `X-Figma-Token` `GET /v1/me`; id/email/handle and no err envelope. Only `figd_` personal tokens are submitted. Other detected Figma families remain findings but return unknown without a request or token exchange. Missing current_user:read scope remains unknown. |
| Clerk | Bearer `GET /v1/users/count` replaces deprecated clients listing; object=total_count and a nonnegative integer total_count, including zero. Retrieves no user records. Test/live secret-key detection retained with whole-token boundaries. |
| Zeplin | Bearer `GET /v1/users/me`; id/username/email required. Aliased emails and absent optional avatar/emotar metadata are legitimate. Supported opaque personal tokens retain their existing format; JWT OAuth/refresh tokens are not truncated into that format. |
| Adafruit IO | `X-AIO-Key` `GET /api/v2/user`; positive integer id, username and created_at. Modern aio_ and legacy key forms use the same authentication; optional name/color/timezone are not required. |
| Pipedream | Bearer `GET /v1/users/me`; nested data id/username/email. Both free and paid account schemas work without requiring plan-specific quota fields. This endpoint supports user API keys, not workspace OAuth clients; subtype rejection remains unknown. |
| LINE Messaging | Bearer `GET /v2/bot/info`; userId/basicId/displayName and documented chatMode/markAsReadMode enums. Supported opaque channel credentials preserve base64 padding and slash characters. No messages are sent and no tokens are issued or refreshed. Other token lengths/formats are outside this detector's supported family. |
| Bannerbear | Bearer `GET /v2/account`; uid/created_at and nonnegative integer api_usage/api_quota. Zero quotas, over-quota usage and nullable plan/project metadata are legitimate success data. The supported V2 format is retained; V5 incompatibility and payment rejection remain unknown. |
| Elastic Email | `X-ElasticEmail-ApiKey` `GET /v4/lists?limit=1&offset=0` replaces sensitive API-key enumeration. Array entries require ListName/DateAdded and boolean AllowUnsubscribe; nullable PublicListID is legitimate. Missing ViewContacts permission remains unknown. |
| Tradier | Bearer `GET /v1/user/profile`; nested profile id/name. Fixed production/sandbox fallback only after authorization ambiguity. Account associations, including closed accounts, are not required for identity; financial metadata is suppressed. Supported token boundaries prevent partial captures. |
| Trigger.dev | Bearer `GET /api/v1/runs?page[size]=10`; non-null data and pagination objects with typed optional cursors, run identity/status/timestamps/isTest and environment id/name. Ten is the documented minimum page size. Failed/cancelled runs and empty collections authenticate; no jobs are triggered. Environment-key prefixes are now detected standalone, including staging and preview. |

All probes use the shared response-size cap and do not follow response-supplied
links or redirects. Tradier fallback stops on throttling, outages, malformed
success, transport/read failures and cancellation. Trigger.dev branch context is
not guessed; self-hosted, branch-restricted and scoped-key failures remain unknown.
Read requests remain subject to provider request quotas.

Mocked regressions cover all ten exact requests, authentication, runtime safety
and default-policy access, valid empty/nullable data, schema errors, contradictory
error envelopes, non-200 success-like bodies, response suppression and transport
failures. Additional tests cover Tradier fallback/cancellation, Figma no-request
credential families, environment-key detection, legacy/modern Adafruit keys,
padded LINE tokens and oversized-token truncation prevention.

Official evidence checked 2026-09-27:

- [Figma current user and required scope](https://developers.figma.com/docs/rest-api/users-endpoints/), [user fields](https://developers.figma.com/docs/rest-api/users-types/), [personal-token authentication](https://developers.figma.com/docs/rest-api/personal-access-tokens/).
- [Clerk official OpenAPI: /users/count, TotalCount and Bearer security](https://github.com/clerk/openapi-specs/blob/main/bapi/2021-02-05.yml).
- [Zeplin current user](https://docs.zeplin.dev/reference/getcurrentuser.md), [user schema and alias emails](https://docs.zeplin.dev/reference/user.md), [OAuth authentication and distinct JWT credentials](https://docs.zeplin.dev/reference/authentication.md).
- [Adafruit IO user schema, header authentication and rate limits](https://io.adafruit.com/api/docs/http.html).
- [Pipedream current-user schemas](https://pipedream.com/docs/rest-api/api-reference/users/get-current-user-info.md), [user-only endpoint restriction](https://pipedream.com/docs/rest-api/api-reference/users), [authentication families](https://pipedream.com/docs/rest-api/auth.md).
- [LINE official OpenAPI bot-info schema](https://github.com/line/line-openapi/blob/main/messaging-api.yml), [channel-token families](https://developers.line.biz/en/docs/basics/channel-access-token/).
- [Bannerbear V2 account and error contract](https://developers.bannerbear.com/v2/), [V5/V2 key incompatibility](https://developers.bannerbear.com/).
- [Elastic Email official V4 OpenAPI: /lists, ContactsList and ViewContacts scope](https://api.elasticemail.com/public/v4/swagger).
- [Tradier profile schema](https://docs.tradier.com/reference/brokerage-api-user-get-profile.md), [production and sandbox hosts](https://docs.tradier.com/docs/endpoints), [token environments](https://docs.tradier.com/docs/getting-started.md).
- [Trigger.dev run schema and minimum page size](https://trigger.dev/docs/management/runs/list.md), [key families, scopes, branch and self-host context](https://trigger.dev/docs/apikeys.md).

## Remediation batch 19: ten account-context and authentication verifiers

Nine probes are now `read_only`; Geckoboard's authentication ping is `auth_only`.
All require HTTP 200 and provider-specific evidence and suppress response bodies
on success and failure. Permission, subscription, credential-subtype and provider
errors remain unknown. Requests use the shared bounded response reader and never
follow redirects or response-supplied links.

| Provider | Contract and evidence required |
| --- | --- |
| Klaviyo | `GET /api/accounts?fields[account]=timezone` replaces profiles; exactly one account with id/type and attributes.timezone. Uses Klaviyo-API-Key authentication, revision `2026-07-15` and JSON:API Accept. Missing accounts:read scope remains unknown. |
| OpenPhone / Quo | `GET /organization`, literal Authorization key and `Quo-Api-Version: 2026-03-30`; data id/createdAt/updatedAt and active or expired subscriptionStatus. Nullable name and expired subscriptions are legitimate. Quo context is now detected. |
| Socket.dev | Bearer `GET /v0/organizations`; non-null organization map, entries with id/slug/plan. Empty maps and nullable names/images are legitimate. Requires authentication but no org-token scope; consumes **one quota unit**. The socketdev prefilter now matches its existing regex context. |
| Float | Bearer `GET /v3/accounts?per-page=1&fields=account_id,name` replaces people; array of positive integer account_id and name. Uses the documented contact-bearing User-Agent, sparse fields and one-item page. |
| Nimble | Bearer `GET /api/v1/myself`; user_id/company_id/email replace the incorrect id expectation. Application code envelopes remain unknown; token suffix boundaries prevent truncated credential verification. |
| Yousign | Bearer `GET /v3/users?limit=1`; data array with id/email and meta.next_cursor string or null. Fixed production/sandbox hosts, fallback only on authorization ambiguity. Optional user metadata and inactive users do not invalidate authentication. |
| Geckoboard | Basic-auth `GET /`; success requires exactly an empty JSON object. Generic success objects no longer prove authentication; trailing credential suffixes cannot be truncated into a supported key. |
| TaxJar | Bearer `GET /v2/categories`; typed product_tax_code/name collection, fixed production/sandbox hosts with authorization-only fallback. Documented 28-character keys are accepted whole. |
| fastFOREX | `X-API-KEY` `GET /usage` replaces exchange-rate lookup and query authentication; numeric quota/history counters and current-period start/end/usage/remaining_quota. Supported key boundaries reject truncated suffixes. |
| CraftMyPDF | `X-API-KEY` `GET /v1/get-account-info`; top-level status=success, username/created_at and numeric quotas replace the incorrect data envelope. Padded base64 credential characters are preserved. |

TaxJar/Yousign fallback stops on malformed success, redirects, throttling,
outages, transport/read failures and cancellation. Collection probes accept empty
collections; identity probes require the documented account evidence. Requests
remain subject to provider quotas. Socket organization and TaxJar category lists
have no requested pagination; response size is capped by the shared reader.

Mocked regressions cover all ten exact requests, headers, ordinary verification
policy, nullable metadata, empty collections, non-200 success-like responses,
contradictory errors, response suppression, transport/read failures, fallback and
cancellation. Detection tests cover padded credentials, whole-key boundaries and
Quo/Socket context. Shared identity requests now preserve explicit Accept headers.

Official evidence checked 2026-09-27:

- [Klaviyo account schema, sparse fields, revision and scope](https://developers.klaviyo.com/en/reference/get_accounts.md).
- [Quo versioned organization endpoint, authentication and subscription states](https://www.quo.com/docs/2026-03-30/organization/get-the-organization.md).
- [Socket organization schema, scopes and quota](https://docs.socket.dev/reference/getorganizations.md), [authentication](https://docs.socket.dev/reference/authentication.md).
- [Float accounts schema and pagination](https://developer.float.com/paths/accounts.yaml), [API overview and sparse fields](https://developer.float.com/), [authentication](https://developer.float.com/overview_authentication.html).
- [Nimble current-user response and OAuth authentication](https://nimble.readthedocs.io/en/latest/).
- [Yousign/Youtrust v3 users schema and environments](https://developers.youtrust.com/reference/get-users-1.md).
- [Geckoboard authentication ping and key example](https://developer.geckoboard.com/).
- [TaxJar authentication, sandbox and category schema](https://developers.taxjar.com/api/reference/).
- [fastFOREX usage schema and header authentication](https://www.fastforex.io/docs/api-reference/admin/usage.md).
- [CraftMyPDF official OpenAPI, account fields and credential examples](https://craftmypdf.s3.ap-southeast-1.amazonaws.com/craftmypdf_api/craftmypdf_api.yaml).

## Remediation batch 18: ten paginated collection and account verifiers

All ten are now `read_only`. Each makes one authenticated GET, requires HTTP 200
and provider-specific structured evidence, and suppresses the response body on
success and failure. Permissions, subscriptions, credential subtypes and provider
failures remain unknown. Redirects and response pagination links are not followed.

| Provider | Contract and evidence required |
| --- | --- |
| Onfido / Entrust | Token-authenticated `GET /v3.6/applicants?page=1&per_page=1`; non-null applicants with string id/created_at. Live/sandbox token prefixes select exactly one EU, US or CA host. Regional bare-token prefilter keywords now match all six documented prefixes. Applicant PII is suppressed. |
| Snipcart | Basic-auth `GET /api/orders?limit=1&format=Excerpt`; nonnegative integer totalItems/offset/limit and typed order token/status. Requests lighter summaries rather than full orders; cancelled orders still authenticate. Public-key rejection remains unknown. |
| Scrutinizer | Escaped access_token query auth on `GET /api/user/repositories?page=1&per_page=1`; page/limit and embedded repositories with type/created_at and self href. Links are treated only as data and never requested. |
| Codemagic | `x-auth-token` `GET /apps`; applications with string _id/appName. Workflow metadata is optional, since YAML workflows are not returned before a build. The documented list has no pagination; one response is read under the shared 1 MiB cap, with truncated JSON unknown. |
| Teachable | `apiKey` `GET /v1/courses?page=1&per=1`; courses with positive integer id/name and boolean is_published, plus meta total/page/per_page. Unpublished courses and nullable descriptions remain legitimate. |
| Axonaut | `userApiKey` `GET /api/v2/companies?type=all&sort=id`, documented `page: 1` header; top-level array of integer id/name objects. Uses the provider's first-page size, since the contract exposes no page-size parameter. Business and financial data are suppressed. |
| Survicate | `Authorization: Basic <key>` `GET /v2/surveys?items_per_page=1`; pagination_data.has_more boolean and typed data survey id/name/created_at/type. Replaces v1, retired September 15, 2026. Does not retrieve survey responses or respondents. |
| Better Stack | Bearer `GET /api/v2/team-members?page=1&per_page=1`; JSON:API member or pending-invitation id/type plus email/role. A global token needing team_name now remains unknown instead of being classified verified from error text. No team is guessed. |
| Intrinio | Bearer `GET /account/current_usage`; account email and non-null usage collection with access_code and documented string count/limit. Limits are not assumed numeric; public-key domain restrictions and subscription failures remain unknown. |
| Mavenlink / Kantata | Bearer `GET /api/v1/users/me.json` replaces collaborator listing; exactly one canonical results entry must resolve to the matching users map id/email_address, with count=1. No optional associations are requested. |

Empty resource collections are valid, whereas missing/null arrays, malformed
entries and contradictory errors are unknown. Current-user identity requires a
real result. All probes use the shared bounded response reader and remain subject
to normal provider request quotas.

Mocked tests cover all ten exact requests and ordinary-policy promotions, query
escaping, Basic/header authentication, integer versus string IDs, unpublished or
cancelled resources, pending invitations, nullable metadata, malformed envelopes,
non-200 success-like bodies, response suppression and transport/read failures.
Onfido tests additionally verify standalone detection and single-host routing for
all six environment/region prefixes, including authorization and outage responses.

Official evidence checked 2026-09-26:

- [Onfido API regions, tokens, applicant schema and pagination](https://documentation.onfido.com/api/latest/).
- [Snipcart orders, Excerpt format, Basic authentication and list envelope](https://docs.snipcart.com/v3/api-reference/orders).
- [Scrutinizer authenticated user repositories and per_page bounds](https://scrutinizer-ci.com/docs/api/).
- [Codemagic applications and optional workflow metadata](https://docs.codemagic.io/rest-api/applications/).
- [Teachable courses, per pagination and typed schemas](https://docs.teachable.com/reference/listcourses.md).
- [Axonaut embedded OpenAPI: company array, page header and userApiKey](https://axonaut.com/api/v2/doc).
- [Survicate survey list](https://developers.survicate.com/data-export/survey.md) and [v1-to-v2 migration, unchanged authentication and retirement date](https://developers.survicate.com/data-export/migration-v1-v2.md).
- [Better Stack members, invitations and global-token ambiguity](https://betterstack.com/docs/uptime/api/team-members/), [pagination](https://betterstack.com/docs/uptime/api/pagination/). The existing detector format is retained; the contract does not publish a universal token-length guarantee.
- [Intrinio current usage](https://docs.intrinio.com/documentation/web_api/get_account_current_usage_v2), [authentication](https://docs.intrinio.com/documentation/api_v2/authentication), and [official SDK string counters](https://github.com/intrinio/javascript-sdk/blob/master/src/model/AccountCurrentUsage.js).
- [Kantata API response indexing and authentication](https://developer.mavenlink.com/), [official OpenAPI /users/me contract and User schema](https://app.mavenlink.com/oas/specification).

## Remediation batch 17: ten principal, token and bounded-read verifiers

Eight probes are promoted to `read_only`; Wistia and Northflank are `auth_only`.
All require HTTP 200 and provider-specific structured evidence. Response bodies
are suppressed on success and failure. Permissions, subscription restrictions,
regions, unsupported token families, throttling and provider outages remain
unknown. No response-supplied links are followed.

| Provider | Contract and evidence required |
| --- | --- |
| Snyk | Token-authenticated `GET /rest/self?version=2024-10-15`; data id/type and user email or service-account/app-instance name. Fixed legacy-US, US, EU and AU hosts; fallback only on authorization ambiguity. The existing UUID detector/authentication is retained; app OAuth and newer PAT formats are not inferred from it. API plan restrictions remain unknown. |
| Meraki | Bearer `GET /api/v1/administered/identities/me` replaces organization enumeration; name/email required. Regional redirects are not followed and remain unknown. |
| Productboard | Bearer `GET /v2/members`, first page only; non-null data array, member id/type and fields.role. Redacted PII is accepted without requesting additional scopes. The endpoint documents cursors but no caller-controlled page size. |
| Wistia | Bearer `GET /modern/token`, `X-Wistia-API-Version: 2026-07`; permanent/expiring/oauth type, non-null string scopes, nullable name and matching application context. Empty scopes are legitimate. Account-inactive and scope failures remain unknown. |
| Twelve Data | Escaped query-authenticated `GET /api_usage`; timestamp/plan category, nonnegative integer current_usage/plan_limit and optional daily counters. Usage can exceed a limit without making the credential invalid. This verification consumes **one API credit** per request. |
| The Guardian | Escaped query-authenticated `GET /search?page-size=1`; nested ok status, user tier, nonnegative total and typed article id/type/webUrl. Article metadata suppressed. |
| NewsAPI | `X-Api-Key` `GET /v2/top-headlines?country=us&pageSize=1`; ok status, nonnegative totalResults and non-null articles with url/publishedAt. Exact apiKeyInvalid/apiKeyDisabled codes are unverified only with HTTP 401, error status and no contradictory success fields. Exhaustion and rate limits remain unknown. |
| Northflank | Bearer `GET /v1/auth` replaces projects; data tokenKind and entityType enums, token id, entityId/entityUid and createdAt. Role and permissions are optional. |
| Shotstack | `x-api-key` `GET /edit/{stage,v1}/templates`; explicit success=true, response owner and typed template id/name. Only authorization ambiguity permits trying the other environment. No renders are submitted. |
| Optimizely | Bearer `GET /v2/me` replaces projects; string id and profile.email, no expansion requested. Application error codes invalidate success evidence. |

Collections may be empty, but missing/null collections and malformed entries are
unknown. Productboard's first page and Shotstack's unpaginated template metadata
use the shared bounded response reader. News and usage reads remain subject to
provider quotas. Snyk/Shotstack fallback stops on malformed success, redirects,
throttling, outages, transport/read failures and cancellation.

Mocked regression tests cover all ten exact requests, authentication encoding,
runtime safety/default-policy access, valid credential variants, redacted PII,
empty scopes and collections, contradictory errors, malformed schemas, non-200
success-like responses, response suppression, fallback order and cancellation.
The older Shotstack fallback fixture now includes the documented owner field.

Official evidence checked 2026-09-26:

- [Snyk self API and linked OpenAPI principal schemas](https://docs.snyk.io/developer-tools/snyk-api/reference/users.md), [authentication and subscription restrictions](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api.md).
- [Meraki current identity](https://developer.cisco.com/meraki/api-v1/get-administered-identities-me/) and [official OpenAPI including Bearer security](https://github.com/meraki/openapi/blob/master/openapi/spec3.json).
- [Productboard members, cursor pagination and PII scope](https://developer.productboard.com/reference/listmembers.md).
- [Wistia versioned current-token schema and error codes](https://docs.wistia.com/reference/gettokendetails.md).
- [Twelve Data usage schema and one-credit cost](https://twelvedata.com/docs#api-usage).
- [Guardian search schema and page-size bounds](https://open-platform.theguardian.com/documentation/md/content_search.md), [authentication](https://open-platform.theguardian.com/documentation/md/common.md).
- [NewsAPI top headlines](https://newsapi.org/docs/endpoints/top-headlines) and [structured errors](https://newsapi.org/docs/errors).
- [Northflank current authentication](https://northflank.com/docs/v1/api/miscellaneous/auth/get-current-authentication-info.md).
- [Shotstack list templates, schema and environment authentication](https://shotstack.io/docs/api/).
- [Optimizely current user and unexpanded profile](https://docs.developers.optimizely.com/web-experimentation/reference/get_me.md).

## Remediation batch 16: ten collection and account verifiers

All ten probes are now `read_only`. Success requires HTTP 200 and the documented
provider-specific evidence below. Returned PII, file names, account settings,
linked social identities, financial statistics and mailing-list metadata are
suppressed. Ambiguous permission, subscription, token-family, deployment and
provider failures remain unknown.

| Provider | Request | Required evidence and changes |
| --- | --- | --- |
| Signaturit | Bearer `GET /v3/signatures.json?limit=1` | Top-level signature array, string id/created_at, typed documents with id/status; failed documents still establish authenticated access. Production/sandbox fallback is authorization-only. |
| Shippo | `ShippoToken` `GET /addresses/?results=1`, API version `2018-02-08` | Non-null results array with string object_id/object_owner; incomplete addresses may still authenticate. Pagination links are never followed. |
| ShipEngine | `API-Key` `GET /v1/account/settings` | Documented default_label_layout enum (`4x6` or `Letter`); fixed US/EU authorization-only fallback. |
| Easyship | Bearer `GET /2024-09/account` | Nested account easyship_company_id/name; optional billing address, credit and payment-source scopes are not required for success. |
| Jotform | `APIKEY` `GET /user` | Explicit numeric responseCode=200 plus content username/email; fixed global/EU/HIPAA authorization-only fallback. Custom-host rejection stays unknown. |
| Klipfolio | `kf-api-key` `GET /api/1.0/profile` | Replaces user enumeration with current-profile data id/email. Optional meta must indicate success if present. |
| Moosend | `GET /v3/lists/1/1.json?apikey=…` | Replaces an unsupported query-based limit with SDK-documented path pagination. Explicit Code=0, absent/null/empty Error and a non-null Context.MailingLists collection with ID/Name are required. |
| Ayrshare | Bearer `GET /api/user` | Primary-profile refId/email, without application-error code/status fields; linked social accounts need not exist. Profile keys requiring additional primary-account context remain unknown. |
| Dynalist | JSON-token `POST /api/v1/file/list` | Read-only POST requires _code=OK, root_file_id, and non-null files with id and document/folder types. Exact InvalidToken is unverified only on HTTP 200 without contradictory success fields; TooManyRequests stays unknown/rate_limited. |
| Ticket Tailor | Basic-auth `GET /v1/overview` | Replaces customer-order retrieval with box_office_name/period/currency evidence; financial statistics are suppressed. |

Regional/environment probes stop on malformed success, redirects, throttling,
outages, transport/read errors and cancellation. Legitimate empty collections are
accepted; missing/null collections and malformed entries are not. Dynalist's
documented file-list API has no pagination, so it performs one request under the
shared bounded response reader. It does not fetch document contents. Ordinary
provider request limits still apply to these account reads.

Mocked tests cover all ten exact requests and default-policy promotions, empty
collections, optional scopes, failed/incomplete resource records, typed
application codes, contradictory errors, response suppression, non-200
success-looking bodies, transport/read failure, fallback order, final-region
success and cancellation. Earlier Dynalist and Signaturit tests now use complete
documented success fixtures.

Official evidence checked 2026-09-25:

- [Signaturit signature lists, authentication and environments](https://docs.signaturit.com/api).
- [Shippo address list, pagination, version and object schema](https://docs.goshippo.com/api-reference/addresses/list-all-addresses.md).
- [ShipEngine official OpenAPI account-settings enum](https://github.com/ShipEngine/shipengine-openapi/blob/master/openapi.yaml).
- [Easyship account and scope-specific examples](https://developers.easyship.com/reference/account_show.md).
- [Jotform current-user response and API-key authentication](https://api.jotform.com/docs/).
- [Klipfolio current-user profile](https://apidocs.klipfolio.com/reference/profile.md) and [authentication and error ambiguity](https://apidocs.klipfolio.com/reference/getting-started.md).
- [Moosend official SDK paging contract](https://github.com/moosend/api-wrappers-go/blob/master/docs/MailingListsApi.md), [request implementation](https://github.com/moosend/api-wrappers-go/blob/master/mailing_lists_api.go), [response envelope](https://github.com/moosend/api-wrappers-go/blob/master/getting_all_active_mailing_lists_with_paging_response.go), [context](https://github.com/moosend/api-wrappers-go/blob/master/context.go), and [list schema](https://github.com/moosend/api-wrappers-go/blob/master/mailing_list.go). Direct documentation had a certificate-chain failure; the official SDK supplied the contract. USER_NOT_FOUND is conservatively unknown.
- [Ayrshare primary/profile context and optional social links](https://www.ayrshare.com/docs/apis/user/profile-details.md).
- [Dynalist file-list schema and exact application-error meanings](https://apidocs.dynalist.io/).
- [Ticket Tailor overview](https://developers.tickettailor.com/docs/api/get-overview) and [authentication](https://developers.tickettailor.com/docs/intro). The overview schema is embedded in the documentation's generated page bundle.
