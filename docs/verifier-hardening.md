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

After remediation batch 33:

| Internal audit status | Patterns | Meaning |
| --- | ---: | --- |
| Reviewed | 544 | The recorded verifier contract has been reviewed/hardened. |
| Requires hardening | 0 | All actionable items in this audit queue have been addressed. |
| Blocked | 23 | Required context or a reliable validation contract is unresolved. |
| Pending review | 0 | The systematic safety assessment is complete. |
| No verifier | 535 | Detection exists without an online verifier. |

These audit statuses are distinct from runtime safety categories: 361
`read_only`, 84 `auth_only`, 99 `unsafe`, and 23 `unreviewed`. Ordinary `--verify`
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

## Remaining contract and coverage work

1. **Blocked contracts:** establish provider-owned authenticated schemas and
   required context for the 23 blocked patterns. Cloudplan, Cloverly, generic
   Google keys, Abstract, APILayer, ConfigCat SDK keys and legacy Greenhouse
   Harvest keys return unknown without requests, including under explicit opt-in.
2. **Credential-subtype routing:** remaining mixed API/webhook and OAuth detectors. Different
   key families require different verification operations; a rejection by the
   wrong API must not label the key invalid.
3. **Region and endpoint context:** self-hosted deployments, alternate Cody
   gateways and broader Grafana region coverage remain follow-ups.
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

## Remediation batch 33: ten scoped metadata contracts

Ten previously blocked patterns now have reviewed `read_only` contracts. Ordinary
`--verify` supports **445 patterns** (361 `read_only` + 84 `auth_only`), with 23
blocked patterns remaining. Support is conditional on the documented credential
family and context; it does not imply every detected key can be verified.

| Provider | Context and authenticated read |
| --- | --- |
| Mailmodo | `MAILMODO_API_KEY`, optional `MAILMODO_API_URL=https://api.mailmodo.com/api/v1`. `mmApiKey` `GET /getAllContactLists` reads list metadata, not contacts or email bodies. Requires listDetails array with id/name/created_at; contacts_count is optional, as in the provider examples, and numeric when present. No pagination is documented, so one response is byte-capped and suppressed. Empty lists are accepted. |
| Beebole | `BEEBOLE_API_KEY` infers `graphql` type; explicit `BEEBOLE_API_URL=https://app.beebole.com/graphql` is required. `BEEBOLE_CREDENTIAL_TYPE=graphql` can qualify legacy ambiguous labels but must agree with the assignment. Read-only POST body is exactly `{"query":"{ currentPerson { name email } }"}` with the raw key in `apikey`. Validates data.currentPerson name/email and rejects operation errors or nonempty/malformed permissionsErrors. `BEEBOLE_API_TOKEN` denotes incompatible legacy tokens; legacy and MCP families remain unknown without requests. |
| Caflou | `CAFLOU_ACCESS_TOKEN` and positive numeric `CAFLOU_ACCOUNT_ID`; optional `CAFLOU_API_URL=https://app.caflou.com/api/v1`. Bearer `GET /{account_id}/account_users?per=1&page=1` uses the published AccountUser schema and pagination. Requires integer id, email and active boolean per item; empty collections and inactive members are accepted. Replaces untyped account discovery; no account hopping or login/token creation. |
| Signable | `SIGNABLE_API_KEY`, optional `SIGNABLE_API_URL=https://api.signable.co.uk/v1`. Basic key:`x` `GET /settings` reads signing preferences. Requires integer http=200, setting_signature_more_info boolean and signature-format strings; false flags are valid. Error codes cannot coexist with accepted success data. No templates, envelopes, signing or notifications are created. |
| Simplesat | `SIMPLESAT_API_KEY`, optional `SIMPLESAT_API_URL=https://api.simplesat.io/api/v1`. `X-Simplesat-Token` `GET /questions?page_size=1&page=1`, requiring integer count and question id/type/required boolean. Empty results and optional questions are accepted. Replaces answer retrieval; no customer responses, survey tokens or survey emails are requested. Missing `read questions` scope stays unknown. |
| GoodDay | `GOODDAY_API_KEY` or `GOODDAY_API_TOKEN` and explicit `GOODDAY_API_URL=https://api.goodday.work/2.0`. `gd-api-token` `GET /skills` reads organization skill id/label metadata. Enterprise/other version bases are not guessed. No pagination is documented; one byte-capped array, empty allowed, is suppressed. |
| Mixmax | `MIXMAX_API_KEY` or `MIXMAX_API_TOKEN`, optional `MIXMAX_API_URL=https://api.mixmax.com/v1`. `X-API-Token` `GET /tasks?limit=1` uses the current OpenAPI contract, replacing undocumented users/me. Requires results _id/type/status, total integer and hasNext/hasPrevious booleans; optional task details are not required. Managed keys need tasks:read; missing permission remains unknown. Cursor links are never followed, and task content is suppressed. |
| Overloop | `OVERLOOP_API_KEY`, optional `OVERLOOP_API_URL=https://api.overloop.com/public/v1`. Raw Authorization key `GET /me`, JSON:API Accept/Content-Type. Requires data.id/type=users and attributes.name/email; nested errors are rejected. Optional profiles, disabled status and relationship links do not affect identity validation; no relationships are followed. |
| Worksnaps | `WORKSNAPS_API_KEY` or `WORKSNAPS_API_TOKEN` plus `WORKSNAPS_PROJECT_ID` (positive signed-32-bit integer); optional `WORKSNAPS_API_URL=https://api.worksnaps.com/api`. Basic key:`ignored` `GET /projects/{id}.xml`, XML Accept/Content-Type. Requires one complete project document with matching id, name and active/archived status. No project-wide listing, user API-token retrieval, time records or reports. |
| Apacta | `APACTA_ACCESS_TOKEN` infers Bearer; `APACTA_API_KEY` or legacy labels require explicit `APACTA_CREDENTIAL_TYPE=bearer`. UUID `APACTA_TIME_ENTRY_TYPE_ID` is required; optional `APACTA_API_URL=https://app.apacta.com/api/v1`. Bearer `GET /time_entry_types/{id}` requires success=true and matching data.id/name. Reads one type definition, not time records; no creation/update or unsupported page-size guesses. |

Apacta's `/ping` is explicitly **not** used: despite the published description
“Check if API is up and API key works,” the credential-free endpoint returned
HTTP 200 with `{"status":"ok","database":true,"searchEngine":true}`. That
response is not credential validation. The time-entry-type collection rejected
a credential-free request with 401; the supported single-resource schema comes
from the Partner OpenAPI.

Worksnaps now parses the entire XML document instead of checking for a
`<project` substring. Duplicate identity fields, extra roots, nested identity
markup, namespaces, error elements, directives, malformed XML and trailing text
are rejected. External entities are never fetched. Archived projects and normal
XML whitespace, declarations and CDATA remain valid.

Every request requires exact HTTP 200 and its typed success schema. Failures,
permission ambiguity, invalid context and unsupported deployments remain
`unknown`; responses are suppressed and capped at 1 MiB. No redirects or
response-supplied links are followed. Mapping-local JSON/YAML and bounded env/INI
context contribute to cache identity, including platform/credential type.

Evidence checked 2026-09-28:

- Mailmodo [provider-hosted developer entry point](https://www.mailmodo.com/developers/) embeds Stoplight project `cHJqOjczODk3`; [published contact-list operation, authentication and examples](https://api.stoplight.io/v1/projects/cHJqOjczODk3/nodes/b96e0fec94c2b-get-all-contact-lists). The operation has no pagination parameters; one documented example omits contacts_count.
- Beebole [current GraphQL authentication, query, legacy incompatibility, errors and permissionsErrors](https://beebole.com/help/api/introduction). The provider explicitly distinguishes new-platform API keys, legacy Basic tokens and MCP Bearer tokens.
- Caflou [provider documentation link](https://www.caflou.com/education/how-to-obtain-access-token-for-api-integromat-or-zapier), [published Postman documentation](https://documenter.getpostman.com/view/4786951/RWMFrTQC) and its linked [OpenAPI account_users schema, Bearer authentication and per/page parameters](https://app.caflou.com/api/v1/i/docs/openapi/v1/openapi.yaml).
- Signable [archived official SDK directing users to the current portal](https://github.com/signable/signable-sdk-php/blob/master/README.md), [settings schema](https://developers.signable.app/openapi/settings/listsettings.md) and [current server/Basic authentication](https://developers.signable.app/openapi.md).
- Simplesat [official help link](https://help.simplesat.io/en/articles/3457141-do-you-have-an-open-api) and [published V1 OpenAPI, question schema, scopes and pagination](https://developer.simplesat.io/api/Simplesat%20API%20(v1)%20OpenAPI.yaml).
- GoodDay [API versions](https://www.goodday.work/developers/api-v2), [header authentication](https://www.goodday.work/developers/api-v2/connect), and [organization skills schema](https://www.goodday.work/developers/api-v2/system).
- Mixmax [current task OpenAPI, read scope, schema and limit](https://developer.mixmax.com/reference/listtasks.md), updated 2026-09-24. The provider identifies its OpenAPI as the source of truth for this reference.
- Overloop [authentication, current-user route and JSON:API user schema](https://apidoc.overloop.com/).
- Worksnaps [provider-linked API overview, Basic authentication and read semantics](https://api.worksnaps.com/api_docs/api_overview.html), [HTTPS Swagger route and XML project example](https://api.worksnaps.com/api_docs/worksnaps.json). User details can include an API token, so that alternative was rejected.
- Apacta [current Partner OpenAPI, Bearer authentication and single time-entry-type response](https://apidoc.apacta.com/partner.yaml). Public ping behavior was checked independently of the documentation.

Credential-free checks returned 401 for Mailmodo, Caflou, Signable, Mixmax,
Overloop and Worksnaps; 403 for Simplesat and GoodDay; Beebole returned HTTP 200
with empty data, permissionsErrors and an InvalidCSRFToken error. These checks
establish rejection boundaries, not live-key success rates.

Mocked regression coverage includes all ten contracts, policy promotion, exact
requests and credential placement, typed and nested-error schemas, legitimate
empty/false/optional metadata, permission failures, transport/read failures,
cancellation/timeouts, response caps, unsupported platforms/hosts, record
isolation, cache identity and JSON/YAML/base64 scanner propagation. Live
benchmarks, broader format coverage and a refreshed TruffleHog comparison remain
deferred.

## Remediation batch 32: ten blocked-provider dispositions

This batch promotes five documented contracts to `read_only` and replaces five
unproven probes with explicit no-network hooks. There are now **435 ordinary
verification patterns** (351 `read_only` + 84 `auth_only`) and **33 blocked
patterns**. Blocked hooks remain `unreviewed`; opting in permits invoking the
hook but cannot supply an absent provider contract or credential context.

### Five supported contracts

| Provider | Context and authenticated read |
| --- | --- |
| PandaDoc | `PANDADOC_API_KEY` uses `Authorization: API-Key`; `PANDADOC_ACCESS_TOKEN` uses Bearer. Optional `PANDADOC_CREDENTIAL_TYPE=api_key` or `bearer` must agree with the assignment; client-secret labels make no request. Optional `PANDADOC_API_URL=https://api.pandadoc.com`. `GET /public/v1/documents/folders?count=1&page=1` replaces the undocumented current-member probe; validates results uuid/name/date_created and has_folders/has_items booleans. Empty folders and false flags accepted. Legacy ambiguous labels retain API-key routing, with ambiguous rejections unknown. |
| Appointedd | `APPOINTEDD_API_KEY`, optional `APPOINTEDD_API_URL=https://api.appointedd.com/v1`. `X-API-KEY` `GET /resources/groups?limit=1` replaces the undocumented availability route; validates integer total and data id/name. Empty groups accepted. No booking or availability computation. |
| Flexport | `FLEXPORT_ACCESS_TOKEN` or `FLEXPORT_API_KEY` supplies bearer context; explicit `FLEXPORT_API_URL=https://api.flexport.com` is required. `FLEXPORT_CREDENTIAL_TYPE=bearer` must agree with labels. `GET /network/me/companies` with `Flexport-Version: 2` reads own-company metadata, validates the version-2 response envelope, company object/id/name and editable boolean. OAuth client secrets and detected `shltm_` logistics keys remain unknown without requests. No token exchange, webhook listing or product-host fallback. |
| Gyazo | `GYAZO_ACCESS_TOKEN`, optional `GYAZO_API_URL=https://api.gyazo.com`; explicit `GYAZO_CREDENTIAL_TYPE`, if supplied, must be `bearer`. Bearer `GET /api/users/me` validates nested user.uid/email. Optional name/profile image metadata may be absent, empty or null. Client-secret labels make no request. No image lookup, search or upload. |
| HappyScribe | `HAPPYSCRIBE_API_KEY`, optional `HAPPYSCRIBE_API_URL=https://www.happyscribe.com/api/v1`. Bearer `GET /organizations` replaces private transcription listing. Requires organization id/name/role/createdAt/updatedAt; empty memberships and non-admin roles are accepted. Staff-only metadata is not required. No server pagination is documented; one byte-capped response is suppressed. No transcription processing. |

These providers inherit mapping-local JSON/YAML context, bounded env/INI
correlation, whole-token trailing boundaries, exact cloud-base allowlists and
context-sensitive cache keys. The added Flexport assignment detector covers
32–1,000-character token literals; the existing 512-byte env/INI correlation
bound still applies, so longer records may need structured mapping context.
All requests require HTTP 200 with typed success evidence, suppress response
bodies, reject oversized responses, and never follow redirects or response links.
Permission, quota, product, deployment and credential-family ambiguity stays
`unknown`.

### Five explicit no-request dispositions

| Pattern | Evidence and remaining blocker |
| --- | --- |
| Generic Google API key | Keys can have API and application restrictions; a Gemini model-list rejection cannot establish validity across Google products. Product/restriction context and a supported validation contract are still required. The generic hook no longer sends keys to Gemini. |
| Abstract API | Official docs explicitly say every product has a distinct key. The old exchange-rate lookup selects an arbitrary product and performs a data operation. A product-specific, non-workload authentication contract remains unproven. |
| APILayer | Marketplace Number Verification has subscription/usage plans; its countries route is not established as generic key introspection. Product subscription and an authoritative verification response contract remain unresolved. |
| ConfigCat SDK key | Configuration downloads consume plan allowances and require matching CDN/data-governance settings. Public Management API uses a separate Basic credential pair, not an SDK key. The hook no longer downloads configuration or guesses the global CDN. |
| Legacy Greenhouse Harvest key | Provider announces v1/v2 removal on 2026-08-31 and migration to v3. The old Basic-auth user-list probe is removed. Current OAuth credential-family support requires separate work; legacy detection is retained. |

All five remain detectable, enforce complete trailing credential boundaries, and
return `unknown` with no network request even under unreviewed/unsafe opt-ins.

Evidence checked 2026-09-28:

- PandaDoc [folder route, pagination, schemas and authentication](https://developers.pandadoc.com/reference/list-documents-folders.md).
- Appointedd [resource-group OpenAPI](https://developers.appointedd.com/reference/get-resource-groups.md) and [API-key authentication](https://developers.appointedd.com/reference/getting-started.md).
- Flexport [API credentials, bearer keys/tokens and exchange limits](https://developers.flexport.com/tutorials/using-api-credentials), [V2 own-company schema](https://apidocs.flexport.com/v2/tag/Company), and the documentation's [published versioned OpenAPI state](https://apidocs.flexport.com/redocly-state-f6204472147f61321db1c6aae9e930031a50c3b0.js).
- Gyazo [authenticated-user response](https://gyazo.com/api/docs/user) and [OAuth access-token authentication](https://gyazo.com/api/docs/auth).
- HappyScribe [organization response and role-specific fields](https://dev.happyscribe.com/sections/product/#organizations-list-organizations) and [authentication](https://dev.happyscribe.com/sections/general/#authentication).
- Google [API-key types, restrictions and management credentials](https://cloud.google.com/docs/authentication/api-keys).
- Abstract [distinct product keys, data operations and quota errors](https://docs.abstractapi.com/api/ip-intelligence.md).
- APILayer [Number Verification subscription and usage plans](https://apilayer.com/marketplace/number_verification-api).
- ConfigCat [download allowances](https://configcat.com/docs/subscription-plan-limits/), [CDN data-governance selection](https://configcat.com/docs/advanced/data-governance/), and [separate management authentication](https://configcat.com/docs/api/reference/configcat-public-management-api/).
- Greenhouse [legacy removal notice and migration link](https://developers.greenhouse.io/harvest.html).

Credential-free reads returned 401 for PandaDoc, Flexport, Gyazo and HappyScribe,
and 403 for Appointedd. These checks confirm an authentication boundary, not
successful verification with a real key; the success schemas come from the
provider contracts above.

Regression tests cover all ten dispositions: policy and opt-in behavior, exact
requests, typed/error responses, nested errors, false/zero/empty values,
suppression, transport/read failures, cancellation/timeouts and response caps.
Additional coverage checks family-specific authentication/cache identity,
conflicting or isolated context, unsupported hosts, and JSON/YAML/base64 scanner
propagation. Contracts were tested with mocked responses, not live customer keys.
Controlled benchmarks, broader format coverage and the refreshed TruffleHog
comparison remain deferred.

## Remediation batch 31: ten context and metadata contracts

Ten more blocked patterns now support ordinary `--verify` as `read_only`.
The mapping-local and bounded env/INI context rules from batch 30 also apply
here. Explicit credential-family assignments participate in conflict detection
and cache identity. Unsupported families remain detectable and return `unknown`.

| Provider | Context and authenticated operation |
| --- | --- |
| Hightouch | `HIGHTOUCH_API_KEY`; optional `HIGHTOUCH_API_URL=https://api.hightouch.com/api/v1`. Bearer `GET /events/domains?limit=1&offset=0` replaces the undocumented workspace listing. Requires data array with string id/name and numeric workspaceId. |
| Deno Deploy | Current `ddo_` organization tokens use Bearer `GET https://api.deno.com/v2/domains?limit=1`; optional `DENO_API_URL` must match that base. Requires domain id, organization_id, domain and boolean is_validated. Legacy `ddp_`/`ddw_` tokens make no request. |
| ngrok | `NGROK_API_KEY` or explicit `NGROK_CREDENTIAL_TYPE=api`; `NGROK_AUTHTOKEN` conflicts with API context. Optional `NGROK_API_URL=https://api.ngrok.com`. Bearer `GET /agent_ingresses?limit=1`, ngrok-version 2; typed ingress metadata and uri. Untyped prefixed tokens make no request. |
| ConvertAPI | `CONVERTAPI_MASTER_TOKEN` or explicit `CONVERTAPI_CREDENTIAL_TYPE=master`; ordinary `CONVERTAPI_API_TOKEN` is incompatible. Optional `CONVERTAPI_API_URL=https://v2.convertapi.com`. Bearer `GET /user`; requires Active boolean, Email and integer conversion quotas. Inactive accounts and exhausted quotas are accepted. |
| Voicegain | `VOICEGAIN_JWT`, explicit `VOICEGAIN_API_URL=https://api.voicegain.ai/v1` and UUID `VOICEGAIN_SA_CONFIG_ID`. Bearer `GET /sa/config/{id}`; matching saConfId, name and builtIn boolean. Edge deployments and missing context make no request. |
| Stitch Data | `STITCH_API_TOKEN` in `ac_` Connect family, explicit `STITCH_API_URL=https://api.stitchdata.com` and positive numeric `STITCH_CLIENT_ID`. Bearer `GET /v4/{client_id}/extractions?page=1`; validates page/total and matching client_id, source_id, job_name entries. Provider caps this page at 100. No extraction is started and no source credentials are fetched. |
| Qubole | `QUBOLE_API_TOKEN`, explicit `QUBOLE_API_URL` selecting `https://api.qubole.com`, `https://in.qubole.com`, `https://eu.qubole.com`, `https://us.qubole.com` or `https://gcp.qubole.com`. X-AUTH-TOKEN `GET /api/v1.2/qcuh_usages` for the current UTC month with group_by=month; validates month and numeric spot/ondemand usage. Reads precomputed usage, not account cloud credentials or a compute job. |
| PayMongo | `PAYMONGO_SECRET_KEY`, live or test; optional `PAYMONGO_API_URL=https://invoices-api.paymongo.com`. Basic-auth `GET /v1/invoices/settings` requires data.approvals_enabled boolean. Replaces signing-secret-bearing webhook listing. Product/permission errors stay unknown. |
| Canny | `CANNY_API_KEY`; optional `CANNY_API_URL=https://canny.io/api/v1`. Read-only `POST /groups/list` with apiKey and limit=1; validates items id/name/urlName and hasNextPage boolean. Replaces private-board token retrieval. |
| ScrapingBee | `SCRAPINGBEE_API_KEY`; optional `SCRAPINGBEE_API_URL=https://app.scrapingbee.com/api/v1`. Bearer `GET /usage` requires integer quota/concurrency fields. No scrape target is supplied. Exhaustion, bans and ambiguous authentication errors remain unknown. |

All ten require HTTP 200 and typed success evidence, accept documented empty
collections and false/zero values, suppress responses, and stop on ambiguous
errors. Responses are byte-capped; redirects and response-supplied pagination
links are never followed. Exact supported bases (with optional trailing slash)
are required; arbitrary/self-hosted endpoints are not contacted.

Evidence checked 2026-09-28:

- Hightouch [published OpenAPI](https://api.hightouch.io/api/swagger.json) and [API guide](https://hightouch.com/docs/developer-tools/api-guide).
- Deno [V2 OpenAPI, including organization access-token authentication](https://api.deno.com/v2/openapi.json).
- ngrok [agent ingress contract](https://ngrok.com/docs/api-reference/agentingresses/list.md) and [official SDK](https://github.com/ngrok/ngrok-api-go/blob/main/agent_ingresses/client.go).
- ConvertAPI [user contract](https://www.convertapi.com/doc/user) and [authentication](https://www.convertapi.com/doc/auth).
- Voicegain [official SA API client](https://github.com/voicegain/python-sdk/blob/master/voicegain_speech/api/sa_api.py), [configuration model](https://github.com/voicegain/python-sdk/blob/master/voicegain_speech/models/speech_analytics_config.py) and [cloud base](https://github.com/voicegain/python-sdk/blob/master/voicegain_speech/configuration.py).
- Stitch [Connect API authentication, extraction status and pagination](https://www.stitchdata.com/docs/developers/stitch-connect/api).
- Qubole [monthly QCU usage, schemas and supported deployments](https://docs.qubole.com/en/latest/rest-api/account_api/view-qcuh-monthly-usage.html).
- PayMongo [invoice settings contract](https://docs.paymongo.com/reference/list_invoices_settings.md).
- Canny [group listing and authentication](https://developers.canny.io/api-reference).
- ScrapingBee [usage endpoint and Bearer authentication examples](https://www.scrapingbee.com/documentation/).

Mocked regression contracts cover all ten providers, exact requests, success/error
schemas, credential-family and endpoint gating, context/cache isolation, response
suppression, transport/read failures, cancellation, timeouts and oversized bodies.
This is contract validation, not live customer-credential reliability measurement.
The previously recorded benchmarking, broader format coverage and TruffleHog
comparison priorities remain deferred.

## Remediation batch 30: ten context-dependent providers

Ten previously blocked patterns now have supported cloud contracts under ordinary
`--verify`. This adds context-aware capability, not a guarantee of successful
verification when context is absent. Detection remains available for incomplete,
unsupported and self-hosted configurations; those cases return `unknown`.

Provider-qualified context assignments are read from the same JSON/YAML mapping
as the credential, including decoded scalar views. Env/INI fragments correlate
within 512 bytes without crossing blank lines, sections, document boundaries,
bracket/brace boundaries or another credential of the same family. Conflicting
context values prevent requests. Context participates in the verification cache
identity, so the same credential in different accounts/deployments is not cached
as one request. Context capture does not change raw human-output formatting.

| Pattern | Accepted context and authenticated read |
| --- | --- |
| Checkly | `CHECKLY_ACCOUNT_ID` (UUID), optional `CHECKLY_API_URL=https://api.checklyhq.com`. Official CLI `GET /next/accounts/{id}` with Bearer auth and `X-Checkly-Account`; response id must match and name/runtimeId must be strings. |
| SaladCloud | `SALAD_ORGANIZATION_NAME` or `SALAD_ORGANIZATION`; optional `SALAD_API_URL=https://api.salad.com/api/public`. Organization GPU classes, authenticated with `Salad-Api-Key`. Provider schema caps collection at 100; validates item id/name and accepts an empty list. No resource creation or inference. |
| Scaleway | `SCW_ACCESS_KEY` paired with `SCW_SECRET_KEY`; optional `SCW_API_URL=https://api.scaleway.com`. Single IAM `/iam/v1alpha1/api-keys/{access_key}` metadata, matching access_key and a user or application identity. The SDK states secret_key is not returned by this read; responses are suppressed regardless. |
| Semaphore CI | `SEMAPHORE_ORGANIZATION`, optional matching `SEMAPHORE_API_URL=https://{organization}.semaphoreci.com`. `GET /api/v1alpha/agents?page_size=1`, Authorization Token; validates agent state/name/type and accepts empty inventory. Replaces the unrelated Semaphore SMS (`semaphore.co`) request. |
| LangSmith | `LANGSMITH_ENDPOINT`/`LANGCHAIN_ENDPOINT` selects exactly GCP US, EU, APAC or AWS US cloud base. Default is documented GCP US. `LANGSMITH_WORKSPACE_ID`/`LANGCHAIN_WORKSPACE_ID` supplies `X-Tenant-Id` and is required for service keys in this verifier. `GET /api/v1/settings` validates id/display_name/created_at and matches supplied workspace id. No cross-region guessing. |
| Crowdin | Default Crowdin.com or `CROWDIN_ORGANIZATION` for `https://{organization}.api.crowdin.com/api/v2`; optional `CROWDIN_BASE_URL` must match. `GET /user` validates data.id integer and username. No fallback to a different organization. |
| GrowthBook | `GROWTHBOOK_API_HOST` or `GROWTHBOOK_API_URL` must explicitly identify `https://api.growthbook.io/api`. Only `secret_` keys; `GET /v1/projects?limit=1&offset=0`, typed project metadata and pagination. Client/SDK key detection retained, with no verification request. |
| Flagsmith | `FLAGSMITH_API_URL` must explicitly identify `https://edge.api.flagsmith.com/api/v1` or `https://api.flagsmith.com/api/v1`. Only `ser.` server environment keys; `GET /flags/` validates enabled booleans and feature names. No identity argument, trait updates or identity creation. Endpoint has no pagination; one byte-capped response, suppressed completely. |
| Airbyte | `AIRBYTE_API_URL=https://api.airbyte.com/v1` and `AIRBYTE_ACCESS_TOKEN`, or `AIRBYTE_CREDENTIAL_TYPE=bearer` for legacy ambiguous token labels. Client-secret labels are recognized as incompatible, including conflicts with a bearer declaration. One workspace metadata page, limit=1; validates workspaceId/name/dataResidency. Does not exchange client secrets or call self-managed hosts. |
| GetResponse | Default retail base or explicit `GETRESPONSE_API_URL=https://api3.getresponse360.pl/v3` / `https://api3.getresponse360.com/v3` with `GETRESPONSE_DOMAIN` for `X-Domain`. `GET /accounts?fields=accountId,email` requests sparse identity. Domain without a MAX base is ambiguous and makes no request. |

All requests require exact HTTP 200 and typed success fields, suppress response
bodies, retain permission/region/subtype ambiguity as unknown, reject oversized
responses, and never follow response links or redirects. Missing, empty,
conflicting, malformed or unsupported endpoint context cannot cause a request to
an arbitrary host. A trailing slash on a supported base is accepted; alternate
schemes, ports, userinfo, queries and fragments are not.

Evidence checked 2026-09-28:

- Checkly CLI [account routes/schema](https://github.com/checkly/checkly-cli/blob/main/packages/cli/src/rest/accounts.ts), [authentication and account header](https://github.com/checkly/checkly-cli/blob/main/packages/cli/src/rest/api.ts), [production API base](https://github.com/checkly/checkly-cli/blob/main/packages/cli/src/services/config.ts).
- SaladCloud [organization GPU classes OpenAPI, authentication and maximum collection size](https://docs.salad.com/reference/saladcloud-api/organizations/list-gpu-classes.md).
- Scaleway [official IAM SDK APIKey model and GetAPIKey contract](https://github.com/scaleway/scaleway-sdk-go/blob/main/api/iam/v1alpha1/iam_sdk.go).
- Semaphore [API reference: authentication and agent pagination/schema](https://docs.semaphore.io/reference/api).
- LangSmith [deployment/workspace/key configuration](https://docs.langchain.com/langsmith/create-account-api-key.md), [live OpenAPI settings schema and authentication headers](https://api.smith.langchain.com/openapi.json).
- Crowdin [official client API domain and Enterprise routing](https://github.com/crowdin/crowdin-api-client-js/blob/master/src/core/index.ts), [authenticated-user method and models](https://github.com/crowdin/crowdin-api-client-js/blob/master/src/users/index.ts).
- GrowthBook [project pagination, schemas, cloud base and secret-key authentication](https://docs.growthbook.io/api/projects/operation/listProjects.md).
- Flagsmith [environment-key authentication](https://github.com/Flagsmith/flagsmith/blob/main/api/environments/authentication.py), [SDK flag read and no-pagination contract](https://github.com/Flagsmith/flagsmith/blob/main/api/features/views.py), [flag response serializer](https://github.com/Flagsmith/flagsmith/blob/main/api/features/serializers.py).
- Airbyte [official workspace client](https://github.com/airbytehq/airbyte-api-python-sdk/blob/main/src/airbyte_api/workspaces.py), [workspace response JSON aliases](https://github.com/airbytehq/airbyte-api-python-sdk/blob/main/src/airbyte_api/models/workspaceresponse.py), [cloud server selection](https://github.com/airbytehq/airbyte-api-python-sdk/blob/main/src/airbyte_api/sdkconfiguration.py).
- GetResponse [retail/MAX deployment and tenant requirements](https://apidocs.getresponse.com/v3/index.md), [OpenAPI account schema and sparse fields parameter](https://apireference.getresponse.com/open-api.json).

Regression tests cover all ten providers' exact requests, policy promotion,
schemas, empty collections, malformed/error bodies, non-200 responses, response
suppression, transport/read failures and response caps; context order, conflicts,
cache identity, unsupported hosts and credential families; JSON/YAML record and
document isolation; and decoded/base64 scanner-to-verifier context propagation.

Deferred work remains explicitly tracked: controlled live reliability and labeled
accuracy benchmarks, known modern credential-format gaps, and a refreshed
provider-level TruffleHog comparison. Further blocked-provider work should
continue in batches of at least ten without promoting unproven contracts.

## Remediation batch 29: disposition of the final thirteen hardening items

This batch hardens eleven supported contracts (eight `read_only`, three
`auth_only`) and explicitly blocks two unproven contracts. The requires-hardening
queue is now empty; **58 blocked patterns still require further contract or
context work**. This is not a claim that every provider or key family can now be
verified.

| Provider | Disposition and contract |
| --- | --- |
| ComplyAdvantage | `read_only`: documented `/users` status=success/content.data array with integer id and string email/name. Fixed EU/US/APAC authorization-only fallback. The provider documents no pagination for this endpoint; one response per attempted deployment is byte-capped, never followed or expanded. |
| Sourcegraph Cody | `read_only`: official gateway client `/v1/limits` feature map with integer limit/usage, interval and optional nullable timestamp expiry. Empty maps and signed integer limits accepted. The public host returned 404 without credentials during review; deployment/service availability remains unknown, never invalid. Alternate gateways need trusted endpoint context. |
| Twitter/X | `read_only`: `/2/usage/credits` replaces the billable post lookup. Typed total/prepaid/free balances and free_grants amount entries; negative prepaid balances, zero balances, and empty grants accepted. No post or public user lookup. Subscription and OAuth subtype ambiguity remain unknown. |
| Sendbird organization | `read_only`: authenticated `/api/v2/organization_members/predefined_roles` replaces application listing, which can return additional API credentials. Requires a string array. No application or token details fetched. |
| Atera | `read_only`: first agent page, itemsInPage=1, requires integer TotalItemCount and positive integer AgentID for each item. Empty inventory accepted; all device data suppressed. IP allowlists and per-domain token permissions remain unknown. |
| BombBomb | `auth_only`: BBCore's multipart POST `ValidateJsonWebToken` method, with jwt credential, replaces the unproven V2 user probe. Requires status=success and info user/client identity, accepting camelCase and snake_case. Session/JWT payloads suppressed. OAuth and legacy service rejection remain unknown. |
| NVIDIA NGC | `auth_only`: non-nvapi detected keys use SDK's Basic `$oauthtoken` exchange at `authn.nvidia.com/token?service=ngc`, without organization/team scopes. Requires a token string and positive integer expires_in when supplied. Returned token is suppressed and never used for follow-up requests. nvapi-prefixed keys route to scoped-key introspection. |
| NVIDIA NVAPI | `auth_only`: SDK's form POST `/v3/keys/get-caller-info` with credentials. Requires SUCCESS requestStatus, orgName, string products array, and PERSONAL_KEY with userId or SERVICE_KEY. Empty products and personal roles are accepted; service keys need no user. Incompatible formats make no request. |
| ProdPad | `read_only`: published OpenAPI `/v1/tags` string id/tag array. Endpoint documents no server pagination; reads one byte-capped metadata response and suppresses it. No idea/feedback content fetched. Empty tag collections accepted; scope errors unknown. |
| Vyte | `read_only`: documented `/v2/events?limit=1`, raw Authorization key, JSON. Requires event _id, string title (including empty), and confirmed.flag. Empty arrays and unconfirmed events accepted; participant details, messages and third-party metadata suppressed. |
| AlienVault/LevelBlue OTX | `read_only`: `/api/v1/user/me` requires integer user_id and username. The provider SDK and credential-free public profile establish the identity field names; unauthenticated current-user lookup returns 403. No public profile is used by the verifier. Forbidden responses remain unknown. |
| Cloudplan | **Blocked**: `/api/user/me` rejects unauthenticated requests but a current success schema and session/key contract could not be established. The cloudplan.biz website had an expired certificate. Detector retained; hook now returns unknown without any request, even with unreviewed opt-in. |
| Cloverly | **Blocked**: provider material establishes purchase-capable key families but no authenticated account success schema for the old probe. Public SDK methods are primarily estimates/purchases; no speculative purchase or computation is used as verification. Detector retained; hook returns unknown without requests under opt-in too. |

All thirteen patterns now enforce trailing whole-credential boundaries. Direct
TWITTER_BEARER_TOKEN assignments, existing percent-encoded X tokens, and LevelBlue
OTX context are recognized. Existing heuristic key-family coverage is retained;
this does not establish exhaustive modern-format detection.

The shared response reader now reads at most the existing 1 MiB limit plus one
sentinel byte and rejects oversized responses **before classification**. Previously,
a valid JSON prefix followed by content beyond the cap could be mistaken for a
complete response. This matters for metadata endpoints without documented server
pagination. Exactly-at-limit responses still work; oversized responses never
authenticate or trigger regional retries. Response-output formatting is unchanged.

Mocked contracts cover all thirteen dispositions, ordinary policy and blocked
opt-ins, exact requests and credential placement, personal/service/legacy routing,
typed success/error schemas, empty/zero/negative-prepaid values, non-200 bodies,
redirects, regional stop conditions, cancellation, transport/read errors,
whole-token boundaries, response suppression and exact byte-cap boundaries.

Evidence checked 2026-09-28:

- [ComplyAdvantage regional hosts, authentication and user response](https://docs.complyadvantage.com/#get-users).
- [Sourcegraph published gateway client and LimitStatus schema](https://github.com/sourcegraph/sourcegraph-public-snapshot/blob/main/internal/codygateway/client.go). This is a published source snapshot, not evidence that every current deployment exposes the route.
- [X credit-balance endpoint, Bearer authentication and success/error schema](https://docs.x.com/x-api/usage/get-usage-credits.md), [usage endpoint overview](https://docs.x.com/x-api/usage/introduction.md).
- [Sendbird predefined role response](https://sendbird.com/docs/chat/platform-api/v3/organization/managing-roles/list-predefined-roles), [organization authentication](https://sendbird.com/docs/chat/platform-api/v3/organization/organization-overview). Credential-free role lookup returned 403.
- [Atera API authentication, domain permissions, IP restrictions and AgentID examples](https://support.atera.com/hc/en-us/articles/219083397-API). The API documentation UI requires authentication; credential-free bounded agent requests returned 401.
- [BombBomb BBCore JWT validation and identity handling](https://github.com/bombbomb/BBCore/blob/master/src/modules/bbcore.auth.js), [multipart request construction](https://github.com/bombbomb/BBCore/blob/master/src/modules/bbcore.api.js), [HTTPS API host](https://github.com/bombbomb/BBCore/blob/master/src/bbcore.js).
- [NVIDIA key-family guide](https://docs.nvidia.com/ngc/gpu-cloud/ngc-user-guide/index.html), [NGC SDK 4.36.6](https://pypi.org/project/ngcsdk/4.36.6/), [published package metadata](https://pypi.org/pypi/ngcsdk/4.36.6/json), [NGC request-status enum](https://api.ngc.nvidia.com/v3/api-docs). Inspected wheel files: `ngcbase/api/authentication.py`, `ngcbase/constants.py`, `organization/api/users.py`, and `organization/data/uis/SakCallerInfoResponse.py`. Wheel SHA-256: `8cf4ce3bd071b3d2e24d40f2c66abc2c2b49022b53d400a2eb9fe6018fe3f343`. The SDK explicitly says scoped keys do not use normal user lookup; its caller-info schema has no mandatory top-level id. Credential-free legacy exchange returned 401.
- [ProdPad's official API documentation link](https://help.prodpad.com/article/660-working-with-the-prodpad-api), [OpenAPI 1.1.4 tags and authentication](https://api.swaggerhub.com/apis/ProdPad/prodpad/1.1.4).
- [Vyte event limit, array response and schema](https://developer.vyte.in/reference/events/), [authentication](https://developer.vyte.in/reference/#authentification). User-list alternatives can return connected-account tokens and were not selected.
- [OTX official SDK user lookup](https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py), [provider public identity schema](https://otx.alienvault.com/api/v1/user/AlienVault), [current-user auth boundary](https://otx.alienvault.com/api/v1/user/me).
- Cloudplan: credential-free `https://api.cloudplan.biz/api/user/me` returned 401; the website at `https://cloudplan.biz/` failed certificate validation. No certificate-validation bypass was used.
- [Cloverly provider documentation](https://docs.cloverly.com/), [official Python SDK resource inventory](https://github.com/cloverly/cloverly-python-module/tree/main/cloverly/resources). Credential-free account/offset-type endpoints returned 403, which alone does not establish a successful authentication contract.

## Remediation batch 28: ten regional and credential-context verifiers

Nine verifiers are now `read_only`; Vagrant Cloud is `auth_only`. Every probe
requires HTTP 200 and its success schema, suppresses the entire response, and
preserves scope, deployment, legacy-family and subscription ambiguity as unknown.
Grafana permission text and API-Sports token error substrings no longer establish
authentication or invalidity. No pagination links or response-supplied hosts are
followed. All responses use the shared byte cap.

| Provider | Contract and supported scope |
| --- | --- |
| Grafana Cloud | Canonical `www.grafana.com/api/v1/tokens?region=us&pageSize=1` returns typed id/accessPolicyId/name metadata. Fixed US/EU/AU fallback only on 401/403; other regions remain unknown. Empty token inventories accepted. No token creation or token-value retrieval. |
| fal.ai | Authenticated `/v1/account/billing` replaces the model catalog. Requires the documented account username; no credit expansion. Admin-scope requirements mean inference-only keys can remain unknown. |
| Salesforce | Production/sandbox OIDC userinfo with string sub/user_id/organization_id. Only authorization failures try the second host; Bad_OAuth_Token remains ambiguous. Custom org hosts and scope restrictions remain unknown. |
| API-Sports | Existing football `/status` request now requires get=status, results=1, empty errors, account email, subscription plan, and nonnegative integer current/limit_day counters. Both empty-array and empty-object errors accepted. Optional active metadata is ignored, including legacy string representations; inactive subscriptions and zero quotas accepted. RapidAPI and other product keys remain ambiguous. |
| Tray.io | Public/optional-auth connector catalog replaced by authenticated `/core/v1/workspaces?first=1`. Requires typed pagination booleans and id/name/type for returned elements; documented omitted elements accepted. Fixed US/EU/APAC authorization-only fallback; Embedded and RBAC scope differences remain unknown. |
| Vagrant Cloud | Official Ruby SDK host `vagrantcloud.com`, `GET /api/v2/authenticate`, Bearer auth, typed user.username identity consumed by the SDK account loader. Migration messages, empty objects, redirects, HTML, and non-200 statuses remain unknown. No HCP token issuance or refresh. |
| Percy | Corrects header to `Authorization: Token token=…`. Requires the documented single project object with id/type/name/slug/full-slug and boolean publicly-readable; public project-list arrays cannot authenticate. Optional enabled state does not gate success. |
| Pepipost/Netcore | Migrates to V6 Bearer `/suppressions/global/domain?limit=1`. Typed domain/created/modified/status entries, including empty arrays. Fixed non-EU/EU authorization-only fallback. Legacy-key and master-key subaccount requirements remain unknown. |
| Cliengo | Current sk_live_/sk_test_ tokens use fixed production/stage Connect hosts and `/v1/users/me`, requiring id/email. Existing UUID detections retained without network requests because a current legacy contract is unproven. JWT detection remains a follow-up. |
| Data.gov | Retired USDA endpoint replaced by participating-agency NLR `/api/alt-fuel-stations/v1.json?limit=0`. Requires a nonnegative total, station locator URL, and empty station array. Retrieves only metadata; gateway restrictions remain unknown. |

All ten enforce trailing credential boundaries, including punctuation endings.
Percy now recognizes direct PERCY_TOKEN assignments and prefixed tokens. Cliengo
adds contextual live/test tokens while preserving legacy detections. These are
bounded detection heuristics, not claims of exhaustive credential-format coverage.

Mocked regressions cover exact requests and ordinary verification policy, every
success schema, public fallback, error envelopes, non-200 success-like responses,
empty/inactive metadata, family routing, regional retries and stop conditions,
cancellation, transport/read failures, response caps and whole-token boundaries.
Credential-free requests to fal, Vagrant, Percy, API-Sports and NLR returned
401/403 authentication errors; no real credentials were used.

Official evidence checked 2026-09-28:

- [Grafana Cloud token metadata, regions and pagination](https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/).
- [fal billing schema and admin-key authentication](https://fal.ai/docs/platform-apis/v1/account/billing.md).
- Salesforce [production](https://login.salesforce.com/.well-known/openid-configuration) and [sandbox](https://test.salesforce.com/.well-known/openid-configuration) discovery advertise userinfo endpoints and identity claims. The developer reference returned HTTP 403.
- [API-Sports documentation entry](https://api-sports.io/documentation/football/v3.json) identifies the [football OpenAPI reference](https://api-sports.io/public/documentations/football-v3.yaml), which remained HTTP 403 during this review. The provider's SDK repository supplies the [status envelope](https://github.com/api-sports/api-sports/blob/master/src/API-Football.SDK/Models/Status.cs), [account fields](https://github.com/api-sports/api-sports/blob/master/src/API-Football.SDK/Models/Account.cs), [subscription fields](https://github.com/api-sports/api-sports/blob/master/src/API-Football.SDK/Models/Subscription.cs), and [integer usage counters](https://github.com/api-sports/api-sports/blob/master/src/API-Football.SDK/Models/Requests.cs). Credential-free `/status` confirmed the error envelope and authentication requirement.
- [Tray OpenAPI workspace schema and required auth](https://tray.ai/documentation/files/openapi/trayapi.yaml), [regional host allowlist](https://tray.ai/documentation/platform/enterprise-core/organisation-management/regional-hosting.md).
- [Vagrant official SDK host and validation method](https://github.com/hashicorp/vagrant_cloud/blob/main/lib/vagrant_cloud/client.rb), [account loader's user.username contract](https://github.com/hashicorp/vagrant_cloud/blob/main/lib/vagrant_cloud/account.rb), and [official identity fixtures](https://github.com/hashicorp/vagrant_cloud/blob/main/spec/unit/vagrant_cloud/account_spec.rb). The client method's empty-Hash comment conflicts with its account loader and tests; the verifier follows the latter. The endpoint still rejects unauthenticated requests; this does not establish full service availability after migration.
- [Percy project-specific response versus public fallback and header syntax](https://www.browserstack.com/docs/percy/api-reference/projects), [official client authentication](https://github.com/percy/cli/blob/master/packages/client/src/client.js).
- [Netcore V6 domain suppression schema, pagination, regional hosts and auth](https://emaildocs.netcore.ai/reference/get-suppression-domain-1.md).
- [Cliengo current OpenAPI hosts, key prefixes and user schema](https://developers.cliengo.com/openapi.json).
- [NLR station metadata, limit=0 and required key](https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/all/), [API key usage](https://developer.nlr.gov/docs/api-key/), [Data.gov participating APIs](https://api.data.gov/docs/).

## Remediation batch 27: ten usage, inventory and current-account verifiers

All ten are now `read_only`. Success requires HTTP 200 and a provider-specific
schema. Every response body is suppressed, including identity, account keys,
quota metadata, device inventory and address-book PII. Authentication, scope,
subscription, migration and credential-family errors remain unknown. Insightly
429 responses no longer count as authentication; pod fallback retries only
401/403 authorization ambiguity and stops on all other failures or cancellation.

| Provider | Contract and supported scope |
| --- | --- |
| CoinAPI | Replaces unproven `/v1/limits` with documented `/v1/exchanges/COINBASE`, X-CoinAPI-Key. Requires a typed array of matching exchange_id/name entries, including an empty array. One filtered metadata request; other CoinAPI product keys and quota rejection remain unknown. |
| Etherscan | Replaces chain balance lookup with V2 module=getapilimit/action=getapilimit. Requires status=1/message=OK and typed credit usage/limit/interval metadata. String errors, rate-limit messages and success-looking envelopes with missing usage cannot authenticate. |
| Pagar.me | Existing ak_live_ detection identifies legacy keys. Routes those to `GET /1/plans?count=1`, using documented Basic auth with key username and password x. Requires plan object discriminator, integer id/amount/days and name; empty arrays accepted. Incompatible formats make no request. Legacy API deprecation/migration failures remain unknown; V5 sk_ detection is a separate follow-up. |
| Polygon/Massive | Migrates to `https://api.massive.com/v1/marketstatus/now`, Bearer auth. Existing Polygon keys are documented as valid on the new host. Requires market, RFC3339 serverTime and boolean earlyHours/afterHours. Closed markets are valid. No ticker data retrieval. |
| Detectify | Routes 32-hex V2 keys to `/rest/v2/assets/?pageSize=1&include_subdomains=false` with X-Detectify-Key, and UUID V3 keys to `/rest/v3/ips?limit=1` with raw Authorization. V2 requires typed asset entries and has_more, also accepting the explicitly documented empty object for no assets. V3 requires typed IP identity and address entries. Unrecognized formats remain detected but make no request. Required V2 message-signature or missing scope stays unknown. |
| Route4Me | Strictly bounds existing address-book retrieval with limit=1/offset=0. Requires integer total and contact address_id/address_1; empty collections accepted. Optional personal fields ignored, all returned PII suppressed. |
| Smartlead | Replaces full campaign configurations with the sparse analytics campaign selector `/api/v1/analytics/campaign/list`. Requires ok=true and data.campaign_list id/name entries, including empty lists. No documented server pagination; one byte-capped metadata response, truncation unknown. |
| Ubidots | Replaces undocumented V1.6 current-user lookup with V2 `/devices/?page=1&page_size=1`, X-Auth-Token. Requires count and device id/label entries, including empty arrays; inactive devices and optional last-activity fields accepted. Account API keys, scoped tokens and deployment ambiguity remain unknown; no token creation. |
| APIMatic | Official CLI's `/account/profile` replaces code-generation listing. Requires Id/Email with X-Auth-Key authentication. Entire profile is suppressed, including optional SecurityStamp and ApiCopilotKeys; no generated artifacts retrieved. |
| Insightly | Basic-auth `/v3.1/Users/Me` replaces contact listing, requiring integer USER_ID and EMAIL_ADDRESS. Fixed na1/eu1/au1 pod fallback with authorization-only retries. Optional inactive/profile fields accepted; quota errors never prove authentication. Custom/unknown pods remain ambiguous. |

All ten patterns enforce trailing credential boundaries. Detectify now detects
the documented V3 UUID family while retaining its existing ambiguous family;
Smartlead keyword prefilters cover the existing underscore/hyphen variants.
Broader modern credential-format coverage remains separate from this review.
Metadata requests can still consume provider request quota. No response-supplied
links or cursors are followed, and every body uses the shared response cap.

Mocked tests cover exact requests and credentials, ordinary verification policy,
typed success/error schemas, non-200 success-like bodies, empty/inactive/optional
metadata, version routing, whole-token boundaries, regional fallback/stop
conditions, cancellation, transport/read failures and byte-capped suppression.
Unauthenticated, credential-free checks of the new CoinAPI and Massive metadata
endpoints returned HTTP 401; no real credentials were used for validation.

Official evidence checked 2026-09-27:

- [CoinAPI published OpenAPI, exchange-id filter and schema](https://rest.coinapi.io/swagger/v1/swagger.json).
- [Etherscan account API usage endpoint and response](https://docs.etherscan.io/api-reference/endpoint/getapilimit.md).
- [Pagar.me legacy plans schema and count bound](https://docs.pagar.me/v4/reference/retornando-planos.md), [Basic authentication](https://docs.pagar.me/v4/reference/principios-basicos), [modern sk_/pk_ keys](https://docs.pagar.me/docs/chaves-de-acesso.md).
- [Polygon-to-Massive transition and key compatibility](https://massive.com/blog/polygon-is-now-massive), [REST authentication](https://massive.com/docs/rest/quickstart), [market-status contract](https://massive.com/docs/rest/stocks/market-operations/market-status.md).
- [Detectify V2 authentication, optional signing, bounded assets and empty-object response](https://developer.detectify.com/v2/), [V3-specific key authentication and bounded IP schema](https://developer.detectify.com/).
- [Route4Me address-book pagination](https://route4me.io/docs/), [official Go response envelope](https://github.com/route4me/route4me-go-sdk/blob/master/addressbook/addressbook.go), [contact/query types](https://github.com/route4me/route4me-go-sdk/blob/master/addressbook/models.go).
- [Smartlead sparse campaign selector](https://api.smartlead.ai/api-reference/analytics/campaign-list.md), [full campaign endpoint lacks server pagination](https://api.smartlead.ai/api-reference/campaigns/get-all.md).
- [Ubidots V2 device schema](https://docs.ubidots.com/reference/get-all-devices.md), [pagination](https://docs.ubidots.com/reference/pagination.md), [token/API-key distinction](https://docs.ubidots.com/reference/authentication.md).
- [APIMatic official CLI account request and auth](https://github.com/apimatic/apimatic-cli/blob/main/src/infrastructure/services/api-service.ts), [account schema](https://github.com/apimatic/apimatic-cli/blob/main/src/types/api/account.ts).
- [Insightly current-user OpenAPI](https://api.na1.insightly.com/v3.1/swagger/docs/v3.1), [pod context, Basic auth and quota behavior](https://api.insightly.com/v3.1/Help).

Salesforce/API-Football reference pages still returned HTTP 403 during this
review. Atera documentation was also blocked; those verifiers remain unchanged.

## Remediation batch 26: ten control-plane identity and metadata verifiers

Platform.sh is now `auth_only`; the other nine are `read_only`. Every success
requires HTTP 200 and an explicit typed schema. Responses, including issued
access tokens, identity fields and token metadata, are suppressed on all outcomes.
Permission, deployment and credential-family rejection remains unknown.

| Provider | Contract and supported scope |
| --- | --- |
| Harness | Personal-token `x-api-key` current-user request, supplying accountIdentifier from the existing pat token's account hint. Requires SUCCESS and data.uuid/email; error codes cannot authenticate. Other token formats make no request. Self-managed deployments remain ambiguous. |
| Sanity | Bearer versioned `/users/me`, requiring id and a string name (including empty). Email and profile metadata are optional. Robot/project-token rejection remains unknown. |
| Temporal Cloud | Bearer `/cloud/current-identity` with temporal-cloud-api-version=v0.22.0. Requires exactly one user or service-account principal, with id and spec.email or spec.name. Optional principalApiKey metadata is suppressed. Client-secret rejection remains unknown. |
| Bunny.net | Replaces undocumented `/user` with `/statistics`, bounded to the previous completed UTC day. Requires typed bandwidth, origin traffic, response time, request count and cache-hit rate; zero usage accepted. Storage/Stream credential rejection remains unknown. |
| Cronitor | Basic API-key `/api/groups?page=1&pageSize=1`, version 2025-11-28. Requires numeric count and group key/name entries, including empty collections. Telemetry-only and restricted-key rejection remains unknown. |
| PartnerStack | Partner Bearer `/api/v2/partnerships?limit=1&include_offers=false`. Requires numeric status=200, boolean data.has_more and typed items with key/company.id. Empty collections and archived partnerships accepted. Vendor credentials require a different contract; rejection remains unknown. |
| Feedier | Migrates to `https://api.bx.feedier.com/v3/teams?page=1&limit=1`, Bearer auth. Requires data array with numeric id/name entries; empty teams and optional hierarchy metadata accepted. |
| Fulcrum | X-ApiToken `/api/v2/users.json` returns the current user, requiring user.id/email. US/AU/CA/EU fixed-host fallback only on authorization ambiguity. Organization contexts are suppressed and byte-capped. |
| Platform.sh/Upsun | Migrates api_token grant to `https://auth.upsun.com/oauth2/token`, with documented public-client Basic auth platform-api-user and empty password. Requires access_token, Bearer token_type and positive integer expires_in. Issued tokens are suppressed; incompatible bearer tokens remain unknown. |
| ZeroTier | Replaces network listing with legacy Central `/api/v1/status`, Authorization: token. Requires central_status/CentralStatus and user.id/email. Read-only mode is legitimate. Local-service and newer credential-family rejection remains unknown. |

All ten enforce whole-token trailing boundaries. Harness's keyword prefilter now
recognizes standalone pat tokens; ZeroTier covers existing underscore/hyphen
context variants. This batch hardens supported families without claiming complete
modern-format detection. Fulcrum regional fallback stops on redirects, malformed
success, rate limits, outages, transport/read failures and cancellation. No returned
pagination links are followed.

Mocked tests cover exact requests, ordinary verification policy, typed and
conflicting schemas, legitimate empty/inactive/optional fields, response
suppression, regional order and stop conditions, response caps, credential
boundaries and unsupported Harness formats.

Official evidence checked 2026-09-27:

- [Harness current-user endpoint and required account context](https://apidocs.harness.io/user/getcurrentuserinfo.md), [official response model](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_response_dto_user_info.go), [UserInfo model](https://github.com/harness/harness-go-sdk/blob/main/harness/nextgen/model_user_info.go).
- [Sanity official users client](https://github.com/sanity-io/client/blob/main/src/users/UsersClient.ts), [current-user types](https://github.com/sanity-io/client/blob/main/src/types.ts), [authentication](https://www.sanity.io/docs/content-lake/http-auth.md).
- [Temporal Cloud published OpenAPI](https://saas-api.tmprl.cloud/spec.json), [current API version](https://github.com/temporalio/cloud-api/blob/main/VERSION).
- [Bunny Core OpenAPI statistics schema and date bounds](https://bunny.net/docs/api-reference/core/openapi.json).
- [Cronitor group metadata, scopes and pagination](https://cronitor.io/docs/groups-api), [versioned API authentication](https://cronitor.io/docs/api).
- [PartnerStack Partner Bearer authentication](https://docs.partnerstack.com/reference/partner-api-authentication.md), [Partner partnership schema and pagination](https://docs.partnerstack.com/reference/get_v2-partnerships.md).
- [Feedier teams endpoint and schema](https://developers.feedier.com/teams), [pagination](https://developers.feedier.com/pagination).
- [Fulcrum Users API authentication and current-user response](https://docs.fulcrumapp.com/reference/users-intro.md), [endpoint and regional servers](https://docs.fulcrumapp.com/reference/users-get-user.md).
- [Upsun token exchange](https://developer.upsun.com/api/rest/authentication.md), [official Platform.sh CLI auth-host configuration](https://github.com/platformsh/cli/blob/main/internal/config/platformsh-cli.yaml).
- [ZeroTier legacy Central OpenAPI status, user and authentication schemas](https://docs.zerotier.com/openapi/central/v1.json).

## Remediation batch 25: ten schema, identity and metadata verifiers

All ten are now `read_only`. Success requires HTTP 200 and a provider-specific
schema, except VirusTotal's documented structured sentinel miss. Response bodies
are suppressed on every outcome. Regional and credential-header fallback retries
only authorization ambiguity, stopping on malformed success, redirects, quota
errors, outages, transport/read failures and cancellation. Every response is
subject to the shared byte cap; no returned links or pagination are followed.

| Provider | Contract and supported scope |
| --- | --- |
| BitBar | Basic API key with empty password, `GET https://cloud.bitbar.com/api/me`. Numeric id and email from the official APIUser model; optional enabled/name/account metadata ignored. Entire identity response, including any apiKey echo, is suppressed. Private/on-premise and disabled-account rejection remain unknown. OAuth password grant is not attempted. |
| BlazeMeter | API Monitoring/Runscope Bearer `GET /account`, requiring data.uuid/name and meta.status=success. Email requires the separate account:email scope and is not required. Teams can be empty. Existing UUID-shaped detection retained; other BlazeMeter product credentials are not claimed as compatible and rejection remains unknown. |
| Pendo | Integration-key `GET /api/v1/metadata/schema/account`. Requires built-in auto object and typed field-definition objects across groups. Empty groups and uninferred empty Type values are legitimate; samples and metadata suppressed. Fixed app.pendo.io, app.eu.pendo.io, us1.app.pendo.io, app.jpn.pendo.io and app.au.pendo.io authorization-only fallback. Public subscription keys and Track Event secrets are distinct families; ambiguous rejection stays unknown. One byte-capped schema request per attempted region. |
| SmartRecruiters | Migrates to `GET /user-api/v201804/users/me`. Requires id/firstName/lastName and systemRole.id, ignoring optional active/email metadata. Uses X-SmartToken first, with Bearer only on authorization ambiguity; never mixes headers. Missing OAuth scope/context remains unknown. |
| Nitro/Alconost | Migrates to canonical `https://api.nitrotranslate.com/v1/account` with Basic API-key authentication. Requires integer or decimal-string account id and numeric balance/reserved. Zero balances and negative overdraft balances accepted. Existing Alconost detection retained; account and funds metadata suppressed. No translation or payment request. |
| Airbrake | User key in documented query parameter, `GET /api/v4/projects?limit=1&key=...`. Requires projects array with numeric id/name entries, including empty lists. Optional deployment metadata is ignored. Top-level code errors rejected; project-key/user-token ambiguity unknown. |
| SSLMate | Basic certificate API `GET /api/v2/certs/example.com`. Requires boolean exists and exact cn=example.com; false is legitimate for absent certificates. Structured reason errors never authenticate. Production/sandbox authorization-only fallback, other SSLMate product credential rejection unknown. No certificate creation, testing, purchase or expansion. |
| SurveySparrow | Replaces legacy contacts retrieval with `GET /v3/roles?limit=1&page=1`, Bearer auth. Requires numeric id/name role entries and boolean has_next_page; empty lists accepted. Fixed documented US/EU/AP/ME/UK/Sydney/Canada regional hosts, authorization-only fallback. Missing role-read permission remains unknown. Published contacts schema is incomplete (string[]), so role metadata supplies the reviewed contract. |
| protocols.io | Bearer `GET /api/v3/session/profile`, supporting documented client/OAuth access context. Requires explicit numeric status_code=0 and user.username/email. Missing/null status no longer defaults to success. Optional empty display name and expiry warnings accepted; response PII suppressed. Nonzero/provider errors remain conservatively unknown. |
| VirusTotal | Retains read-only all-zero SHA-256 file sentinel, avoiding identity retrieval that can return an API key. HTTP 404 requires exact nested error.code=NotFoundError, not a substring; HTTP 200 requires matching file id/type and an attributes object. Exact HTTP 401 WrongCredentialsError is invalid; inactive accounts, permission errors and quota responses remain unknown. Conflicting success/error envelopes rejected. The lookup may consume request quota; it does not upload or rescan a file. |

All ten patterns enforce trailing token boundaries. SmartRecruiters and
SurveySparrow keyword prefilters now cover their existing regex variants.
Supported-family hardening does not imply detection of every newer format.
SSLMate certificate API credentials remain distinct from Cert Spotter/CT Search
and SaaS products; BlazeMeter load-testing credentials remain distinct from
Runscope API Monitoring tokens.

Mocked regression tests cover exact URLs, methods and authentication, ordinary
verification policy, typed success/error schemas, empty collections, optional
and inactive metadata, regional/header ordering, stop conditions, cancellation,
transport/read failures, response suppression, sentinel error-code spoofing,
and whole-token boundaries. The protocols.io regression now uses its documented
username/email profile rather than an unproven numeric user ID.

Official evidence checked 2026-09-27:

- [BitBar API-key authentication and /api/me](https://support.smartbear.com/bitbar/docs/en/use-rest-apis-with-bitbar/authentication.html), [official APIUser model](https://github.com/bitbar/testdroid-api/blob/master/src/main/java/com/testdroid/api/model/APIUser.java).
- [BlazeMeter API Monitoring account schema and optional email scope](https://help.blazemeter.com/apidocs/api-monitoring/account.htm).
- [Pendo official API collection, regional hosts and metadata-schema example](https://engageapi.pendo.io/) ([published collection data](https://documenter.gw.postman.com/api/collections/16265887/Tzm6jvKG?segregateAuth=true&versionTag=latest)).
- [SmartRecruiters versioned current-user OpenAPI](https://developers.smartrecruiters.com/reference/usersme-2.md), [API-key authentication](https://developers.smartrecruiters.com/docs/authentication-api-key.md).
- [Nitro account schema and canonical host](https://docs.nitrotranslate.com/api-reference/account/get.md), [Basic API-key authentication](https://docs.nitrotranslate.com/authentication.md).
- [Airbrake user keys, project schema and pagination](https://docs.airbrake.io/docs/devops-tools/api/).
- [SSLMate certificate retrieval, exists=false, errors and sandbox](https://sslmate.com/help/reference/apiv2).
- [SurveySparrow V3 role schema and bounds](https://developers.surveysparrow.com/rest-apis/get-v-3-roles), [regional hosts and authentication](https://developers.surveysparrow.com/rest-apis/Introduction).
- [protocols.io client/OAuth authentication and V3 profile schema](https://apidoc.protocols.io/).
- [VirusTotal file retrieval](https://docs.virustotal.com/reference/file-info), [structured error codes](https://docs.virustotal.com/reference/errors), [identity response includes API-key metadata](https://docs.virustotal.com/reference/user-object).

## Remediation batch 24: ten regional account and token-context verifiers

Gusto is now `auth_only`; the other nine are `read_only`. All require HTTP 200
and explicit provider schemas and suppress response bodies on every outcome.
Zoho scope errors, Phrase permission errors and ThousandEyes forbidden responses
no longer prove authentication. Rejections remain unknown when region,
credential family, tenant, scope or account-lockout context is ambiguous.

| Provider | Contract and supported scope |
| --- | --- |
| Iterable | Api-Key `GET /api/users/getFields`; non-null fields object, including an empty schema. The official API supports Server-side and Read-only keys; mobile/browser key rejection remains unknown. US/EU authorization-only fallback. Field definitions are metadata, not user records, and are suppressed. |
| Zoho CRM | Zoho-oauthtoken `GET /crm/v8/users?type=CurrentUser`; typed id/email entries, including empty collections. Optional names/status are ignored. Existing fixed US/EU/IN/AU/JP/CA/SA hosts now retry only authorization ambiguity. Other deployments remain unknown. OAUTH_SCOPE_MISMATCH is never successful authentication. |
| Nylas | Bearer `GET /v3/grants?limit=1&offset=0`; grant id/provider/created_at required, including empty arrays. Invalid/blocked grants and missing optional email are legitimate. API-key/legacy-client-secret ambiguity remains unknown; US/EU fallback only after authorization ambiguity. |
| Phrase | Legacy Strings OAuth `Authorization: token` `GET /v2/user`; id/username/email required. EU/US authorization-only fallback. The supported 40-character token detector remains distinct from newer Platform JWT workflows; no exchange is attempted. |
| Gusto | Bearer `GET /v1/token_info` with version 2026-06-15; typed scope and nullable resource/resource_owner objects. Empty scopes, null resources and system-token null owners are legitimate. Present objects require type/uuid. Production/demo authorization-only fallback; OAuth client-secret rejection stays unknown. |
| ThousandEyes | V7 Bearer `GET /account-groups`; typed string aid/accountGroupName array, including empty lists. Optional current/default flags are ignored. Legacy credentials, account lockout and insufficient permission remain unknown. One metadata collection under the shared byte cap; no response links followed. |
| Envoy | Migrates to current Core REST `GET /rest/v1/locations?page=1&perPage=1`, X-API-Key and application/json. Requires data array with id/name/companyId, including empty arrays. Optional enabled/address fields are ignored. Existing supported 220-character pattern retained; no claim of all token-format coverage. |
| Frame.io | V2 Bearer `GET /v2/me`; id/account_id/email required, optional profile metadata ignored and entire response suppressed. Supports the existing V2 developer/OAuth probe. Incompatible Adobe IMS/V4 token rejection remains unknown; no login or token exchange. |
| Codacy | api-token `GET /api/v3/user`; nested numeric nonnegative id and mainEmail. Optional active/admin metadata is ignored. Repository-token and self-hosted ambiguity remains unknown; personal identity and returned support hashes are suppressed. |
| JumpCloud | x-api-key `GET /api/systemusers?limit=1&skip=0&fields=_id`; totalCount and sparse user _id entries, including empty arrays. Fixed US/EU/IN authorization-only fallback; missing tenant/scope context remains unknown. Existing legacy 40-character detection retained; jca_ format coverage remains a follow-up rather than guessed expansion. |

Fallback stops on malformed success, redirects, throttling, outages, transport or
read failures, and cancellation. All responses use the shared byte cap. No
pagination or server-supplied links are followed. Iterable and ThousandEyes
metadata operations have no requested pagination; the other collection probes
select the current user or one resource where supported. Requests remain subject
to provider quotas; Iterable documents three field-schema requests/second/project.

All ten credential patterns now enforce trailing boundaries. Gusto and
ThousandEyes keyword variants now match their regex contexts. Supported-family
verification hardening does not imply detection of every modern credential
format, particularly JumpCloud jca_, Phrase Platform JWT and Adobe IMS tokens.

Mocked tests cover exact requests and headers, ordinary verification policy,
nullable/system-token metadata, inactive accounts and invalid grants, empty
collections, typed malformed/error envelopes, non-200 success-like responses,
response suppression, transport/read failures, regional ordering, cancellation
and whole-token boundaries. Existing Nylas and Envoy regressions are updated to
the conservative authorization category and current REST response schema.

Official evidence checked 2026-09-27:

- [Iterable official OpenAPI: getFields schema, supported key types and rate limit](https://api.iterable.com/api-docs), [US/EU API explorer](https://api.iterable.com/api/docs).
- [Zoho V8 users and CurrentUser filter](https://www.zoho.com/crm/developer/docs/api/v8/get-users.html), [multi-data-center context](https://www.zoho.com/crm/developer/docs/api/v8/multi-dc.html).
- [Nylas grant list, pagination, regional hosts and schema](https://developer.nylas.com/docs/reference/api/manage-grants/get-all-grants/).
- [Phrase current user and regional hosts](https://developers.phrase.com/en/api/strings/users/show-current-user), [legacy token and Platform authentication distinction](https://developers.phrase.com/en/api/strings/authentication.md).
- [Gusto token-info schema, nullable resource/owner and version](https://docs.gusto.com/app-integrations/reference/get-v1-token-info.md).
- [ThousandEyes V7 account groups, Bearer auth and permission errors](https://developer.cisco.com/docs/thousandeyes/list-account-groups/).
- [Envoy current locations OpenAPI: Core REST, API key and pagination](https://developers.envoy.com/hub/reference/locations-1.md), [client API key authentication](https://developers.envoy.com/hub/docs/getting-an-access-and-refresh.md).
- [Frame.io V2 current-user schema and credential types](https://developer.frame.io/api/reference/operation/getMe/).
- [Codacy current-user schema and account authentication](https://api.codacy.com/api/api-docs).
- [JumpCloud official V1 OpenAPI: regions, sparse fields, limits, totalCount and user schema](https://docs.jumpcloud.com/api/1.0/index.yaml).

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
