# TruffleHog Parity Plan

Snapshot source: `trufflesecurity/trufflehog` at `9b6b5326bfe25dbd856eccc8a8275eb5dea7bd52`.

TruffleHog detector directories at snapshot: `870`.

The full detector directory catalog is generated into `internal/parity/catalog.go` from the snapshot above.

Current tracked mapping summary:

- Catalog size: `870`
- Total mappings: `292`
- Direct catalog mappings: `287`
- Sub-detector mappings: `4`
- Duplicate catalog mappings: `1`
- Implemented mappings: `227`
- Partial mappings: `18`
- Planned mappings: `47`
- Untracked catalog directories: `583`

Accounting notes:

- `catalog_size` is the generated TruffleHog detector directory count from the pinned snapshot.
- `catalog_tracked` counts unique mapped IDs that exist in that generated catalog.
- `sub_detector_tracked` counts mapped IDs not present as top-level catalog directories, such as `github/v2`.
- `duplicate_mappings` counts extra mapping rows for one catalog ID, such as separate `aws` access-key and secret-key coverage.

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
- Heroku, Cloudflare, DigitalOcean, Azure DevOps, Terraform Cloud, Netlify, Pulumi, Doppler, Tailscale, ngrok
- Buildkite, NuGet, RubyGems
- Linear, Notion, Postman, Supabase, Firebase
- MongoDB, PostgreSQL, MySQL connection URIs
- Shopify, Square, PayPal, Razorpay key IDs
- Slack, Discord, and Microsoft Teams webhooks
- Grafana, Sentry, Honeycomb, Opsgenie, Splunk Observability, Webex bot tokens
- Hugging Face, Groq, Replicate
- Airtable, Asana, ClickUp, Typeform, HubSpot, Mailchimp, Klaviyo
- Nightfall, Endor Labs, TruffleHog Enterprise token shapes, Tines webhooks
- Pinecone, LangSmith, Langfuse, ElevenLabs, xAI, Voiceflow
- Harness, Zoho CRM, Intercom, Front, Segment, PostHog, LaunchDarkly
- Coda, Monday.com, Postmark, Calendly
- Fly.io, Cloudflare CA keys, Artifactory access/reference tokens
- Azure App Configuration, Storage, Cosmos DB, SAS URLs, and Function key URLs
- SpectralOps, Okta, urlscan.io
- Atlassian, Jira, Salesforce token shapes, Twilio auth tokens, Mailjet basic auth
- OpenAI admin, DeepSeek, Weights & Biases, AssemblyAI, Deepgram, Eden AI, MonkeyLearn
- Contentful, Storyblok, Sanity, Webflow, Shortcut
- Mapbox, LocationIQ, CoinAPI, Etherscan, BscScan, Guardian Open Platform
- CircleCI, Sourcegraph, Sourcegraph Cody, Snyk, UptimeRobot, Sumo Logic partial coverage
- Sendinblue/Brevo, Teamwork, Salesblink, Smooch, Mailmodo
- Zapier webhooks, Deno Deploy, Supabase management tokens, Prefect, Figma, SaladCloud
- PlanetScale, Databricks, Portainer, Statuspage
- AWS AppSync, Azure OpenAI, Azure Batch, Azure Container Registry
- GCP service account JSON and application default credentials
- Redis URIs, Azure Redis connection strings, Couchbase Capella URIs
- Close CRM, Paystack, Wrike, Facebook OAuth secret, Twitter/X consumer secret
- Flutterwave, Pagar.me, Recharge Payments, Lemon Squeezy, Plaid partial coverage
- Cloudinary URLs, Zendesk, Freshdesk, HelpCrunch, Courier, LINE Messaging, Mattermost
- HashiCorp Vault AppRole partial coverage
- Cloudflare global keys, Docker auth configs, Azure Search, Azure API Management
- Auth0 management tokens, VirusTotal, Shodan, SecurityTrails
- Snowflake URLs, SQL Server connection strings, RabbitMQ URIs
- NewsAPI, OpenWeather, Tomorrow.io, HERE, Polygon.io
- Aiven, AbuseIPDB, SonarCloud, JumpCloud, Pipedrive, SparkPost
- Vercel, Railway, Travis CI, BetterStack, Logz.io, Code Climate, Codacy, Coveralls
- Customer.io, Trello, Help Scout, MailerLite, Mandrill, OneSignal
- Copper, Capsule CRM, Apollo, Lemlist, GetResponse
- AlienVault OTX, Censys, VPNAPI.io, IPQualityScore, IPstack, IPGeolocation, ZeroTier
- Weatherstack, AccuWeather, Weatherbit, MapQuest
- Dropbox, ReadMe, Rootly, Web3.Storage, Stripe PaymentIntent client secrets, Checkout.com
- Aha and LarkSuite app secrets
- JWTs, private keys, SSH private keys
- Basic-auth URLs and generic assigned secrets

## Implemented Platform Coverage

- Local filesystem scanning
- GitHub repository URL cloning
- Optional full git object scanning with `--git-history`
- Bounded base64 and base64url decoding before detector matching
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
