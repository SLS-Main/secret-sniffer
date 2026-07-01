# TruffleHog Parity Plan

Snapshot source: `trufflesecurity/trufflehog` at `9b6b5326bfe25dbd856eccc8a8275eb5dea7bd52`.

TruffleHog detector directories at snapshot: `870`.

The detector directory identifier catalog is generated into `internal/parity/catalog.go` from the snapshot above.

TruffleHog is a project of Truffle Security. This project is not affiliated with or endorsed by Truffle Security. The generated parity catalog contains only detector directory identifiers from the pinned snapshot for comparison and interoperability tracking. It does not include TruffleHog source code, detector regexes, verifier logic, or documentation text.

Current tracked mapping summary:

- Catalog size: `870`
- Total mappings: `875`
- Direct catalog mappings: `870`
- Sub-detector mappings: `4`
- Duplicate catalog mappings: `1`
- Implemented mappings: `807`
- Partial mappings: `66`
- Planned mappings: `2`
- Untracked catalog directories: `0`

Accounting notes:

- `catalog_size` is the generated TruffleHog detector directory count from the pinned snapshot.
- `catalog_tracked` counts unique mapped IDs that exist in that generated catalog.
- `sub_detector_tracked` counts mapped IDs not present as top-level catalog directories, such as `github/v2`.
- `duplicate_mappings` counts extra mapping rows for one catalog ID, such as separate `aws` access-key and secret-key coverage.

This project is not trying to copy TruffleHog's discovery algorithm or source code. Parity means comparable source coverage, provider detector coverage, verification coverage, output usability, and operational behavior on large servers.

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
- Nightfall, Endor Labs, TruffleHog Enterprise credential formats, Tines webhooks
- Pinecone, LangSmith, Langfuse, ElevenLabs, xAI, Voiceflow
- Harness, Zoho CRM, Intercom, Front, Segment, PostHog, LaunchDarkly
- Coda, Monday.com, Postmark, Calendly
- Fly.io, Cloudflare CA keys, Artifactory access/reference tokens
- Azure App Configuration, Storage, Cosmos DB, SAS URLs, and Function key URLs
- SpectralOps, Okta, urlscan.io
- Atlassian, Jira, Salesforce token formats, Twilio auth tokens, Mailjet basic auth
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
- AWS session tokens and Alibaba Cloud access key IDs
- Scaleway secret keys, GitHub App private keys, Datadog application keys, Braintree access tokens
- GitHub/GitLab OAuth client secrets, Azure Entra client secrets, Twitch client secrets
- Auth0 OAuth client secrets, OneLogin client secrets, LDAP credential URLs, LoginRadius API secrets, Stytch secrets
- Detectify, Wiz client secrets, JupiterOne API tokens, Twitter/X bearer tokens, Twitch access tokens
- Webex access tokens, Coinbase CDP API keys, OpenVPN static keys
- Fastly, Telnyx, Vagrant Cloud, Zeplin, Vultr, Bitly, Algolia admin keys
- Airbrake, Bugsnag, Infura, MessageBird, Pinata, Pushbullet, Sendbird
- StormGlass, Todoist, Uploadcare
- BrowserStack, Cloudsmith, Eventbrite, Harvest, Lokalise, MaxMind, Nylas, Pipedream
- Percy, Crowdin, PostageApp, Sendbird organization tokens
- Checkly, Confluent partial coverage, DocuSign, GoCardless, Gumroad, HelloSign
- Mailboxlayer, Mediastack, OpenCage, Packagecloud, Phrase, Semaphore, Scrutinizer CI, Sauce Labs partial coverage
- Less Annoying CRM, MeaningCloud, OpenUV, PandaScore, Paperform, ParseHub, PDFShift
- People Data Labs, Plivo partial coverage, RapidAPI, ScraperAPI, Scrapestack, ScrapingBee
- Serpstack, Shotstack, SignalWire partial coverage, TestingBot partial coverage
- Abstract, Alchemy, Apify, APILayer, Bannerbear, Baremetrics, Beamer, Bitbar
- BlazeMeter, ButterCMS, Canny, ChartMogul, Clearbit, Clockify, CloudConvert, Cloudmersive
- ConvertAPI, ConvertKit partial coverage, Daily.co, DeepAI, Delighted, Deputy, FullStory
- Geoapify, GraphHopper, Hunter, ImageKit, Kickbox, Klipfolio, Lob, Moosend
- NeutrinoAPI partial coverage, Numverify, Omnisend, OwlBot, PandaDoc, PartnerStack, Pastebin
- PayMongo, PhotoRoom, ProxyCrawl, Qase, Rebrandly, RepairShopr, Reply.io, Restpack
- RocketReach, Route4Me, Salesflare
- Adzuna partial coverage, AirVisual, Amadeus partial coverage, Ambee, Amplitude, APIFLASH
- APITemplate, Appcues, AppFollow, Autoklose, Aviationstack, Ayrshare, BestTime
- Brandfetch, Browshot, Calendarific, Carbon Interface, CraftMyPDF, CurrentsAPI, DeBounce, Detect Language
- Clarifai, ClickSend SMS, Codemagic, Databox, Diffbot, Edamam partial coverage, Ethplorer
- Face++ partial coverage, Geckoboard, Hasura, Holiday API, HTML2PDF, IP2Location, ipapi
- IPInfoDB, Jotform, Keen.io, Languagelayer, LINE Notify, LinkPreview
- Loggly, Mixpanel partial coverage, Mockaroo, Mux partial coverage, Nutritionix partial coverage
- OANDA, Onfleet, PDFLayer, Pepipost, Pivotal Tracker, Pixabay, Podio
- PubNub publish/subscribe keys, Pusher channel keys, Qualaroo, RAWG, RingCentral partial coverage
- ScrapeOwl, Scrapfly
- ScreenshotAPI, Screenshotlayer, SelectPdf, Sheety, Shipday, Signable, Signaturit
- Simplesat, SmartyStreets partial coverage, Snipcart, Spoonacular, SportsMonk
- Spotify partial coverage, StatusCake, StockData, StoryChief, Strava partial coverage
- Swiftype, Tatum, TaxJar
- TextMagic, Tiingo, TimeCamp, TimezoneAPI, Toggl Track, TomTom, Wise/TransferWise
- Unsplash, Userstack, Visual Crossing, Voicegain, WePay partial coverage, Yandex, Yelp
- YNAB, ZenRows, Zenscrape, Zenserp, ZeroBounce, Zipcodebase
- Bitfinex partial coverage, BitMEX partial coverage, KuCoin partial coverage, Smartsheet
- Tableau partial coverage, ThousandEyes, Ticketmaster, The Odds API, Thinkific, Ubidots
- uClassify, UPC Database, UpLead, VBOUT, Veriphone, Walk Score, WebsitePulse
- Whoxy, Wistia, Wit.ai
- Ticket Tailor, TMetric, Teamgate, Teamwork Spaces, SignUpGenius, SpeechText.AI
- Sirv, Siteleaf, Skrapp, SkyBiometry, SimplyNoted, Simvoly, Sinch Message
- SSLMate, Statuspal, Storecove, Stormboard, Streak, Stripo, Sugester
- Abyssale, Adafruit IO, Adobe IO, Aero Workflow, Agora, Airship, Alconost
- Alegra, Aletheia, AllSports, Anypoint, Apacta, API2Cart, Apideck, Apifonica
- APIMatic, APImetrics, Appointedd, AppOptics, AppSynergy
- Apptivo, Artsy, Atera, Atlassian Data Center, AudD, Autodesk, Autopilot
- Axonaut, AYLIEN, Beebole, BeSnappy, Billomat, Blitapp, Blogger, BombBomb
- Boost Note, BorgBase, BuddyNS, Budibase, BugHerd
- Bulbul, BulkSMS, Caflou, CalorieNinjas, Campayn, Captain Data, Cashboard
- Caspio, CentralStationCRM, CEX.IO, ChatBot, Chatfuel, Chec, Checkvist
- Cicero, ClickHelp, Cliengo, Clientary, ClinchPad, Clockwork SMS
- Avaza, Cloud Elements, Cloudimage, Cloudplan, Cloverly, Cloze, Clustdoc, Codequiry
- Collect2, Column, Commerce.js, Commodities, CompanyHub, ConversionTools, Convier
- Countrylayer, Currencycloud, Customer.guru, D7 Network, Dandelion, Dareboost
- Data.gov, Demio, dfuse, Diggernaut, Disqus, Ditto, DNSCheck, Docparser, Documo
- Dotdigital, Dovico, DronaHQ, Drone CI, Duply, Dynalist, Dyspatch
- Eagle Eye Networks, Easy Insight, EcoStruxure IT, 8x8
- Dwolla, EnableX, Enigma, Envoy, Eraser, Everhour, ExportSDK, Extractor API
- Feedier, FetchRSS, Fibery, File.io, Finage, Findl, Flatio, Fleetbase, Flexport
- Flickr, FlightAPI, FlightLabs, FlightStats
- Float, Flowlu, FMFW, FormBucket, FormCraft, Form.io, Formsite, Foursquare partial coverage
- Frame.io, FreshBooks, Fulcrum, FXMarket, Gengo, Geocodify, Geo.ipify, GetEmail
- GetEmails, GetGeoAPI, GetGist, GetSandbox
- Gitter, Glassnode, GoCanvas, GoDaddy, GoodDay, GraphCMS, GrooveHQ, GTmetrix
- Guru, Gyazo, Happy Scribe, Hive, Hiveage, Holistic, Humanity, Hybiscus
- HyperTrack, IBM Cloud user keys, Iconfinder, IEX APIs
- IEX Cloud, Imagga partial coverage, Impala, Insightly, Instabot, Instamojo partial coverage
- Interseller, Intra42, Intrinio, InvoiceOcean, Juro, Kanban, Kanban Tool, karmaCRM
- Knapsack Pro, Kontent, Kylas, Leadfeeder, Lendflow, Lexigram
- Kraken partial coverage, LarkSuite, LiveAgent, Livestorm, Loadmill, Loyverse
- Lunch Money, Luno partial coverage, M3O, MadKudu, MagicBell, Magnetic, Mailjet SMS
- Mailsac, Manifest, Mavenlink, MeisterTask, Meraki, Mesibo, MetaApi
- Metabase, Metrilo, MindMeister, Miro, mite, Mixmax, Moderation, MoonClerk
- Moralis, MrTickTock, Freshworks, MyIntervals, Nasdaq Data Link, NetHunt
- NetSuite partial coverage, NewsCatcher, Nexmo, NFTPort, NVIDIA NGC, Nicereply
- Nimble, Noticeable, Nozbe Teams, NVAPI, OneDesk, OnePageCRM, OOPSpam
- Optimizely, Overloop, ParallelDots, Parsers, Parseur, Paydirt, Paymo
- Planview LeanKit, Planyo, Polls API, Poloniex partial coverage, Postbacks, Powrbot
- Privacy.com, ProdPad, Prospect CRM, Protocols.io, PureStake, Qubole, Ramp, Raven
- ReachMail, Really Simple Systems, Refiner, Rentman, Request Finance, Rev.ai
- Revamp CRM, RiteKit, Roaring, Robinhood Crypto partial coverage, Rownd, Runrun.it
- SalesCookie, Salesmate, SatisMeter project/write keys, Scalr, ScraperBox, ScrapingAnt
- SERPHouse, SherpaDesk, Shutterstock, SigOpt, SimFin, Square app partial coverage
- Squarespace, Stitch Data, Supernotes, Survey Anyplace, Surveybot, SurveySparrow, Survicate
- Swell, Tallyfy, Technical Analysis API, Tefter, Teletype, T.LY, Tokeet
- Travelpayouts, tru.ID, Twist, tyntec, Typetalk, UnifyID, Unplugg, Upwave
- Userflow, Verimail, VersionEye, viewneo, VoodooSMS, Vouchery, Vyte
- WebScraper, WebScraping, Worksnaps, Workstack, Yousign, Zenkit, Zip API
- ZipBooks, ZipCodeAPI, Zonka Feedback, Zulip Chat
- Airtable OAuth partial coverage, Anypoint OAuth partial coverage, Asana OAuth partial coverage
- Azure API Management partial coverage, Azure Direct Management partial coverage, Bing subscription keys
- Box and Box OAuth partial coverage using Box JWT/OAuth config context, Gemini partial coverage, Portainer
- Shopify OAuth partial coverage, Shutterstock OAuth partial coverage
- FTP/FTPS/SFTP credential URLs, plus host/user partial coverage only inside credentialed URLs
- IPinfo, CoinLayer, Coinlib, CryptoCompare, BitcoinAverage, WorldCoinIndex, Blocknative
- Fixer.io, Currencylayer, ExchangeRate-API, ExchangeRatesAPI, CurrencyFreaks, CurrencyScoop
- FastForex, Marketstack, Financial Modeling Prep, Finnhub, Tradier, Twelve Data, VATLayer
- World Weather Online, Positionstack, Geocodio
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

The pinned TruffleHog detector-directory catalog is fully tracked: `870` of `870` catalog directories have mappings. Some mappings remain `partial` because this project intentionally avoids noisy tuple-free matches or has not implemented live provider verification.

Future detector work should focus on two streams: improving partial TruffleHog-compatible mappings and adding SecretSniffer-only industry detectors where provider context makes detection reliable.

## SecretSniffer-Only Detector Backlog

This backlog tracks high-signal detectors that are useful for companies that store operational secrets in GitHub but are not currently modeled as direct TruffleHog parity work. Add these only with provider-specific context, documented token prefixes, exact headers, exact environment labels, or credential-pair correlation.

### Betting, Gaming, And Sports Data

| Provider | Use case | Credential context | Detection approach | TruffleHog difference |
| --- | --- | --- | --- | --- |
| Sportradar | Sports data and sportsbook feeds | `x-api-key`, `api.sportradar.com`, sports API paths | Provider host plus API-key label and 24/40-char key candidates | Implemented SecretSniffer-only |
| The Odds API | Sportsbook odds aggregation | `api.the-odds-api.com`, `apiKey`, `/v4/sports` | Host/query-param context; avoid generic `apiKey` without host | Existing coverage |
| Sportmonks | Sports data and predictions | `api.sportmonks.com`, `api_token`, football API paths | Provider host plus `api_token` label | Existing coverage |
| API-FOOTBALL / API-Sports | Sports and odds data | `v3.football.api-sports.io`, `x-apisports-key` | Exact host/header context; RapidAPI-only keys should stay generic/partial | Implemented SecretSniffer-only |
| PandaScore | Esports fixtures and odds | `api.pandascore.co`, bearer token, `token` query param | Provider host plus auth/token label and esports path context | Already covered; improve with provider-host context if needed |
| DATA.BET | Sportsbook platform and odds feed | `feed.int.databet.cloud`, widget secret, JWT signing secret, client cert/key | Provider host plus widget secret labels or cert/private-key context | Implemented SecretSniffer-only |
| Betfair | Betting exchange and trading bots | `api.betfair.com/exchange`, `X-Application`, `X-Authentication` | Require Betfair endpoint plus app/session header context | Implemented SecretSniffer-only |
| OddsJam | Odds and arbitrage analytics | `api.oddsjam.com`, `OddsJam` API key | Provider host plus key/token label | Implemented SecretSniffer-only |
| OpticOdds | Odds feed and sportsbook market data | `api.opticodds.com`, `OpticOdds` API key | Provider host plus key/token label | Implemented SecretSniffer-only |
| GeoComply / GeoGuard | Gambling geolocation compliance | SDK/license credentials, `geocomply`, `geoguard` | Provider SDK/config context only; no generic license-key matching | Implemented SecretSniffer-only |

### Marketing, Adtech, CRM, And Attribution

| Provider | Use case | Credential context | Detection approach | TruffleHog difference |
| --- | --- | --- | --- | --- |
| Braze | Lifecycle marketing and messaging | `BRAZE_API_KEY`, `rest.iad-*.braze.com`, `rest.fra-*.braze.eu` | Provider host/env labels plus bearer/API-key context | Implemented SecretSniffer-only |
| Iterable | Cross-channel messaging | `ITERABLE_API_KEY`, `Api-Key`, `api.iterable.com` | Exact provider host/header context | Implemented SecretSniffer-only |
| ActiveCampaign | Email and CRM automation | `ACTIVECAMPAIGN_API_KEY`, `Api-Token`, `*.api-us1.com/api/3` | Account URL plus `Api-Token` or exact env labels | Implemented SecretSniffer-only |
| HubSpot private app tokens | CRM and marketing automation | `pat-<region>-...`, `HUBSPOT_ACCESS_TOKEN`, `api.hubapi.com` | Distinguish private app PATs from legacy `hapikey` | Existing coverage; improve private-app specificity |
| Marketo | Marketing automation | `MARKETO_CLIENT_SECRET`, `mktorest.com`, OAuth token endpoint | Provider host plus `client_secret`; pair with client ID when possible | Implemented SecretSniffer-only |
| Salesforce Marketing Cloud / Pardot | Enterprise marketing automation | `auth.marketingcloudapis.com`, `SFMC_CLIENT_SECRET`, `PARDOT_CLIENT_SECRET` | Provider-specific OAuth client-secret context | Implemented SecretSniffer-only beyond generic Salesforce mappings |
| Google Ads | Paid search ads | `GOOGLE_ADS_DEVELOPER_TOKEN`, `google-ads.yaml`, `developer-token` | Exact config/header context; avoid generic OAuth-only matches | Implemented SecretSniffer-only beyond Google OAuth |
| TikTok Business API | Paid social ads and conversions | `business-api.tiktok.com`, `Access-Token`, app secret | Provider host plus exact header/secret labels | Implemented SecretSniffer-only |
| LinkedIn Marketing API | B2B ads and integrations | `api.linkedin.com/rest`, `Linkedin-Version`, OAuth client secret | Provider host plus OAuth labels | Implemented SecretSniffer-only |
| Branch | Mobile attribution and deep links | `branch_key`, `branch_secret`, `api2.branch.io` | Prefer key+secret pair correlation; branch key alone is lower severity | Implemented SecretSniffer-only |
| AppsFlyer | Mobile attribution | `APPSFLYER_API_TOKEN`, `api.appsflyer.com`, SDK config | API token context; avoid app IDs alone | Implemented SecretSniffer-only |
| Adjust | Mobile attribution | `ADJUST_API_TOKEN`, `Authorization: Token`, `api.adjust.com` | Provider host plus auth token label | Implemented SecretSniffer-only |
| Attentive | SMS marketing | `api.attentivemobile.com`, API key, access token, signing secret | Provider host plus exact auth/signing labels | Implemented SecretSniffer-only |

### Financial Institutions, Fintech, Payments, KYC, And Crypto

| Provider | Use case | Credential context | Detection approach | TruffleHog difference |
| --- | --- | --- | --- | --- |
| Modern Treasury | Treasury, ACH, wires, ledgers | `MODERN_TREASURY_API_KEY`, `moderntreasury.com` | Provider SDK/host plus API-key label | Implemented SecretSniffer-only |
| Treasury Prime | Banking as a service | `TREASURY_PRIME_API_KEY_ID`, `TREASURY_PRIME_API_SECRET` | Pair key ID with secret when possible | Implemented SecretSniffer-only |
| Unit | Banking, cards, ACH | `UNIT_API_TOKEN`, `api.unit.co`, `api.s.unit.sh` | Provider host plus bearer/API-token label | Implemented SecretSniffer-only |
| Increase | Banking, ACH, Fedwire, cards | `INCREASE_API_KEY`, `INCREASE_WEBHOOK_SECRET`, `api.increase.com` | Provider host plus API/webhook labels | Implemented SecretSniffer-only |
| Lithic | Card issuing and virtual cards | `LITHIC_API_KEY`, `api.lithic.com` | Provider host plus bearer/API-key label | Implemented SecretSniffer-only |
| Marqeta | Card issuing | `application_token`, `admin_access_token`, `sandbox-api.marqeta.com` | Require Marqeta context and app/admin token pair | Implemented SecretSniffer-only |
| Adyen | Payments, issuing, acquiring | `ADYEN_API_KEY`, `ADYEN_HMAC_KEY`, `ws_*@Company.*` | Provider context plus API/HMAC labels or documented username shape | Implemented SecretSniffer-only |
| Alloy | KYC/KYB and fraud workflows | `ALLOY_API_KEY`, `ALLOY_API_SECRET`, `developer.alloy.com` | Provider host plus API key/secret labels | Implemented SecretSniffer-only |
| Persona | KYC/KYB identity verification | `PERSONA_API_KEY`, `PERSONA_WEBHOOK_SECRET`, `api.withpersona.com` | Provider host plus bearer/webhook labels | Implemented SecretSniffer-only |
| Onfido / Entrust IDV | KYC and document verification | `api_live.`, `api_sandbox.`, regional token prefixes | Distinct prefixed token plus optional provider host/header context | Implemented SecretSniffer-only |
| Sumsub | KYC/KYB, AML, travel rule | `X-App-Token`, `X-App-Access-Sig`, `api.sumsub.com` | Exact headers plus provider context; pair app token and secret when possible | Implemented SecretSniffer-only |
| Socure | KYC and fraud | `SOCURE_API_KEY`, `api.socure.com`, `X-API-Key` | Provider host plus exact key label/header | Implemented SecretSniffer-only |
| ComplyAdvantage | AML and sanctions screening | `COMPLYADVANTAGE_API_KEY`, `api.complyadvantage.com` | Provider host plus exact env label | Implemented SecretSniffer-only |
| Chainalysis | Crypto KYT and sanctions | `CHAINALYSIS_API_KEY`, `api.chainalysis.com` | Provider host plus API-key label | Implemented SecretSniffer-only |
| TRM Labs | Crypto AML/KYT | `TRM_LABS_API_KEY`, `api.trmlabs.com` | Provider host plus key/secret label | Implemented SecretSniffer-only |
| Fireblocks | Crypto custody and treasury | `FIREBLOCKS_API_KEY`, `fireblocks_secret.key`, private key PEM | Fireblocks context plus UUID-like API key or private-key filename/context | Implemented SecretSniffer-only |
| BitGo | Crypto custody and wallets | `BITGO_ACCESS_TOKEN`, `app.bitgo.com`, `test.bitgo.com` | Provider host/SDK context plus bearer token label | Implemented SecretSniffer-only |
| Circle | Stablecoin payments and wallets | `CIRCLE_API_KEY`, `api.circle.com`, `api-sandbox.circle.com` | Provider host plus bearer/API-key labels | Implemented SecretSniffer-only |
| Alpaca | Brokerage and trading | `APCA_API_KEY_ID`, `APCA_API_SECRET_KEY`, `paper-api.alpaca.markets` | Exact env/header pair correlation | Implemented SecretSniffer-only |
| DriveWealth | Brokerage APIs | `DRIVEWEALTH_CLIENT_SECRET`, `bo-api.drivewealth` | Provider host plus OAuth/client-secret context | Implemented SecretSniffer-only |
| Teller | Open banking | mTLS certificate/private key, `TELLER_SIGNING_SECRET`, `api.teller.io` | Teller context plus PEM/signing labels; avoid generic private-key duplication | Implemented SecretSniffer-only |
| TrueLayer | Open banking and payments | `TRUELAYER_CLIENT_SECRET`, `TRUELAYER_SIGNING_KEY`, `auth.truelayer.com` | Provider host plus client/signing secret labels | Implemented SecretSniffer-only |
| Yapily | Open banking | `YAPILY_APPLICATION_SECRET`, `api.yapily.com` | App ID plus app secret pair where possible | Implemented SecretSniffer-only |
| Tink | Open banking and payments | `TINK_CLIENT_SECRET`, `oauth.tink.com`, `api.tink.com` | OAuth/client-secret context with provider host | Implemented SecretSniffer-only |

### Additional Implemented SecretSniffer-Only Coverage

| Provider | Use case | Credential context | Detection approach | TruffleHog difference |
| --- | --- | --- | --- | --- |
| Plaid client secrets | Open banking and ACH | `PLAID_SECRET`, `plaid.com`, client secret labels | Provider context plus secret/client-secret labels; complements Plaid access-token coverage | Implemented SecretSniffer-only improvement |
| Coinbase Exchange / Prime | Crypto exchange, custody, prime brokerage | `CB-ACCESS-SECRET`, `CB-ACCESS-PASSPHRASE`, Coinbase Exchange/Prime hosts | Provider host/header context plus secret/passphrase labels | Implemented SecretSniffer-only beyond CDP key coverage |
| MoEngage | Customer engagement and marketing automation | `api.moengage.com`, API secret, app secret | Provider host plus API/app secret labels | Implemented SecretSniffer-only |
| CleverTap | Engagement analytics and messaging | `X-CleverTap-Passcode`, `api.clevertap.com` | Exact passcode/header context plus provider host | Implemented SecretSniffer-only |
| mParticle | CDP and event ingestion | `s2s.mparticle.com`, API secret, server key | Provider host plus API secret/server key labels | Implemented SecretSniffer-only |
| Cohere | LLM API and embeddings | `api.cohere.ai`, API key, bearer token | Provider host plus API/authorization labels | Implemented SecretSniffer-only |
| Mistral AI | LLM API | `api.mistral.ai`, API key, bearer token | Provider host plus API/authorization labels | Implemented SecretSniffer-only |
| Together AI | LLM API and inference | `api.together.xyz`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Fireworks AI | LLM inference platform | `api.fireworks.ai`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Voyage AI | Embeddings and reranking | `api.voyageai.com`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Perplexity | LLM API/search | `api.perplexity.ai`, `pplx-` | Provider host/prefix plus API/bearer token labels | Implemented SecretSniffer-only |
| OpenRouter | LLM routing API | `openrouter.ai`, `sk-or-` | Provider host/prefix plus API/bearer token labels | Implemented SecretSniffer-only |
| AI21 | LLM API | `api.ai21.com`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Cerebras | LLM inference API | `api.cerebras.ai`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Baseten | Model serving platform | `model-apis.baseten.co`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Runpod | GPU and serverless inference | `api.runpod.ai`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Modal | Serverless compute and inference | `api.modal.com`, token secret | Provider host plus token/API secret labels | Implemented SecretSniffer-only |
| fal.ai | Generative media inference | `api.fal.ai`, `fal_key` | Provider host/label plus API/bearer token labels | Implemented SecretSniffer-only |
| Novita AI | Model inference API | `api.novita.ai`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Predibase | Fine-tuning and model serving | `serving.app.predibase.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| OctoAI | Model serving API | `api.octoai.cloud`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Qdrant Cloud | Vector database | `cloud.qdrant.io`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Weaviate Cloud | Vector database | `weaviate.cloud`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Zilliz Cloud | Vector database | `api.cloud.zilliz.com`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Chroma Cloud | Vector database | `api.trychroma.com`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| SEON | Fraud prevention and risk scoring | `api.seon.io`, `X-API-Key`, license key | Provider host/header context plus API/license key labels | Implemented SecretSniffer-only |
| Jumio | KYC and identity verification | `api.jumio.com`, `netverify`, client secret | Provider/API context plus client/API secret labels | Implemented SecretSniffer-only |
| Trulioo | Global identity verification | `api.trulioo.com`, `api.globaldatacompany.com`, `x-trulioo-api-key` | Provider hosts plus exact API-key header labels | Implemented SecretSniffer-only |
| Sardine | Fraud, risk, KYC, AML | `api.sardine.ai`, client secret, API key | Provider host plus client-secret/API-key labels | Implemented SecretSniffer-only |
| Sift | Fraud and trust/risk scoring | `api.sift.com`, REST API key, beacon key | Provider host plus API/rest/beacon key labels | Implemented SecretSniffer-only |
| Forter | Ecommerce fraud prevention | `api.forter.com`, API key, site secret/token | Provider host plus API/secret/token labels | Implemented SecretSniffer-only |
| Riskified | Ecommerce fraud prevention | `api.riskified.com`, auth token, API key | Provider host plus API/auth token labels | Implemented SecretSniffer-only |
| Flagsmith | Feature flags and remote config | `api.flagsmith.com`, server/environment key | Provider host plus server/API/environment key labels | Implemented SecretSniffer-only |
| GrowthBook | Feature flags and experimentation | `api.growthbook.io`, API/SDK/secret key | Provider host plus API/SDK/secret key labels | Implemented SecretSniffer-only |
| Unleash | Feature flags | `unleash-hosted.com`, API/client/admin token | Hosted Unleash context plus token labels | Implemented SecretSniffer-only |
| Split.io | Feature flags and experimentation | `sdk.split.io`, `events.split.io`, SDK/admin key | Split hosts plus SDK/API/admin key labels | Implemented SecretSniffer-only |
| Statsig | Feature gates and experimentation | `api.statsig.com`, server secret, SDK secret | Provider host plus server/SDK secret labels | Implemented SecretSniffer-only |
| ConfigCat | Feature flags | `cdn-global.configcat.com`, SDK/API key | Provider CDN/API context plus SDK/API key labels | Implemented SecretSniffer-only |
| VWO | Experimentation and optimization | `dev.visualwebsiteoptimizer.com`, API token, SDK key | Provider host plus API/account token labels | Implemented SecretSniffer-only |
| AB Tasty | Experimentation and personalization | `api.abtasty.com`, API key, client secret | Provider host plus API/client-secret labels | Implemented SecretSniffer-only |
| Hotjar | Product analytics and feedback | `api.hotjar.com`, API token/key | Provider host plus API token/key labels | Implemented SecretSniffer-only |
| LogRocket | Session replay and frontend observability | `api.logrocket.com`, API key, app secret | Provider host plus API/app secret labels | Implemented SecretSniffer-only |
| Pendo | Product analytics and guides | `api.pendo.io`, integration key, metadata key | Provider host plus integration/API key labels | Implemented SecretSniffer-only |
| Heap | Product analytics | `api.heap.io`, API key, env/app ID | Provider host plus API/token/secret labels | Implemented SecretSniffer-only |
| Contentsquare | Digital experience analytics | `api.contentsquare.com`, API key, client secret | Provider host plus API/client-secret labels | Implemented SecretSniffer-only |
| Gorgias | Ecommerce support desk | `api.gorgias.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Kustomer | Customer support CRM | `api.kustomerapp.com`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Crisp | Customer messaging | `api.crisp.chat`, API token | Provider host plus API/identifier token labels | Implemented SecretSniffer-only |
| Userpilot | Product adoption platform | `api.userpilot.io`, API key/server key | Provider host plus API/server key labels | Implemented SecretSniffer-only |
| Chameleon | Product adoption platform | `api.chameleon.io`, API/secret key | Provider host plus API/secret labels | Implemented SecretSniffer-only |
| Productboard | Product management | `api.productboard.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| UserVoice | Product feedback | `api.uservoice.com`, API token/client secret | Provider host plus API/OAuth secret labels | Implemented SecretSniffer-only |
| Product Fruits | Product onboarding | `api.productfruits.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Vitally | Customer success platform | `api.vitally.io`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Planhat | Customer success platform | `api.planhat.com`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Attio | CRM and customer data | `api.attio.com`, API key, access token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Affinity | Relationship intelligence CRM | `api.affinity.co`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Height | Project management | `api.height.app`, API key, bearer token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Gong | Revenue intelligence | `api.gong.io`, access key secret, API token | Provider host plus access-key/API secret labels | Implemented SecretSniffer-only |
| Chorus | Conversation intelligence | `api.chorus.ai`, API key, access token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Outreach | Sales engagement | `api.outreach.io`, access token, client secret | Provider host plus OAuth/API token labels | Implemented SecretSniffer-only |
| Salesloft | Sales engagement | `api.salesloft.com`, API key, OAuth token | Provider host plus API/OAuth token labels | Implemented SecretSniffer-only |
| Clay | Sales enrichment and GTM automation | `api.clay.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Instantly | Outbound email automation | `api.instantly.ai`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Smartlead | Outbound email automation | `api.smartlead.ai`, API key, client secret | Provider host plus API/client-secret labels | Implemented SecretSniffer-only |
| Salesforce Pardot | Marketing automation | `pi.pardot.com`, client secret, refresh token | Pardot host/context plus OAuth secret labels | Implemented SecretSniffer-only beyond generic Salesforce mappings |
| Front | Shared inbox and customer operations | `api2.frontapp.com`, API token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Inngest | Durable workflow execution | `api.inngest.com`, `signkey-`, signing key | Provider host/prefix plus signing/API key labels | Implemented SecretSniffer-only |
| Trigger.dev | Background jobs and workflow automation | `api.trigger.dev`, `tr_dev_`, `tr_prod_` | Provider host/prefix plus API/token labels | Implemented SecretSniffer-only |
| Temporal Cloud | Durable workflow platform | `cloud.temporal.io`, API key, client secret | Provider host plus API/OAuth secret labels | Implemented SecretSniffer-only |
| Windmill | Workflow automation and internal tools | `app.windmill.dev`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| n8n | Workflow automation | `n8n.io`, API key/token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Workato | Enterprise automation/iPaaS | `apim.workato.com`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Tray.io | Enterprise automation/iPaaS | `api.tray.io`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Airbyte | ELT/data integration | `api.airbyte.com`, API token, client secret | Provider host plus API/OAuth secret labels | Implemented SecretSniffer-only |
| Fivetran | ELT/data integration | `api.fivetran.com`, API secret | Provider host plus API key/secret labels | Implemented SecretSniffer-only |
| Hightouch | Reverse ETL/CDP activation | `api.hightouch.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Typesense Cloud | Search API | `typesense.net`, `x-typesense-api-key` | Provider host/header plus API/admin/search key labels | Implemented SecretSniffer-only |
| Meilisearch | Search API | `meilisearch`, `x-meili-api-key`, master key | Provider/header context plus master/API key labels | Implemented SecretSniffer-only |
| Elastic Cloud | Hosted Elasticsearch/Search | `cloud.elastic.co`, encoded API key | Provider host plus API/authorization labels | Implemented SecretSniffer-only |
| Elastic App Search | Enterprise Search/App Search | `app-search`, private key, API key | App Search context plus private/API key labels | Implemented SecretSniffer-only |
| Bonsai Elasticsearch | Hosted Elasticsearch | `bonsai.io`, API key, password/token | Provider host plus API/token/password labels | Implemented SecretSniffer-only |
| Searchspring | Ecommerce search | `searchspring.net`, API/site key | Provider host plus API/site key labels | Implemented SecretSniffer-only |
| Constructor.io | Ecommerce search and discovery | `constructor.io`, `ac.cnstrc.com`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Coveo | Enterprise search | `platform.cloud.coveo.com`, API key | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Yext | Search and listings | `api.yext.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| OpenSearch | Managed search | `opensearch`, `aoss.amazonaws.com`, API key | Provider context plus API/bearer/password labels | Implemented SecretSniffer-only |
| Contentstack | Headless CMS | `cdn.contentstack.io`, API key, management token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| DatoCMS | Headless CMS | `site-api.datocms.com`, API token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Directus | Headless CMS/data platform | `directus.cloud`, static token | Provider context plus static/API token labels | Implemented SecretSniffer-only |
| Strapi | Headless CMS | `strapi.io`, API token, JWT secret | Provider context plus API/admin secret labels | Implemented SecretSniffer-only |
| Prismic | Headless CMS | `.cdn.prismic.io`, access token | Provider host plus access/permanent token labels | Implemented SecretSniffer-only |
| Builder.io | Visual CMS | `cdn.builder.io`, private key | Provider host plus private/API/write key labels | Implemented SecretSniffer-only |
| commercetools | Composable commerce | `commercetools.com`, client secret | Provider auth/API hosts plus client-secret labels | Implemented SecretSniffer-only |
| BigCommerce | Ecommerce platform | `api.bigcommerce.com`, `x-auth-token` | Provider host/header plus API/access token labels | Implemented SecretSniffer-only |
| Saleor | Composable commerce | `saleor.cloud`, app token, webhook secret | Provider context plus API/app token labels | Implemented SecretSniffer-only |
| Medusa | Commerce backend | `medusajs`, admin API token, JWT secret | Provider context plus admin token/secret labels | Implemented SecretSniffer-only |
| Bunny.net | CDN and object storage | `api.bunny.net`, `storage.bunnycdn.com`, access key | Provider host plus API/storage key labels | Implemented SecretSniffer-only |
| imgix | Image CDN and optimization | `api.imgix.com`, secure URL token | Provider host plus API/secure-token labels | Implemented SecretSniffer-only |
| Akamai EdgeGrid | CDN and edge platform | `.edgerc`, EdgeGrid client secret | Akamai/EdgeGrid context plus client-secret labels | Implemented SecretSniffer-only |
| KeyCDN | CDN | `api.keycdn.com`, API key/token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Filestack | File upload and CDN | `cdn.filestackcontent.com`, API key, app secret | Provider host plus API/secret labels | Implemented SecretSniffer-only |
| Bytescale | File upload and media processing | `api.bytescale.com`, API key | Provider host plus API/secret labels | Implemented SecretSniffer-only |
| Transloadit | Media encoding and uploads | `api2.transloadit.com`, auth key/secret | Provider host plus auth/API key labels | Implemented SecretSniffer-only |
| Gumlet | Image/video optimization CDN | `api.gumlet.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| ImageEngine | Image CDN | `control-api.imageengine.io`, API token | Provider host plus API/delivery token labels | Implemented SecretSniffer-only |
| TinyPNG/Tinify | Image compression API | `api.tinify.com`, API key | Provider host plus API key labels | Implemented SecretSniffer-only |
| OpenPhone | Business phone and messaging | `api.openphone.com`, API key | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Aircall | Cloud phone system | `api.aircall.io`, API token/id | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Dialpad | Business communications | `dialpad.com`, API key | Provider context plus API/access-token labels | Implemented SecretSniffer-only |
| Five9 | Contact center | `five9.com`, client secret | Provider context plus client/API secret labels | Implemented SecretSniffer-only |
| Genesys Cloud | Contact center | `mypurecloud.com`, client secret | Provider host plus OAuth/client-secret labels | Implemented SecretSniffer-only |
| Talkdesk | Contact center | `api.talkdeskapp.com`, API token | Provider host plus API/OAuth token labels | Implemented SecretSniffer-only |
| Ringover | Business phone system | `api.ringover.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| JustCall | Cloud phone system | `api.justcall.io`, API key/secret | Provider host plus API/secret labels | Implemented SecretSniffer-only |
| CallRail | Call tracking | `api.callrail.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| CallTrackingMetrics | Call tracking | `api.calltrackingmetrics.com`, API key/secret | Provider host plus API/secret labels | Implemented SecretSniffer-only |
| incident.io | Incident management | `api.incident.io`, API key, bearer token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| FireHydrant | Incident management and service catalog | `api.firehydrant.io`, service token, API key | Provider host plus API/service-token labels | Implemented SecretSniffer-only |
| Squadcast | Incident response and on-call | `api.squadcast.com`, API token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| ilert | Alerting and on-call | `api.ilert.com`, API key/token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| xMatters | Incident automation | `api.xmatters.com`, API token, password secret | Provider host plus API/token/password labels | Implemented SecretSniffer-only |
| Semgrep AppSec Platform | SAST and supply-chain security | `semgrep.dev`, app token, API token | Provider context plus app/API token labels | Implemented SecretSniffer-only |
| Socket.dev | Dependency and supply-chain security | `api.socket.dev`, API key | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Aikido Security | AppSec and cloud security | `app.aikido.dev`, API token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Infisical | Secrets management | `app.infisical.com`, service token, client secret | Provider host plus service/access-token labels | Implemented SecretSniffer-only |
| Render | App hosting and deployment | `api.render.com`, API key/token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Koyeb | App hosting and deployment | `api.koyeb.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Northflank | App hosting and deployment | `api.northflank.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Qovery | App hosting and deployment | `api.qovery.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Porter | Kubernetes app platform | `dashboard.porter.run`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| EnvKey | Secrets and configuration management | `envkey.com`, server key/org token | Provider context plus server/API token labels | Implemented SecretSniffer-only |
| Akeyless | Secrets management | `api.akeyless.io`, access secret | Provider host plus access/API secret labels | Implemented SecretSniffer-only |
| Platform.sh | App hosting and deployment | `api.platform.sh`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Flightcontrol | AWS deployment platform | `app.flightcontrol.dev`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Cleavr | Server provisioning and deployment | `cleavr.io`, API key | Provider context plus API/bearer token labels | Implemented SecretSniffer-only |
| Neon | Serverless Postgres | `api.neon.tech`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Turso | Edge SQLite database | `api.turso.tech`, auth token | Provider host plus API/auth token labels | Implemented SecretSniffer-only |
| Xata | Serverless database/search | `api.xata.io`, API key | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| Cockroach Cloud | Distributed SQL database | `api.cockroachlabs.cloud`, API key | Provider host plus API/service-account secret labels | Implemented SecretSniffer-only |
| Upstash | Redis/Kafka/QStash | `api.upstash.com`, REST token | Provider host plus REST/API token labels | Implemented SecretSniffer-only |
| MotherDuck | DuckDB cloud data warehouse | `motherduck.com`, access token | Provider context plus token/API key labels | Implemented SecretSniffer-only |
| Grafbase | GraphQL backend platform | `api.grafbase.com`, API key | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| SingleStore | Cloud database | `api.singlestore.com`, API key | Provider host plus API/management-token labels | Implemented SecretSniffer-only |
| Timescale | Managed PostgreSQL/TimescaleDB | `api.timescale.com`, API key | Provider host plus API/token/password labels | Implemented SecretSniffer-only |
| Convex | Backend/database platform | `api.convex.dev`, deploy key | Provider host plus deploy/admin key labels | Implemented SecretSniffer-only |
| Cronitor | Monitoring and cron observability | `cronitor.io`, API key, telemetry key | Provider host plus API/telemetry key labels | Implemented SecretSniffer-only |
| Greenhouse Harvest | Applicant tracking | `harvest.greenhouse.io`, Harvest API key | Provider API host plus Harvest/API key labels | Implemented SecretSniffer-only |
| Lever | Applicant tracking | `api.lever.co`, API key, OAuth secret | Provider API host plus API/access-token labels | Implemented SecretSniffer-only |
| Ashby | Applicant tracking | `api.ashbyhq.com`, API key | Provider API host plus API/bearer token labels | Implemented SecretSniffer-only |
| Workable | Applicant tracking | `api.workable.com`, API token | Provider API host plus API token/key labels | Implemented SecretSniffer-only |
| SmartRecruiters | Applicant tracking | `api.smartrecruiters.com`, `x-smarttoken` | Provider API host plus exact token/API key labels | Implemented SecretSniffer-only |
| Personio | HRIS and recruiting | `api.personio.de`, client secret, API secret | Provider API host plus client/API secret labels | Implemented SecretSniffer-only |
| HiBob | HRIS | `api.hibob.com`, service token | Provider API host plus service/API token labels | Implemented SecretSniffer-only |
| BambooHR | HRIS | `api.bamboohr.com`, API key | Provider API host plus API/access-token labels | Implemented SecretSniffer-only |
| Rippling | HRIS and identity | `api.rippling.com`, API token | Provider API host plus API/access-token labels | Implemented SecretSniffer-only |
| Deel | HR/payroll and contractor management | `api.deel.com`, API token | Provider API host plus API/access-token labels | Implemented SecretSniffer-only |
| Gusto | Payroll and benefits | `api.gusto.com`, API token, client secret | Provider API host plus API/OAuth secret labels | Implemented SecretSniffer-only |
| Workday | HRIS and finance | `workday.com`, client secret, refresh token | Workday host/context plus OAuth secret labels | Implemented SecretSniffer-only |
| Canvas / Instructure | Learning management system | `canvas.instructure.com`, access token | Provider host plus access/API token labels | Implemented SecretSniffer-only |
| Blackboard | Learning management system | `learn.blackboard.com`, REST/client secret | Provider host plus REST/client secret labels | Implemented SecretSniffer-only |
| Moodle | Learning management system | `wstoken`, Moodle webservice endpoint | Moodle/webservice context plus token labels | Implemented SecretSniffer-only |
| Brightspace / D2L | Learning management system | `auth.brightspace.com`, client secret | Provider host plus OAuth secret labels | Implemented SecretSniffer-only |
| Schoology | Learning management system | `api.schoology.com`, consumer/API secret | Provider host plus consumer/API secret labels | Implemented SecretSniffer-only |
| Teachable | Online course platform | `developers.teachable.com`, API key/token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Kajabi | Online course and creator platform | `api.kajabi.com`, API key/token | Provider host plus API/token labels | Implemented SecretSniffer-only |
| LearnWorlds | Online course platform | `api.learnworlds.com`, API key, client secret | Provider host plus API/client-secret labels | Implemented SecretSniffer-only |
| TalentLMS | Learning management system | `talentlms.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| Docebo | Enterprise learning platform | `api.docebo.com`, access token, client secret | Provider host plus API/OAuth token labels | Implemented SecretSniffer-only |
| Shippo | Shipping and fulfillment | `api.goshippo.com`, API token | Provider host plus API/bearer token labels | Implemented SecretSniffer-only |
| EasyPost | Shipping and fulfillment | `api.easypost.com`, `EZAK`, `EZTK` | Provider host plus EasyPost key prefixes/API labels | Implemented SecretSniffer-only |
| ShipStation | Shipping and order fulfillment | `ssapi.shipstation.com`, API key/secret | Provider host plus API key/secret labels | Implemented SecretSniffer-only |
| ShipEngine | Shipping API | `api.shipengine.com`, API key | Provider host plus API/token labels | Implemented SecretSniffer-only |
| AfterShip | Shipment tracking | `api.aftership.com`, API key | Provider host plus API key labels | Implemented SecretSniffer-only |
| Easyship | Shipping and fulfillment | `api.easyship.com`, API token | Provider host plus API/access-token labels | Implemented SecretSniffer-only |
| Sendcloud | Shipping platform | `panel.sendcloud.sc`, API key/secret | Provider host plus API key/secret labels | Implemented SecretSniffer-only |
| Avalara AvaTax | Tax compliance | `rest.avatax.com`, license key | Provider host plus license/API secret labels | Implemented SecretSniffer-only |
| Vertex Tax | Tax compliance | `vertexinc.com`, client secret, trusted ID | Provider context plus tax API secret labels | Implemented SecretSniffer-only |
| TaxBit | Crypto tax compliance | `api.taxbit.com`, API key/secret | Provider host plus API/token labels | Implemented SecretSniffer-only |
| signNow | E-signature | `api.signnow.com`, access token, client secret | Provider host plus API/OAuth token labels | Implemented SecretSniffer-only |
| Adobe Acrobat Sign | E-signature | `api.adobesign.com`, client secret | Provider host plus client/integration secret labels | Implemented SecretSniffer-only |

## Explicit Differences From TruffleHog

- SecretSniffer is detector-first and does not use TruffleHog's discovery algorithm.
- The generated TruffleHog catalog is used only for compatibility accounting; no TruffleHog regexes, verifier logic, source code, or documentation text are copied.
- Raw secrets are included by default for remediation workflows; use `--redact` to omit them from machine-readable output.
- Archive scanning is opt-in with `--scan-archives`; supported archive contents are expanded in memory and reported with virtual paths.
- Some TruffleHog IDs are intentionally `partial` where this project detects only the high-confidence credential side and avoids tuple-free matches, such as exchange key/secret pairs, OAuth client ID/secret pairs, and generic `host`/`user` fields.
- Generic standalone fields such as `host`, `user`, and broad credential labels are not treated as findings unless they appear inside credentialed URL or provider-specific context.
- Box detection intentionally requires Box JWT/OAuth configuration context such as `boxAppSettings` or the Box OAuth token endpoint to avoid the high false-positive behavior commonly seen with generic `box` proximity matching.
- Provider verification is opt-in and currently available only for selected providers; unverified detector coverage is tracked separately from live validation coverage.

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
