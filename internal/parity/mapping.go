package parity

type Status string

const (
	Implemented Status = "implemented"
	Partial     Status = "partial"
	Planned     Status = "planned"
)

type Mapping struct {
	TruffleHogID    string  `json:"trufflehog_id"`
	SecretSnifferID *string `json:"secret_sniffer_id"`
	Status          Status  `json:"status"`
	Category        string  `json:"category"`
	Notes           string  `json:"notes,omitempty"`
}

type Report struct {
	SnapshotCommit           string    `json:"snapshot_commit"`
	CatalogSize              int       `json:"catalog_size"`
	TotalTracked             int       `json:"total_tracked"`
	CatalogTracked           int       `json:"catalog_tracked"`
	SubDetectorTracked       int       `json:"sub_detector_tracked"`
	DuplicateMappings        int       `json:"duplicate_mappings"`
	Implemented              int       `json:"implemented"`
	Partial                  int       `json:"partial"`
	Planned                  int       `json:"planned"`
	Untracked                int       `json:"untracked"`
	UntrackedTruffleHogs     []string  `json:"untracked_trufflehog_ids"`
	SubDetectorTruffleHogIDs []string  `json:"sub_detector_trufflehog_ids"`
	DuplicateTruffleHogIDs   []string  `json:"duplicate_trufflehog_ids"`
	Mappings                 []Mapping `json:"mappings"`
}

const SnapshotCommit = GeneratedSnapshotCommit

func CurrentReport() Report {
	m := CurrentMappings()
	r := Report{SnapshotCommit: SnapshotCommit, CatalogSize: len(TruffleHogCatalog), TotalTracked: len(m), Mappings: m}
	for _, entry := range m {
		switch entry.Status {
		case Implemented:
			r.Implemented++
		case Partial:
			r.Partial++
		case Planned:
			r.Planned++
		}
	}
	r.CatalogTracked, r.SubDetectorTracked, r.DuplicateMappings, r.SubDetectorTruffleHogIDs, r.DuplicateTruffleHogIDs = mappedCatalogStats(m)
	r.UntrackedTruffleHogs = untrackedCatalogIDs(m)
	r.Untracked = len(r.UntrackedTruffleHogs)
	return r
}

func mappedCatalogStats(mappings []Mapping) (catalogTracked, subDetectorTracked, duplicateMappings int, subDetectorIDs, duplicateIDs []string) {
	catalog := catalogSet()
	seen := map[string]int{}
	for _, m := range mappings {
		seen[m.TruffleHogID]++
	}
	for id, count := range seen {
		if _, ok := catalog[id]; ok {
			catalogTracked++
		} else {
			subDetectorTracked++
			subDetectorIDs = append(subDetectorIDs, id)
		}
		if count > 1 {
			duplicateMappings += count - 1
			duplicateIDs = append(duplicateIDs, id)
		}
	}
	return catalogTracked, subDetectorTracked, duplicateMappings, subDetectorIDs, duplicateIDs
}

func untrackedCatalogIDs(mappings []Mapping) []string {
	tracked := map[string]struct{}{}
	catalog := catalogSet()
	for _, m := range mappings {
		if _, ok := catalog[m.TruffleHogID]; ok {
			tracked[m.TruffleHogID] = struct{}{}
		}
	}
	untracked := make([]string, 0, len(TruffleHogCatalog))
	for _, id := range TruffleHogCatalog {
		if _, ok := tracked[id]; !ok {
			untracked = append(untracked, id)
		}
	}
	return untracked
}

func catalogSet() map[string]struct{} {
	catalog := make(map[string]struct{}, len(TruffleHogCatalog))
	for _, id := range TruffleHogCatalog {
		catalog[id] = struct{}{}
	}
	return catalog
}

func CurrentMappings() []Mapping {
	return []Mapping{
		mapImplemented("cloud/infrastructure", "cloudflareapitoken", "cloudflare-api-token", "Cloudflare API token."),
		mapImplemented("cloud/infrastructure", "digitaloceantoken", "digitalocean-token", "DigitalOcean token."),
		mapImplemented("cloud/infrastructure", "heroku", "heroku-api-key", "Heroku API key."),
		mapImplemented("container/infrastructure", "dockerhub", "dockerhub-token", "Docker Hub token."),
		mapPartial("cloud/infrastructure", "aws", "aws-access-key", "Access key covered; paired AWS verification not implemented yet."),
		mapPartial("cloud/infrastructure", "aws", "aws-secret-key", "Secret key covered; paired AWS verification not implemented yet."),
		mapPartial("cloud/infrastructure", "digitaloceanv2", "digitalocean-token", "Existing detector covers core DigitalOcean token shape."),
		mapPartial("cloud/infrastructure", "googleoauth2", "google-oauth-client-secret", "OAuth client secret covered; full OAuth credential pair planned."),
		mapPlanned("cloud/infrastructure", "aws/session_keys", "AWS session token."),
		mapPlanned("cloud/infrastructure", "aws/appsync", "AWS AppSync API key."),
		mapPlanned("cloud/infrastructure", "azure_batch", "Azure Batch key."),
		mapImplemented("cloud/infrastructure", "azure_cosmosdb", "azure-cosmosdb-connection-string", "Azure Cosmos DB connection string coverage."),
		mapPlanned("cloud/infrastructure", "azure_openai", "Azure OpenAI key."),
		mapImplemented("cloud/infrastructure", "azure_storage", "azure-storage-connection-string", "Azure Storage connection string coverage."),
		mapImplemented("cloud/infrastructure", "azureappconfigconnectionstring", "azure-app-config-connection-string", "Azure App Configuration connection string coverage."),
		mapImplemented("cloud/infrastructure", "azurefunctionkey", "azure-function-key-url", "Azure Function key URL coverage."),
		mapImplemented("cloud/infrastructure", "azuresastoken", "azure-sas-url", "Azure SAS URL coverage."),
		mapPlanned("container/infrastructure", "azurecontainerregistry", "Azure Container Registry credential."),
		mapPlanned("cloud/infrastructure", "gcp", "GCP service account JSON key."),
		mapPlanned("cloud/infrastructure", "gcpapplicationdefaultcredentials", "GCP application default credentials."),
		mapImplemented("cloud/infrastructure", "cloudflarecakey", "cloudflare-ca-key", "Cloudflare CA key coverage."),
		mapPlanned("cloud/infrastructure", "cloudflareglobalapikey", "Cloudflare global API key."),
		mapPlanned("container/infrastructure", "docker", "Docker auth config."),
		mapPlanned("cloud/infrastructure", "hashicorpvaultauth", "HashiCorp Vault auth token."),
		mapImplemented("cloud/infrastructure", "terraformcloudpersonaltoken", "terraform-cloud-token", "Terraform Cloud token coverage."),
		mapPlanned("cloud/infrastructure", "aiven", "Aiven token."),
		mapPlanned("cloud/infrastructure", "alibaba", "Alibaba Cloud access key."),
		mapPlanned("cloud/infrastructure", "scalewaykey", "Scaleway key."),
		mapPlanned("cloud/infrastructure", "vercel", "Vercel token."),
		mapImplemented("cloud/infrastructure", "netlify", "netlify-token", "Netlify token coverage."),
		mapImplemented("cloud/infrastructure", "flyio", "flyio-token", "Fly.io token coverage."),
		mapPlanned("cloud/infrastructure", "railwayapp", "Railway token."),
		mapImplemented("cloud/infrastructure", "pulumi", "pulumi-token", "Pulumi access token coverage."),
		mapImplemented("cloud/infrastructure", "doppler", "doppler-token", "Doppler token coverage."),
		mapImplemented("cloud/infrastructure", "tailscale", "tailscale-key", "Tailscale auth/API/client key coverage."),
		mapImplemented("cloud/infrastructure", "ngrok", "ngrok-token", "ngrok API/PAT token coverage."),

		mapImplemented("vcs", "github", "github-token", "GitHub classic and prefixed token coverage."),
		mapImplemented("vcs", "github/v2", "github-pat-v2", "GitHub fine-grained token coverage."),
		mapImplemented("vcs", "gitlab", "gitlab-token", "GitLab token coverage."),
		mapImplemented("vcs", "bitbucketapppassword", "bitbucket-app-password", "Bitbucket app password coverage."),
		mapImplemented("package-registry", "npmtoken", "npm-token", "npm token coverage."),
		mapImplemented("package-registry", "npmtokenv2", "npm-token", "npm v2 token coverage."),
		mapImplemented("package-registry", "pypi", "pypi-token", "PyPI token coverage."),
		mapImplemented("developer-tooling", "postman", "postman-api-key", "Postman API key coverage."),
		mapImplemented("developer-tooling", "linearapi", "linear-api-key", "Linear API key coverage."),
		mapPlanned("vcs", "github_oauth2", "GitHub OAuth2 credentials."),
		mapPlanned("vcs", "githubapp", "GitHub App private keys."),
		mapPlanned("vcs", "gitlaboauth2", "GitLab OAuth2 credentials."),
		mapImplemented("vcs", "azuredevopspersonalaccesstoken", "azure-devops-pat", "Azure DevOps new-format PAT coverage."),
		mapImplemented("package-registry", "nugetapikey", "nuget-api-key", "NuGet API key coverage."),
		mapImplemented("package-registry", "rubygems", "rubygems-api-key", "RubyGems API key coverage."),
		mapImplemented("package-registry", "artifactory", "artifactory-access-token", "JFrog Artifactory access token coverage."),
		mapImplemented("package-registry", "artifactoryreferencetoken", "artifactory-reference-token", "JFrog Artifactory reference token coverage."),
		mapImplemented("developer-tooling", "circleci", "circleci-pat", "CircleCI personal access token coverage."),
		mapImplemented("developer-tooling", "buildkite", "buildkite-token", "Buildkite token coverage."),
		mapPlanned("developer-tooling", "travisci", "Travis CI token."),
		mapImplemented("developer-tooling", "snykkey", "snyk-api-key", "Snyk API key coverage with provider context."),
		mapImplemented("developer-tooling", "sourcegraph", "sourcegraph-token", "Sourcegraph access token coverage."),
		mapImplemented("developer-tooling", "sourcegraphcody", "sourcegraph-cody-token", "Sourcegraph Cody token coverage."),
		mapImplemented("developer-tooling", "jiratoken", "jira-api-token", "Jira API token coverage."),
		mapImplemented("developer-tooling", "atlassian", "atlassian-api-token", "Atlassian API token coverage."),
		mapImplemented("developer-tooling", "launchdarkly", "launchdarkly-key", "LaunchDarkly server-side API/SDK key coverage."),
		mapImplemented("developer-tooling", "shortcut", "shortcut-api-token", "Shortcut API token coverage with provider context."),

		mapImplemented("communication", "slack", "slack-token", "Slack token coverage."),
		mapImplemented("communication", "discordbottoken", "discord-bot-token", "Discord bot token coverage."),
		mapImplemented("communication", "telegrambottoken", "telegram-bot-token", "Telegram bot token coverage."),
		mapImplemented("communication", "sendgrid", "sendgrid-key", "SendGrid key coverage."),
		mapImplemented("communication", "mailgun", "mailgun-key", "Mailgun key coverage."),
		mapImplemented("communication", "twilioapikey", "twilio-key", "Twilio SK API key coverage."),
		mapImplemented("incident-management", "pagerdutyapikey", "pagerduty-token", "PagerDuty key coverage."),
		mapImplemented("observability", "datadogapikey", "datadog-api-key", "Datadog API key coverage."),
		mapImplemented("observability", "newrelicpersonalapikey", "new-relic-key", "New Relic key coverage."),
		mapPartial("communication", "twilio", "twilio-auth-token", "Account SID plus auth token coverage; live verification planned."),
		mapImplemented("communication", "slackwebhook", "slack-webhook", "Slack webhook URL coverage."),
		mapImplemented("communication", "discordwebhook", "discord-webhook", "Discord webhook URL coverage."),
		mapImplemented("communication", "microsoftteamswebhook", "microsoft-teams-webhook", "Microsoft Teams webhook URL coverage."),
		mapPlanned("communication", "webex", "Webex credentials."),
		mapImplemented("communication", "webexbot", "webex-bot-token", "Webex bot token coverage."),
		mapPlanned("observability", "datadogtoken", "Datadog app key/API key pair."),
		mapImplemented("observability", "grafana", "grafana-token", "Grafana token coverage."),
		mapImplemented("observability", "grafanaserviceaccount", "grafana-service-account-token", "Grafana service account token coverage."),
		mapImplemented("observability", "sentryorgtoken", "sentry-org-token", "Sentry organization token coverage."),
		mapImplemented("observability", "sentrytoken", "sentry-user-token", "Sentry user token coverage."),
		mapImplemented("observability", "honeycomb", "honeycomb-api-key", "Honeycomb API key coverage with provider context."),
		mapImplemented("observability", "splunkobservabilitytoken", "splunk-observability-token", "Splunk Observability token coverage with provider context."),
		mapImplemented("incident-management", "opsgenie", "opsgenie-api-key", "Opsgenie API key coverage with provider context."),
		mapPlanned("observability", "betterstack", "BetterStack API key."),

		mapImplemented("database", "mongodb", "mongodb-uri", "MongoDB URI coverage."),
		mapImplemented("database", "postgres", "postgres-uri", "PostgreSQL URI coverage."),
		mapPartial("database", "jdbc", "mysql-uri", "MySQL URI covered outside JDBC envelope."),
		mapPlanned("database", "redis", "Redis credential."),
		mapPlanned("database", "snowflake", "Snowflake credential."),
		mapPlanned("database", "couchbase", "Couchbase credential."),
		mapImplemented("ai-ml", "openai", "openai-key", "OpenAI API key coverage."),
		mapImplemented("ai-ml", "anthropic", "anthropic-key", "Anthropic API key coverage."),
		mapPartial("ai-ml", "googlegemini", "google-api-key", "Generic Google API key covers Gemini key shape."),
		mapImplemented("ai-ml", "groq", "groq-api-key", "Groq API key coverage."),
		mapImplemented("ai-ml", "huggingface", "huggingface-token", "Hugging Face token coverage."),
		mapImplemented("ai-ml", "replicate", "replicate-token", "Replicate token coverage."),
		mapImplemented("payment", "stripe", "stripe-key", "Stripe key coverage."),
		mapImplemented("payment", "square", "square-token", "Square token coverage."),
		mapImplemented("payment", "paypaloauth", "paypal-token", "PayPal token coverage."),
		mapImplemented("commerce", "shopify", "shopify-token", "Shopify token coverage."),
		mapPlanned("payment", "braintreepayments", "Braintree payment credentials."),
		mapPartial("payment", "razorpay", "razorpay-key", "Razorpay key ID covered; paired secret correlation planned."),
		mapPlanned("payment", "coinbase", "Coinbase credentials."),
		mapImplemented("generic", "jwt", "jwt", "JWT coverage."),
		mapImplemented("generic", "privatekey", "private-key", "PEM private key coverage."),
		mapImplemented("generic", "privatekey/ssh", "ssh-private-key", "OpenSSH private key coverage."),
		mapImplemented("generic", "uri", "basic-auth-url", "Credentialed URI coverage."),
		mapImplemented("generic", "generic", "generic-assigned-secret", "Assigned generic secret coverage."),

		mapImplemented("marketing/crm", "hubspot_apikey", "hubspot-private-app-token", "HubSpot private app token coverage."),
		mapImplemented("marketing/crm", "mailchimp", "mailchimp-key", "Mailchimp API key coverage."),
		mapImplemented("customer-success", "intercom", "intercom-access-token", "Intercom access token coverage with provider context."),
		mapPlanned("customer-support", "zendeskapi", "Zendesk API token."),
		mapPartial("crm", "salesforce", "salesforce-access-token", "Salesforce access token shape covered; instance correlation and verification planned."),
		mapPartial("crm", "salesforceoauth2", "salesforce-consumer-key", "Salesforce OAuth consumer key covered; consumer secret correlation planned."),
		mapImplemented("crm", "salesforcerefreshtoken", "salesforce-refresh-token", "Salesforce refresh token coverage."),
		mapPlanned("marketing-automation", "customerio", "Customer.io API key."),
		mapImplemented("email-marketing", "klaviyo", "klaviyo-key", "Klaviyo API key coverage."),
		mapImplemented("sales-scheduling", "calendlyapikey", "calendly-api-key", "Calendly API key coverage with provider context."),
		mapImplemented("forms/customer-data", "typeform", "typeform-token", "Typeform token coverage."),
		mapImplemented("collaboration/customer-data", "airtablepersonalaccesstoken", "airtable-pat", "Airtable personal access token coverage."),
		mapImplemented("collaboration/customer-data", "coda", "coda-api-token", "Coda API token coverage with provider context."),
		mapImplemented("collaboration/customer-data", "notion", "notion-token", "Notion token coverage."),
		mapImplemented("project-management", "asanapersonalaccesstoken", "asana-pat", "Asana personal access token coverage."),
		mapImplemented("project-management/crm", "monday", "monday-api-token", "Monday.com API token coverage with provider context."),
		mapImplemented("project-management", "clickuppersonaltoken", "clickup-token", "ClickUp personal token coverage."),
		mapPlanned("project-management", "trelloapikey", "Trello API key."),
		mapPlanned("project-management", "wrike", "Wrike API token."),
		mapPlanned("customer-support", "freshdesk", "Freshdesk API key."),
		mapPlanned("customer-support", "helpscout", "Help Scout API key."),
		mapImplemented("customer-support/email-saas", "front", "front-api-token", "Front API token coverage."),
		mapPlanned("crm", "closecrm", "Close CRM API key."),
		mapPlanned("crm", "pipedrive", "Pipedrive API token."),
		mapPlanned("email-marketing", "mailerlite", "MailerLite API key."),
		mapImplemented("email-saas", "mailjetbasicauth", "mailjet-basic-auth", "Mailjet basic auth credential coverage with provider context."),
		mapPlanned("email-saas", "mandrill", "Mandrill API key."),
		mapImplemented("email-saas", "postmark", "postmark-token", "Postmark server token coverage with provider context."),
		mapPlanned("email-saas", "sparkpost", "SparkPost API key."),
		mapImplemented("email-saas", "elasticemail", "elastic-email-api-key", "Elastic Email API key coverage with provider context."),
		mapPlanned("customer-messaging", "onesignal", "OneSignal app/API key."),
		mapImplemented("crm", "zohocrm", "zoho-crm-token", "Zoho CRM token coverage."),
		mapPlanned("crm", "copper", "Copper CRM API key."),
		mapPlanned("crm", "capsulecrm", "Capsule CRM API key."),
		mapPlanned("sales-intelligence", "apollo", "Apollo API key."),
		mapPlanned("sales-engagement/email-saas", "lemlist", "Lemlist API key."),
		mapPlanned("email-marketing", "getresponse", "GetResponse API key."),

		mapPlanned("security/scanning", "shodankey", "Shodan API key."),
		mapPlanned("threat-intel", "virustotal", "VirusTotal API key."),
		mapImplemented("identity/auth", "okta", "okta-api-token", "Okta API token coverage with Okta domain context."),
		mapPlanned("identity/auth", "auth0managementapitoken", "Auth0 Management API token."),
		mapPlanned("identity/auth", "auth0oauth", "Auth0 OAuth credential."),
		mapPlanned("identity/auth", "onelogin", "OneLogin API credential."),
		mapPlanned("identity/auth", "jumpcloud", "JumpCloud API key."),
		mapImplemented("security/dlp", "nightfall", "nightfall-api-key", "Nightfall DLP API key coverage."),
		mapPlanned("security/scanning", "detectify", "Detectify API key."),
		mapPlanned("threat-intel", "securitytrails", "SecurityTrails API key."),
		mapImplemented("threat-intel", "urlscan", "urlscan-api-key", "urlscan.io API key coverage with provider context."),
		mapPlanned("threat-intel", "abuseipdb", "AbuseIPDB API key."),
		mapPlanned("threat-intel", "alienvault", "AlienVault OTX API key."),
		mapPlanned("threat-intel", "censys", "Censys API credentials."),
		mapPlanned("vpn/threat-intel", "vpnapi", "VPNAPI.io API key."),
		mapPlanned("threat-intel/fraud", "ipquality", "IPQualityScore API key."),
		mapPlanned("threat-intel/geolocation", "ipinfo", "IPinfo token."),
		mapPlanned("threat-intel/geolocation", "ipstack", "IPstack API key."),
		mapPlanned("threat-intel/geolocation", "ipgeolocation", "IPGeolocation API key."),
		mapImplemented("security/scanning", "spectralops", "spectralops-token", "SpectralOps API key coverage."),
		mapPlanned("cloud-security", "wiz", "Wiz API credential."),
		mapPlanned("security/asset-inventory", "jupiterone", "JupiterOne API token."),
		mapPartial("security/scanning", "endorlabs", "endorlabs-token", "Endor Labs token coverage; paired key/secret correlation planned."),
		mapPartial("security/scanning", "trufflehogenterprise", "trufflehog-enterprise-key", "TruffleHog Enterprise key/secret shapes covered; tuple correlation planned."),
		mapPlanned("vpn/auth", "openvpn", "OpenVPN credential/config secret."),
		mapPlanned("vpn/auth", "zerotier", "ZeroTier API token."),
		mapPlanned("identity/auth", "azure_entra", "Microsoft Entra identity credential."),
		mapPlanned("identity/auth", "ldap", "LDAP credential."),
		mapPlanned("identity/auth", "loginradius", "LoginRadius API secret."),
		mapPlanned("identity/auth", "stytch", "Stytch API credential."),

		mapImplemented("crypto", "coinapi", "coinapi-key", "CoinAPI market data API key coverage with provider context."),
		mapPlanned("crypto", "coinlayer", "CoinLayer cryptocurrency rates API key."),
		mapPlanned("crypto", "coinlib", "Coinlib cryptocurrency data API key."),
		mapPlanned("crypto", "cryptocompare", "CryptoCompare API key."),
		mapPlanned("crypto", "bitcoinaverage", "BitcoinAverage market data key."),
		mapPlanned("crypto", "worldcoinindex", "WorldCoinIndex API key."),
		mapImplemented("crypto", "etherscan", "etherscan-api-key", "Etherscan API key coverage with provider context."),
		mapImplemented("crypto", "bscscan", "bscscan-api-key", "BscScan API key coverage with provider context."),
		mapPlanned("crypto", "blocknative", "Blocknative API key."),
		mapPlanned("finance", "fixerio", "Fixer.io exchange-rate API key."),
		mapPlanned("finance", "currencylayer", "Currencylayer exchange-rate API key."),
		mapPlanned("finance", "exchangerateapi", "ExchangeRate-API key."),
		mapPlanned("finance", "exchangeratesapi", "ExchangeRatesAPI key."),
		mapPlanned("finance", "currencyfreaks", "CurrencyFreaks API key."),
		mapPlanned("finance", "currencyscoop", "CurrencyScoop API key."),
		mapPlanned("finance", "fastforex", "FastForex API key."),
		mapPlanned("finance", "marketstack", "Marketstack market data API key."),
		mapPlanned("finance", "financialmodelingprep", "Financial Modeling Prep API key."),
		mapPlanned("finance", "finnhub", "Finnhub market data API key."),
		mapPlanned("finance", "polygon", "Polygon.io financial data API key."),
		mapPlanned("finance", "tradier", "Tradier brokerage API token."),
		mapPlanned("finance", "twelvedata", "Twelve Data API key."),
		mapPlanned("finance", "vatlayer", "VATLayer API key."),
		mapPlanned("weather/geolocation", "weatherstack", "Weatherstack API key."),
		mapPlanned("weather/geolocation", "openweather", "OpenWeather API key."),
		mapPlanned("weather/geolocation", "accuweather", "AccuWeather API key."),
		mapPlanned("weather/geolocation", "weatherbit", "Weatherbit API key."),
		mapPlanned("weather/geolocation", "worldweather", "World Weather Online API key."),
		mapPlanned("weather/geolocation", "tomorrowio", "Tomorrow.io API key."),
		mapImplemented("weather/geolocation", "mapbox", "mapbox-secret-token", "Mapbox secret token coverage; public pk tokens intentionally ignored."),
		mapPlanned("weather/geolocation", "mapquest", "MapQuest API key."),
		mapPlanned("weather/geolocation", "positionstack", "Positionstack geocoding API key."),
		mapImplemented("weather/geolocation", "locationiq", "locationiq-api-key", "LocationIQ API key coverage with provider context."),
		mapPlanned("weather/geolocation", "hereapi", "HERE API key."),
		mapPlanned("weather/geolocation", "geocode", "Generic geocode API key."),
		mapPlanned("weather/geolocation", "geocodio", "Geocodio API key."),
		mapPlanned("data-provider", "newsapi", "NewsAPI key."),
		mapImplemented("data-provider", "guardianapi", "guardian-api-key", "Guardian Open Platform API key coverage with provider context."),
		mapPartial("public-api", "youtubeapikey", "google-api-key", "YouTube API key shape covered by generic Google API key detector."),
		mapPlanned("public-api", "facebookoauth", "Facebook OAuth credential."),
		mapPlanned("public-api", "twitter", "Twitter/X API credentials."),
		mapPlanned("public-api", "twitterconsumerkey", "Twitter/X consumer key."),
		mapPlanned("public-api", "twitch", "Twitch API credentials."),
		mapPlanned("public-api", "twitchaccesstoken", "Twitch access token."),

		mapImplemented("ai-ml", "deepseek", "deepseek-api-key", "DeepSeek API key coverage with provider context."),
		mapImplemented("ai-ml", "openaiadmin", "openai-admin-key", "OpenAI admin key coverage."),
		mapImplemented("ai-ml", "elevenlabs", "elevenlabs-api-key", "ElevenLabs API key coverage with provider context."),
		mapImplemented("ai-ml", "langsmith", "langsmith-api-key", "LangSmith API key coverage."),
		mapImplemented("ai-ml", "langfuse", "langfuse-secret-key", "Langfuse secret key coverage."),
		mapImplemented("ai-ml", "weightsandbiases", "weightsandbiases-api-key", "Weights & Biases API key coverage with provider context."),
		mapImplemented("ai-ml", "pinecone", "pinecone-api-key", "Pinecone API key coverage."),
		mapImplemented("ai-ml", "xai", "xai-api-key", "xAI API key coverage."),
		mapImplemented("ai-ml", "assemblyai", "assemblyai-api-key", "AssemblyAI API key coverage with provider context."),
		mapImplemented("ai-ml", "deepgram", "deepgram-api-key", "Deepgram API key coverage with provider context."),
		mapImplemented("ai-ml", "edenai", "edenai-api-key", "Eden AI API key coverage with provider context."),
		mapImplemented("ai-ml", "voiceflow", "voiceflow-api-key", "Voiceflow API key coverage."),
		mapImplemented("ai-ml", "monkeylearn", "monkeylearn-api-key", "MonkeyLearn API key coverage with provider context."),
		mapImplemented("cms", "contentfulpersonalaccesstoken", "contentful-pat", "Contentful personal access token coverage."),
		mapImplemented("cms", "storyblokpersonalaccesstoken", "storyblok-personal-access-token", "Storyblok personal access token coverage."),
		mapImplemented("cms", "storyblok", "storyblok-access-token", "Storyblok access token coverage with provider context."),
		mapImplemented("cms", "sanity", "sanity-auth-token", "Sanity auth token coverage with provider context."),
		mapImplemented("website/cms", "webflow", "webflow-api-key", "Webflow API key coverage with provider context."),
		mapPlanned("observability", "logzio", "Logz.io token."),
		mapPartial("observability", "sumologickey", "sumologic-access-key", "Sumo Logic access key covered; access ID correlation planned."),
		mapImplemented("observability", "uptimerobot", "uptimerobot-api-key", "UptimeRobot API key coverage with provider context."),
		mapPlanned("ci-cd", "sonarcloud", "SonarCloud token."),
		mapPlanned("ci-cd", "codeclimate", "Code Climate token."),
		mapPlanned("ci-cd", "codacy", "Codacy API token."),
		mapPlanned("ci-cd", "coveralls", "Coveralls repository token."),
		mapImplemented("ci-cd", "harness", "harness-pat", "Harness personal access token coverage with provider context."),
		mapImplemented("analytics", "posthog", "posthog-personal-api-key", "PostHog personal API key coverage."),
		mapImplemented("analytics/customer-data", "segmentapikey", "segment-api-key", "Segment API key coverage with provider context."),
		mapImplemented("security/automation", "tineswebhook", "tines-webhook", "Tines webhook URL coverage."),
		mapImplemented("communication/webhook", "zapierwebhook", "zapier-webhook", "Zapier webhook URL coverage."),
		mapImplemented("developer-platform", "deno", "deno-deploy-token", "Deno Deploy token coverage."),
		mapImplemented("database/platform", "supabasetoken", "supabase-management-token", "Supabase management token coverage."),
		mapImplemented("workflow/orchestration", "prefect", "prefect-api-key", "Prefect API key coverage."),
		mapImplemented("design", "figmapersonalaccesstoken", "figma-pat", "Figma personal access token coverage."),
		mapImplemented("cloud/compute", "saladcloudapikey", "saladcloud-api-key", "SaladCloud API key coverage."),
		mapImplemented("database/platform", "planetscale", "planetscale-token", "PlanetScale token coverage."),
		mapImplemented("database/platform", "planetscaledb", "planetscale-db-password", "PlanetScale database password coverage."),
		mapImplemented("data-platform", "databrickstoken", "databricks-token", "Databricks token coverage."),
		mapImplemented("container/infrastructure", "portainertoken", "portainer-token", "Portainer token coverage."),
		mapImplemented("email-marketing", "sendinbluev2", "sendinblue-api-key", "Sendinblue/Brevo API key coverage."),
		mapImplemented("crm", "teamworkcrm", "teamwork-token", "Teamwork CRM token coverage."),
		mapImplemented("customer-support", "teamworkdesk", "teamwork-token", "Teamwork Desk token coverage."),
		mapImplemented("sales-engagement", "salesblink", "salesblink-api-key", "Salesblink API key coverage with provider context."),
		mapImplemented("customer-messaging", "smooch", "smooch-app-key", "Smooch app key coverage with provider context."),
		mapImplemented("email-marketing", "mailmodo", "mailmodo-api-key", "Mailmodo API key coverage with provider context."),
		mapImplemented("incident-management", "statuspage", "statuspage-api-key", "Statuspage API key coverage with provider context."),
	}
}

func mapImplemented(category, trufflehogID, secretSnifferID, notes string) Mapping {
	return mapping(category, trufflehogID, &secretSnifferID, Implemented, notes)
}

func mapPartial(category, trufflehogID, secretSnifferID, notes string) Mapping {
	return mapping(category, trufflehogID, &secretSnifferID, Partial, notes)
}

func mapPlanned(category, trufflehogID, notes string) Mapping {
	return mapping(category, trufflehogID, nil, Planned, notes)
}

func mapping(category, trufflehogID string, secretSnifferID *string, status Status, notes string) Mapping {
	return Mapping{TruffleHogID: trufflehogID, SecretSnifferID: secretSnifferID, Status: status, Category: category, Notes: notes}
}
