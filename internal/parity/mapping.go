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
		mapImplemented("cloud/infrastructure", "aws/session_keys", "aws-session-token", "AWS session token coverage with exact variable context."),
		mapImplemented("cloud/infrastructure", "aws/appsync", "aws-appsync-api-key", "AWS AppSync API key coverage."),
		mapImplemented("cloud/infrastructure", "azure_batch", "azure-batch-key", "Azure Batch key coverage with endpoint context."),
		mapImplemented("cloud/infrastructure", "azure_cosmosdb", "azure-cosmosdb-connection-string", "Azure Cosmos DB connection string coverage."),
		mapImplemented("cloud/infrastructure", "azure_openai", "azure-openai-key", "Azure OpenAI key coverage with endpoint context."),
		mapImplemented("cloud/infrastructure", "azure_storage", "azure-storage-connection-string", "Azure Storage connection string coverage."),
		mapImplemented("cloud/infrastructure", "azureappconfigconnectionstring", "azure-app-config-connection-string", "Azure App Configuration connection string coverage."),
		mapImplemented("cloud/infrastructure", "azurefunctionkey", "azure-function-key-url", "Azure Function key URL coverage."),
		mapImplemented("cloud/infrastructure", "azuresastoken", "azure-sas-url", "Azure SAS URL coverage."),
		mapImplemented("container/infrastructure", "azurecontainerregistry", "azure-container-registry-password", "Azure Container Registry password coverage."),
		mapImplemented("cloud/infrastructure", "gcp", "gcp-service-account-json", "GCP service account JSON key coverage."),
		mapImplemented("cloud/infrastructure", "gcpapplicationdefaultcredentials", "gcp-application-default-credentials", "GCP application default credential coverage."),
		mapImplemented("cloud/infrastructure", "cloudflarecakey", "cloudflare-ca-key", "Cloudflare CA key coverage."),
		mapImplemented("cloud/infrastructure", "cloudflareglobalapikey", "cloudflare-global-api-key", "Cloudflare global API key coverage with provider context."),
		mapImplemented("container/infrastructure", "docker", "docker-auth-config", "Docker auth config coverage."),
		mapImplemented("cloud/infrastructure", "azuresearchadminkey", "azure-search-key", "Azure Search admin key coverage with endpoint context."),
		mapImplemented("cloud/infrastructure", "azuresearchquerykey", "azure-search-key", "Azure Search query key coverage with endpoint context."),
		mapImplemented("cloud/infrastructure", "azureapimanagementsubscriptionkey", "azure-apim-subscription-key", "Azure API Management subscription key coverage."),
		mapPartial("cloud/infrastructure", "hashicorpvaultauth", "hashicorp-vault-approle", "Vault AppRole secret ID covered; role ID and Vault URL correlation planned."),
		mapImplemented("cloud/infrastructure", "terraformcloudpersonaltoken", "terraform-cloud-token", "Terraform Cloud token coverage."),
		mapImplemented("cloud/infrastructure", "aiven", "aiven-token", "Aiven token coverage with provider context."),
		mapImplemented("cloud/infrastructure", "alibaba", "alibaba-access-key", "Alibaba Cloud access key ID coverage."),
		mapImplemented("cloud/infrastructure", "scalewaykey", "scaleway-secret-key", "Scaleway secret key coverage with exact env/provider context."),
		mapImplemented("cloud/infrastructure", "vercel", "vercel-token", "Vercel token coverage with provider context."),
		mapImplemented("cloud/infrastructure", "netlify", "netlify-token", "Netlify token coverage."),
		mapImplemented("cloud/infrastructure", "flyio", "flyio-token", "Fly.io token coverage."),
		mapImplemented("cloud/infrastructure", "railwayapp", "railway-token", "Railway token coverage with provider context."),
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
		mapImplemented("vcs", "github_oauth2", "github-oauth-client-secret", "GitHub OAuth client secret coverage with OAuth/client-secret context."),
		mapImplemented("vcs", "githubapp", "github-app-private-key", "GitHub App private key coverage with GitHub App context."),
		mapImplemented("vcs", "gitlaboauth2", "gitlab-oauth-client-secret", "GitLab OAuth client secret coverage with OAuth/client-secret context."),
		mapImplemented("vcs", "azuredevopspersonalaccesstoken", "azure-devops-pat", "Azure DevOps new-format PAT coverage."),
		mapImplemented("package-registry", "nugetapikey", "nuget-api-key", "NuGet API key coverage."),
		mapImplemented("package-registry", "rubygems", "rubygems-api-key", "RubyGems API key coverage."),
		mapImplemented("package-registry", "artifactory", "artifactory-access-token", "JFrog Artifactory access token coverage."),
		mapImplemented("package-registry", "artifactoryreferencetoken", "artifactory-reference-token", "JFrog Artifactory reference token coverage."),
		mapImplemented("developer-tooling", "circleci", "circleci-pat", "CircleCI personal access token coverage."),
		mapImplemented("developer-tooling", "buildkite", "buildkite-token", "Buildkite token coverage."),
		mapImplemented("developer-tooling", "travisci", "travisci-token", "Travis CI token coverage with provider context."),
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
		mapImplemented("communication", "webex", "webex-access-token", "Webex access token coverage with provider and token label context."),
		mapImplemented("communication", "webexbot", "webex-bot-token", "Webex bot token coverage."),
		mapPartial("observability", "datadogtoken", "datadog-app-key", "Datadog application key covered; API/app key tuple correlation planned."),
		mapImplemented("observability", "grafana", "grafana-token", "Grafana token coverage."),
		mapImplemented("observability", "grafanaserviceaccount", "grafana-service-account-token", "Grafana service account token coverage."),
		mapImplemented("observability", "sentryorgtoken", "sentry-org-token", "Sentry organization token coverage."),
		mapImplemented("observability", "sentrytoken", "sentry-user-token", "Sentry user token coverage."),
		mapImplemented("observability", "honeycomb", "honeycomb-api-key", "Honeycomb API key coverage with provider context."),
		mapImplemented("observability", "splunkobservabilitytoken", "splunk-observability-token", "Splunk Observability token coverage with provider context."),
		mapImplemented("incident-management", "opsgenie", "opsgenie-api-key", "Opsgenie API key coverage with provider context."),
		mapImplemented("observability", "betterstack", "betterstack-api-key", "BetterStack API key coverage with provider context."),

		mapImplemented("database", "mongodb", "mongodb-uri", "MongoDB URI coverage."),
		mapImplemented("database", "postgres", "postgres-uri", "PostgreSQL URI coverage."),
		mapPartial("database", "jdbc", "mysql-uri", "MySQL URI covered outside JDBC envelope."),
		mapImplemented("database", "redis", "redis-uri", "Authenticated Redis URI and Azure Redis connection-string coverage."),
		mapImplemented("database", "snowflake", "snowflake-url", "Snowflake credentialed URL coverage."),
		mapImplemented("database", "couchbase", "couchbase-capella-uri", "Couchbase Capella credentialed URI coverage."),
		mapImplemented("ai-ml", "openai", "openai-key", "OpenAI API key coverage."),
		mapImplemented("ai-ml", "anthropic", "anthropic-key", "Anthropic API key coverage."),
		mapPartial("ai-ml", "googlegemini", "google-api-key", "Generic Google API key covers Gemini key shape."),
		mapImplemented("ai-ml", "groq", "groq-api-key", "Groq API key coverage."),
		mapImplemented("ai-ml", "huggingface", "huggingface-token", "Hugging Face token coverage."),
		mapImplemented("ai-ml", "replicate", "replicate-token", "Replicate token coverage."),
		mapImplemented("payment", "stripe", "stripe-key", "Stripe key coverage."),
		mapImplemented("payment", "stripepaymentintent", "stripe-payment-intent-client-secret", "Stripe PaymentIntent client secret coverage."),
		mapImplemented("payment", "square", "square-token", "Square token coverage."),
		mapImplemented("payment", "paypaloauth", "paypal-token", "PayPal token coverage."),
		mapImplemented("commerce", "shopify", "shopify-token", "Shopify token coverage."),
		mapImplemented("payment", "braintreepayments", "braintree-access-token", "Braintree access token coverage."),
		mapImplemented("payment", "flutterwave", "flutterwave-secret-key", "Flutterwave secret key coverage."),
		mapImplemented("payment", "pagarme", "pagarme-live-key", "Pagar.me live key coverage."),
		mapImplemented("payment", "rechargepayments", "rechargepayments-token", "Recharge Payments token coverage."),
		mapImplemented("payment", "lemonsqueezy", "lemonsqueezy-api-token", "Lemon Squeezy API token coverage with provider context."),
		mapImplemented("payment", "checkout", "checkout-secret-key", "Checkout.com secret key coverage with provider context."),
		mapPartial("payment", "plaidkey", "plaid-access-token", "Plaid access token covered; client ID/secret correlation planned."),
		mapImplemented("payment", "paystack", "paystack-secret-key", "Paystack secret key coverage."),
		mapPartial("payment", "razorpay", "razorpay-key", "Razorpay key ID covered; paired secret correlation planned."),
		mapPartial("payment", "coinbase", "coinbase-cdp-api-key", "Coinbase CDP API key resource name covered; full key/secret tuple correlation planned."),
		mapImplemented("generic", "jwt", "jwt", "JWT coverage."),
		mapImplemented("generic", "privatekey", "private-key", "PEM private key coverage."),
		mapImplemented("generic", "privatekey/ssh", "ssh-private-key", "OpenSSH private key coverage."),
		mapImplemented("generic", "uri", "basic-auth-url", "Credentialed URI coverage."),
		mapImplemented("generic", "generic", "generic-assigned-secret", "Assigned generic secret coverage."),

		mapImplemented("marketing/crm", "hubspot_apikey", "hubspot-private-app-token", "HubSpot private app token coverage."),
		mapImplemented("marketing/crm", "mailchimp", "mailchimp-key", "Mailchimp API key coverage."),
		mapImplemented("customer-success", "intercom", "intercom-access-token", "Intercom access token coverage with provider context."),
		mapImplemented("customer-support", "zendeskapi", "zendesk-api-token", "Zendesk API token coverage with domain context."),
		mapPartial("crm", "salesforce", "salesforce-access-token", "Salesforce access token shape covered; instance correlation and verification planned."),
		mapPartial("crm", "salesforceoauth2", "salesforce-consumer-key", "Salesforce OAuth consumer key covered; consumer secret correlation planned."),
		mapImplemented("crm", "salesforcerefreshtoken", "salesforce-refresh-token", "Salesforce refresh token coverage."),
		mapImplemented("marketing-automation", "customerio", "customerio-api-key", "Customer.io API key coverage with provider context."),
		mapImplemented("email-marketing", "klaviyo", "klaviyo-key", "Klaviyo API key coverage."),
		mapImplemented("sales-scheduling", "calendlyapikey", "calendly-api-key", "Calendly API key coverage with provider context."),
		mapImplemented("forms/customer-data", "typeform", "typeform-token", "Typeform token coverage."),
		mapImplemented("collaboration/customer-data", "airtablepersonalaccesstoken", "airtable-pat", "Airtable personal access token coverage."),
		mapImplemented("collaboration/customer-data", "coda", "coda-api-token", "Coda API token coverage with provider context."),
		mapImplemented("collaboration/customer-data", "notion", "notion-token", "Notion token coverage."),
		mapImplemented("project-management", "asanapersonalaccesstoken", "asana-pat", "Asana personal access token coverage."),
		mapImplemented("project-management/crm", "monday", "monday-api-token", "Monday.com API token coverage with provider context."),
		mapImplemented("project-management", "clickuppersonaltoken", "clickup-token", "ClickUp personal token coverage."),
		mapImplemented("project-management", "trelloapikey", "trello-api-key", "Trello API key coverage with provider context."),
		mapImplemented("project-management", "wrike", "wrike-access-token", "Wrike access token coverage with provider context."),
		mapImplemented("customer-support", "freshdesk", "freshdesk-api-key", "Freshdesk API key coverage with domain context."),
		mapImplemented("customer-support", "helpscout", "helpscout-api-key", "Help Scout API key coverage with provider context."),
		mapImplemented("customer-support/email-saas", "front", "front-api-token", "Front API token coverage."),
		mapImplemented("customer-support", "helpcrunch", "helpcrunch-api-key", "HelpCrunch API key coverage with provider context."),
		mapImplemented("crm", "closecrm", "closecrm-api-key", "Close CRM API key coverage."),
		mapImplemented("crm", "pipedrive", "pipedrive-api-token", "Pipedrive API token coverage with provider context."),
		mapImplemented("email-marketing", "mailerlite", "mailerlite-api-key", "MailerLite API key coverage with provider context."),
		mapImplemented("email-saas", "mailjetbasicauth", "mailjet-basic-auth", "Mailjet basic auth credential coverage with provider context."),
		mapImplemented("email-saas", "mandrill", "mandrill-api-key", "Mandrill API key coverage with provider context."),
		mapImplemented("email-saas", "postmark", "postmark-token", "Postmark server token coverage with provider context."),
		mapImplemented("email-saas", "sparkpost", "sparkpost-api-key", "SparkPost API key coverage with provider context."),
		mapImplemented("email-saas", "elasticemail", "elastic-email-api-key", "Elastic Email API key coverage with provider context."),
		mapImplemented("customer-messaging", "onesignal", "onesignal-api-key", "OneSignal API key coverage with provider context."),
		mapImplemented("crm", "zohocrm", "zoho-crm-token", "Zoho CRM token coverage."),
		mapImplemented("crm", "copper", "copper-api-key", "Copper CRM API key coverage with provider context."),
		mapImplemented("crm", "capsulecrm", "capsulecrm-api-key", "Capsule CRM API key coverage with provider context."),
		mapImplemented("sales-intelligence", "apollo", "apollo-api-key", "Apollo API key coverage with provider context."),
		mapImplemented("sales-engagement/email-saas", "lemlist", "lemlist-api-key", "Lemlist API key coverage with provider context."),
		mapImplemented("email-marketing", "getresponse", "getresponse-api-key", "GetResponse API key coverage with provider context."),

		mapImplemented("security/scanning", "shodankey", "shodan-api-key", "Shodan API key coverage with provider context."),
		mapImplemented("threat-intel", "virustotal", "virustotal-api-key", "VirusTotal API key coverage with provider context."),
		mapImplemented("identity/auth", "okta", "okta-api-token", "Okta API token coverage with Okta domain context."),
		mapImplemented("identity/auth", "auth0managementapitoken", "auth0-domain-jwt", "Auth0 management token coverage with tenant domain context."),
		mapImplemented("identity/auth", "auth0oauth", "auth0-client-secret", "Auth0 OAuth client secret coverage with provider context."),
		mapImplemented("identity/auth", "onelogin", "onelogin-client-secret", "OneLogin client secret coverage with provider context."),
		mapImplemented("identity/auth", "jumpcloud", "jumpcloud-api-key", "JumpCloud API key coverage with provider context."),
		mapImplemented("security/dlp", "nightfall", "nightfall-api-key", "Nightfall DLP API key coverage."),
		mapImplemented("security/scanning", "detectify", "detectify-api-key", "Detectify API key coverage with provider and key label context."),
		mapImplemented("threat-intel", "securitytrails", "securitytrails-api-key", "SecurityTrails API key coverage with provider context."),
		mapImplemented("threat-intel", "urlscan", "urlscan-api-key", "urlscan.io API key coverage with provider context."),
		mapImplemented("threat-intel", "abuseipdb", "abuseipdb-api-key", "AbuseIPDB API key coverage with provider context."),
		mapImplemented("threat-intel", "alienvault", "alienvault-otx-api-key", "AlienVault OTX API key coverage with provider context."),
		mapImplemented("threat-intel", "censys", "censys-api-key", "Censys API key coverage with provider context."),
		mapImplemented("vpn/threat-intel", "vpnapi", "vpnapi-key", "VPNAPI.io API key coverage with provider context."),
		mapImplemented("threat-intel/fraud", "ipquality", "ipqualityscore-api-key", "IPQualityScore API key coverage with provider context."),
		mapImplemented("threat-intel/geolocation", "ipinfo", "ipinfo-token", "IPinfo token coverage with provider and token label context."),
		mapImplemented("threat-intel/geolocation", "ipstack", "ipstack-api-key", "IPstack API key coverage with provider context."),
		mapImplemented("threat-intel/geolocation", "ipgeolocation", "ipgeolocation-api-key", "IPGeolocation API key coverage with provider context."),
		mapImplemented("security/scanning", "spectralops", "spectralops-token", "SpectralOps API key coverage."),
		mapImplemented("cloud-security", "wiz", "wiz-client-secret", "Wiz client secret coverage with provider context."),
		mapImplemented("security/asset-inventory", "jupiterone", "jupiterone-api-token", "JupiterOne API token coverage with provider and token label context."),
		mapPartial("security/scanning", "endorlabs", "endorlabs-token", "Endor Labs token coverage; paired key/secret correlation planned."),
		mapPartial("security/scanning", "trufflehogenterprise", "trufflehog-enterprise-key", "TruffleHog Enterprise key/secret shapes covered; tuple correlation planned."),
		mapImplemented("vpn/auth", "openvpn", "openvpn-static-key", "OpenVPN static key block coverage."),
		mapImplemented("vpn/auth", "zerotier", "zerotier-api-token", "ZeroTier API token coverage with provider context."),
		mapImplemented("identity/auth", "azure_entra", "azure-entra-client-secret", "Microsoft Entra client secret coverage with Azure/Entra context."),
		mapImplemented("identity/auth", "ldap", "ldap-url", "LDAP credentialed URL coverage."),
		mapImplemented("identity/auth", "loginradius", "loginradius-api-secret", "LoginRadius API secret coverage with provider context."),
		mapImplemented("identity/auth", "stytch", "stytch-secret", "Stytch secret coverage with environment prefix."),

		mapImplemented("crypto", "coinapi", "coinapi-key", "CoinAPI market data API key coverage with provider context."),
		mapImplemented("crypto", "coinlayer", "coinlayer-api-key", "CoinLayer API key coverage with provider and key label context."),
		mapImplemented("crypto", "coinlib", "coinlib-api-key", "Coinlib API key coverage with provider and key label context."),
		mapImplemented("crypto", "cryptocompare", "cryptocompare-api-key", "CryptoCompare API key coverage with provider and key label context."),
		mapImplemented("crypto", "bitcoinaverage", "bitcoinaverage-api-key", "BitcoinAverage market data key coverage with provider and key label context."),
		mapImplemented("crypto", "worldcoinindex", "worldcoinindex-api-key", "WorldCoinIndex API key coverage with provider and key label context."),
		mapImplemented("crypto", "etherscan", "etherscan-api-key", "Etherscan API key coverage with provider context."),
		mapImplemented("crypto", "bscscan", "bscscan-api-key", "BscScan API key coverage with provider context."),
		mapImplemented("crypto", "blocknative", "blocknative-api-key", "Blocknative API key coverage with provider and key label context."),
		mapImplemented("finance", "fixerio", "fixerio-api-key", "Fixer.io exchange-rate API key coverage with provider and key label context."),
		mapImplemented("finance", "currencylayer", "currencylayer-api-key", "Currencylayer exchange-rate API key coverage with provider and key label context."),
		mapImplemented("finance", "exchangerateapi", "exchangerate-api-key", "ExchangeRate-API key coverage with provider and key label context."),
		mapImplemented("finance", "exchangeratesapi", "exchangeratesapi-api-key", "ExchangeRatesAPI key coverage with provider and key label context."),
		mapImplemented("finance", "currencyfreaks", "currencyfreaks-api-key", "CurrencyFreaks API key coverage with provider and key label context."),
		mapImplemented("finance", "currencyscoop", "currencyscoop-api-key", "CurrencyScoop API key coverage with provider and key label context."),
		mapImplemented("finance", "fastforex", "fastforex-api-key", "FastForex API key coverage with provider and key label context."),
		mapImplemented("finance", "marketstack", "marketstack-api-key", "Marketstack market data API key coverage with provider and key label context."),
		mapImplemented("finance", "financialmodelingprep", "financialmodelingprep-api-key", "Financial Modeling Prep API key coverage with provider and key label context."),
		mapImplemented("finance", "finnhub", "finnhub-api-key", "Finnhub market data API key coverage with provider and key label context."),
		mapImplemented("finance", "polygon", "polygon-api-key", "Polygon.io financial data API key coverage with provider context."),
		mapImplemented("finance", "tradier", "tradier-token", "Tradier brokerage API token coverage with provider and token label context."),
		mapImplemented("finance", "twelvedata", "twelvedata-api-key", "Twelve Data API key coverage with provider and key label context."),
		mapImplemented("finance", "vatlayer", "vatlayer-api-key", "VATLayer API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "weatherstack", "weatherstack-api-key", "Weatherstack API key coverage with provider context."),
		mapImplemented("weather/geolocation", "openweather", "openweather-api-key", "OpenWeather API key coverage with provider context."),
		mapImplemented("weather/geolocation", "accuweather", "accuweather-api-key", "AccuWeather API key coverage with provider context."),
		mapImplemented("weather/geolocation", "weatherbit", "weatherbit-api-key", "Weatherbit API key coverage with provider context."),
		mapImplemented("weather/geolocation", "worldweather", "worldweather-api-key", "World Weather Online API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "tomorrowio", "tomorrowio-api-key", "Tomorrow.io API key coverage with provider context."),
		mapImplemented("weather/geolocation", "mapbox", "mapbox-secret-token", "Mapbox secret token coverage; public pk tokens intentionally ignored."),
		mapImplemented("weather/geolocation", "mapquest", "mapquest-api-key", "MapQuest API key coverage with provider context."),
		mapImplemented("weather/geolocation", "positionstack", "positionstack-api-key", "Positionstack geocoding API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "locationiq", "locationiq-api-key", "LocationIQ API key coverage with provider context."),
		mapImplemented("weather/geolocation", "hereapi", "here-api-key", "HERE API key coverage with provider context."),
		mapPlanned("weather/geolocation", "geocode", "Generic geocode API key."),
		mapImplemented("weather/geolocation", "geocodio", "geocodio-api-key", "Geocodio API key coverage with provider and key label context."),
		mapImplemented("data-provider", "newsapi", "newsapi-key", "NewsAPI key coverage with provider context."),
		mapImplemented("data-provider", "guardianapi", "guardian-api-key", "Guardian Open Platform API key coverage with provider context."),
		mapPartial("public-api", "youtubeapikey", "google-api-key", "YouTube API key shape covered by generic Google API key detector."),
		mapPartial("public-api", "facebookoauth", "facebook-oauth-secret", "Facebook app secret covered; app ID correlation planned."),
		mapPartial("public-api", "twitter", "twitter-bearer-token", "Twitter/X bearer token covered; full API key/secret tuple correlation planned."),
		mapPartial("public-api", "twitterconsumerkey", "twitter-consumer-secret", "Twitter/X consumer secret covered; consumer key correlation planned."),
		mapPartial("public-api", "twitch", "twitch-client-secret", "Twitch client secret covered; client ID/secret tuple correlation planned."),
		mapImplemented("public-api", "twitchaccesstoken", "twitch-access-token", "Twitch access token coverage with provider and token label context."),

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
		mapImplemented("observability", "logzio", "logzio-token", "Logz.io token coverage with provider context."),
		mapPartial("observability", "sumologickey", "sumologic-access-key", "Sumo Logic access key covered; access ID correlation planned."),
		mapImplemented("observability", "uptimerobot", "uptimerobot-api-key", "UptimeRobot API key coverage with provider context."),
		mapImplemented("ci-cd", "sonarcloud", "sonarcloud-token", "SonarCloud token coverage with provider context."),
		mapImplemented("ci-cd", "codeclimate", "codeclimate-token", "Code Climate token coverage with provider context."),
		mapImplemented("ci-cd", "codacy", "codacy-api-token", "Codacy API token coverage with provider context."),
		mapImplemented("ci-cd", "coveralls", "coveralls-repo-token", "Coveralls repository token coverage with provider context."),
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
		mapImplemented("customer-messaging", "courier", "courier-api-key", "Courier API key coverage with provider context."),
		mapImplemented("customer-messaging", "linemessaging", "line-messaging-token", "LINE Messaging token coverage with provider context."),
		mapImplemented("communication", "mattermostpersonaltoken", "mattermost-personal-token", "Mattermost personal token coverage with cloud domain context."),
		mapImplemented("media", "cloudinary", "cloudinary-url", "Cloudinary credential URL coverage."),
		mapImplemented("incident-management", "statuspage", "statuspage-api-key", "Statuspage API key coverage with provider context."),
		mapImplemented("database", "sqlserver", "sqlserver-connection-string", "SQL Server connection string coverage."),
		mapImplemented("messaging", "rabbitmq", "rabbitmq-uri", "RabbitMQ credentialed URI coverage."),
		mapImplemented("storage", "dropbox", "dropbox-token", "Dropbox token coverage."),
		mapImplemented("network/cdn", "fastlypersonaltoken", "fastly-personal-token", "Fastly personal token coverage with provider and token label context."),
		mapImplemented("communication", "telnyx", "telnyx-api-key", "Telnyx API key coverage with provider and key label context."),
		mapImplemented("developer-platform", "vagrantcloudpersonaltoken", "vagrant-cloud-token", "Vagrant Cloud personal token coverage with provider and token label context."),
		mapImplemented("design", "zeplin", "zeplin-token", "Zeplin token coverage with provider and token label context."),
		mapImplemented("cloud/infrastructure", "vultrapikey", "vultr-api-key", "Vultr API key coverage with provider and key label context."),
		mapImplemented("link-management", "bitlyaccesstoken", "bitly-access-token", "Bitly access token coverage with provider and token label context."),
		mapImplemented("search", "algoliaadminkey", "algolia-admin-key", "Algolia admin API key coverage with provider and admin-key label context."),
		mapImplemented("monitoring", "airbrakeprojectkey", "airbrake-project-key", "Airbrake project key coverage with provider and key label context."),
		mapImplemented("monitoring", "airbrakeuserkey", "airbrake-user-key", "Airbrake user key coverage with provider and key label context."),
		mapImplemented("monitoring", "bugsnag", "bugsnag-api-key", "Bugsnag API key coverage with provider and key label context."),
		mapImplemented("developer-platform", "infura", "infura-project-id", "Infura project ID coverage with provider and project label context."),
		mapImplemented("communication", "messagebird", "messagebird-api-key", "MessageBird live/test API key coverage with provider context."),
		mapImplemented("storage/ipfs", "pinata", "pinata-jwt", "Pinata JWT coverage with provider and token label context."),
		mapImplemented("communication", "pushbulletapikey", "pushbullet-token", "Pushbullet access token coverage with provider and token label context."),
		mapImplemented("communication", "sendbird", "sendbird-api-token", "Sendbird API token coverage with provider and token label context."),
		mapImplemented("weather/geolocation", "stormglass", "stormglass-api-key", "StormGlass API key coverage with provider and key label context."),
		mapImplemented("productivity", "todoist", "todoist-api-token", "Todoist API token coverage with provider and token label context."),
		mapImplemented("storage/media", "uploadcare", "uploadcare-secret-key", "Uploadcare secret key coverage with provider and secret-key label context."),
		mapImplemented("testing", "browserstack", "browserstack-access-key", "BrowserStack access key coverage with provider and access-key label context."),
		mapImplemented("package-registry", "cloudsmith", "cloudsmith-api-key", "Cloudsmith API key coverage with provider and key label context."),
		mapImplemented("events", "eventbrite", "eventbrite-private-token", "Eventbrite private token coverage with provider and token label context."),
		mapImplemented("time-tracking", "harvest", "harvest-access-token", "Harvest access token coverage with provider and token label context."),
		mapImplemented("localization", "lokalisetoken", "lokalise-token", "Lokalise token coverage with provider and token label context."),
		mapImplemented("geolocation", "maxmindlicense", "maxmind-license-key", "MaxMind license key coverage with provider and license-key label context."),
		mapImplemented("email/api", "nylas", "nylas-api-key", "Nylas API key/client secret coverage with provider and key label context."),
		mapImplemented("developer-platform", "pipedream", "pipedream-api-key", "Pipedream API key coverage with provider and key label context."),
		mapImplemented("ci-cd", "percy", "percy-token", "Percy token coverage with provider/env-var context."),
		mapImplemented("localization", "crowdin", "crowdin-token", "Crowdin token coverage with provider and token label context."),
		mapImplemented("email-saas", "postageapp", "postageapp-api-key", "PostageApp API key coverage with provider and key label context."),
		mapImplemented("communication", "sendbirdorganizationapi", "sendbird-organization-api-token", "Sendbird organization API token coverage with provider and organization-token label context."),
		mapImplemented("monitoring", "checklyhq", "checkly-api-key", "Checkly API key coverage with provider and key label context."),
		mapPartial("data-streaming", "confluent", "confluent-api-secret", "Confluent API secret covered; key/secret tuple correlation planned."),
		mapImplemented("esignature", "docusign", "docusign-client-secret", "DocuSign client secret coverage with provider context."),
		mapImplemented("payment", "gocardless", "gocardless-access-token", "GoCardless live/sandbox access token coverage with provider context."),
		mapImplemented("commerce", "gumroad", "gumroad-access-token", "Gumroad access token coverage with provider and token label context."),
		mapImplemented("esignature", "hellosign", "hellosign-api-key", "HelloSign API key coverage with provider and key label context."),
		mapImplemented("email-validation", "mailboxlayer", "mailboxlayer-api-key", "Mailboxlayer API key coverage with provider and key label context."),
		mapImplemented("data-provider", "mediastack", "mediastack-api-key", "Mediastack API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "opencagedata", "opencage-api-key", "OpenCage API key coverage with provider and key label context."),
		mapImplemented("package-registry", "packagecloud", "packagecloud-token", "Packagecloud token coverage with provider and token label context."),
		mapImplemented("localization", "phraseaccesstoken", "phrase-access-token", "Phrase access token coverage with provider and token label context."),
		mapImplemented("ci-cd", "semaphore", "semaphore-api-token", "Semaphore API token coverage with provider and token label context."),
		mapImplemented("ci-cd", "scrutinizerci", "scrutinizer-token", "Scrutinizer CI token coverage with provider and token label context."),
		mapPartial("testing", "saucelabs", "saucelabs-access-key", "Sauce Labs access key covered; username/access-key tuple correlation planned."),
		mapImplemented("crm", "lessannoyingcrm", "lessannoyingcrm-api-key", "Less Annoying CRM API key coverage with provider and key label context."),
		mapImplemented("ai-ml", "meaningcloud", "meaningcloud-api-key", "MeaningCloud API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "openuv", "openuv-api-key", "OpenUV API key coverage with provider and key label context."),
		mapImplemented("sports-data", "pandascore", "pandascore-api-key", "PandaScore API key coverage with provider and key label context."),
		mapImplemented("forms", "paperform", "paperform-api-key", "Paperform API key coverage with provider and key label context."),
		mapImplemented("data-extraction", "parsehub", "parsehub-api-key", "ParseHub API key coverage with provider and key label context."),
		mapImplemented("document", "pdfshift", "pdfshift-api-key", "PDFShift API key coverage with provider and key label context."),
		mapImplemented("data-provider", "peopledatalabs", "peopledatalabs-api-key", "People Data Labs API key coverage with provider and key label context."),
		mapPartial("communication", "plivo", "plivo-auth-token", "Plivo auth token covered; auth ID/token tuple correlation planned."),
		mapImplemented("api-marketplace", "rapidapi", "rapidapi-key", "RapidAPI key coverage with provider and header/key label context."),
		mapImplemented("scraping", "scraperapi", "scraperapi-key", "ScraperAPI key coverage with provider and key label context."),
		mapImplemented("scraping", "scrapestack", "scrapestack-api-key", "Scrapestack API key coverage with provider and key label context."),
		mapImplemented("scraping", "scrapingbee", "scrapingbee-api-key", "ScrapingBee API key coverage with provider and key label context."),
		mapImplemented("search", "serpstack", "serpstack-api-key", "Serpstack API key coverage with provider and key label context."),
		mapImplemented("media", "shotstack", "shotstack-api-key", "Shotstack API key coverage with provider and key label context."),
		mapPartial("communication", "signalwire", "signalwire-api-token", "SignalWire API token covered; project/token tuple correlation planned."),
		mapPartial("testing", "testingbot", "testingbot-secret", "TestingBot secret covered; key/secret tuple correlation planned."),
		mapImplemented("data-provider", "abstract", "abstract-api-key", "Abstract API key coverage with provider and key label context."),
		mapImplemented("web3", "alchemy", "alchemy-api-key", "Alchemy API key coverage with provider and key label context."),
		mapImplemented("automation/scraping", "apify", "apify-token", "Apify token coverage with provider and token prefix context."),
		mapImplemented("api-provider", "apilayer", "apilayer-key", "APILayer key coverage with provider and key label context."),
		mapImplemented("media", "bannerbear", "bannerbear-api-key", "Bannerbear API key coverage with provider and key label context."),
		mapImplemented("analytics", "baremetrics", "baremetrics-api-key", "Baremetrics API key coverage with provider and key label context."),
		mapImplemented("customer-messaging", "beamer", "beamer-api-key", "Beamer API key coverage with provider and key label context."),
		mapImplemented("testing", "bitbar", "bitbar-api-key", "Bitbar API key coverage with provider and key label context."),
		mapImplemented("testing", "blazemeter", "blazemeter-api-key", "BlazeMeter API key coverage with provider and key label context."),
		mapImplemented("cms", "buttercms", "buttercms-api-token", "ButterCMS API token coverage with provider and token label context."),
		mapImplemented("product-feedback", "cannyio", "canny-api-key", "Canny API key coverage with provider and key label context."),
		mapImplemented("analytics", "chartmogul", "chartmogul-api-key", "ChartMogul API key coverage with provider and key label context."),
		mapImplemented("data-provider", "clearbit", "clearbit-api-key", "Clearbit API key coverage with provider and key label context."),
		mapImplemented("time-tracking", "clockify", "clockify-api-key", "Clockify API key coverage with provider and key label context."),
		mapImplemented("document", "cloudconvert", "cloudconvert-api-key", "CloudConvert API key coverage with provider and key label context."),
		mapImplemented("document", "cloudmersive", "cloudmersive-api-key", "Cloudmersive API key coverage with provider and key label context."),
		mapImplemented("document", "convertapi", "convertapi-secret", "ConvertAPI secret coverage with provider and secret/key label context."),
		mapPartial("email-marketing", "convertkit", "convertkit-api-secret", "ConvertKit API secret covered; API key/secret tuple correlation planned."),
		mapImplemented("communication/video", "dailyco", "dailyco-api-key", "Daily.co API key coverage with provider and key label context."),
		mapImplemented("ai-ml", "deepai", "deepai-api-key", "DeepAI API key coverage with provider and key label context."),
		mapImplemented("customer-feedback", "delighted", "delighted-api-key", "Delighted API key coverage with provider and key label context."),
		mapImplemented("workforce", "deputy", "deputy-api-token", "Deputy API token coverage with provider and token label context."),
		mapImplemented("analytics", "fullstory", "fullstory-api-key", "FullStory API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "geoapify", "geoapify-api-key", "Geoapify API key coverage with provider and key label context."),
		mapImplemented("weather/geolocation", "graphhopper", "graphhopper-api-key", "GraphHopper API key coverage with provider and key label context."),
		mapImplemented("email-finder", "hunter", "hunter-api-key", "Hunter API key coverage with provider and key label context."),
		mapImplemented("media", "imagekit", "imagekit-private-key", "ImageKit private key coverage with provider and private-key prefix context."),
		mapImplemented("email-validation", "kickbox", "kickbox-api-key", "Kickbox API key coverage with provider and key label context."),
		mapImplemented("analytics", "klipfolio", "klipfolio-api-key", "Klipfolio API key coverage with provider and key label context."),
		mapImplemented("postal", "lob", "lob-api-key", "Lob live/test API key coverage with provider context."),
		mapImplemented("email-marketing", "moosend", "moosend-api-key", "Moosend API key coverage with provider and key label context."),
		mapPartial("data-provider", "neutrinoapi", "neutrinoapi-api-key", "NeutrinoAPI API key covered; user-id/key tuple correlation planned."),
		mapImplemented("phone-validation", "numverify", "numverify-api-key", "Numverify API key coverage with provider and access-key label context."),
		mapImplemented("email-marketing", "omnisend", "omnisend-api-key", "Omnisend API key coverage with provider and key label context."),
		mapImplemented("dictionary", "owlbot", "owlbot-api-key", "OwlBot API key coverage with provider and token/key label context."),
		mapImplemented("document", "pandadoc", "pandadoc-api-key", "PandaDoc API key coverage with provider and key label context."),
		mapImplemented("partner-management", "partnerstack", "partnerstack-api-key", "PartnerStack API key coverage with provider and token/key label context."),
		mapImplemented("developer-platform", "pastebin", "pastebin-api-key", "Pastebin API developer key coverage with provider and key label context."),
		mapImplemented("payment", "paymongo", "paymongo-secret-key", "PayMongo live/test secret key coverage with provider context."),
		mapImplemented("media", "photoroom", "photoroom-api-key", "PhotoRoom API key coverage with provider and key label context."),
		mapImplemented("scraping", "proxycrawl", "proxycrawl-api-token", "ProxyCrawl API token coverage with provider and token/key label context."),
		mapImplemented("testing", "qase", "qase-api-token", "Qase API token coverage with provider and token/key label context."),
		mapImplemented("link-management", "rebrandly", "rebrandly-api-key", "Rebrandly API key coverage with provider and key label context."),
		mapImplemented("commerce", "repairshopr", "repairshopr-api-key", "RepairShopr API key coverage with provider and key label context."),
		mapImplemented("sales-engagement", "replyio", "replyio-api-key", "Reply.io API key coverage with provider and key label context."),
		mapImplemented("document", "restpackhtmltopdfapi", "restpack-htmltopdf-api-key", "Restpack HTML-to-PDF API key coverage with provider, product, and key label context."),
		mapImplemented("media", "restpackscreenshotapi", "restpack-screenshot-api-key", "Restpack Screenshot API key coverage with provider, product, and key label context."),
		mapImplemented("sales-intelligence", "rocketreach", "rocketreach-api-key", "RocketReach API key coverage with provider and key label context."),
		mapImplemented("routing/geolocation", "route4me", "route4me-api-key", "Route4Me API key coverage with provider and key label context."),
		mapImplemented("crm", "salesflare", "salesflare-api-key", "Salesflare API key coverage with provider and key label context."),
		mapPartial("job-search", "adzuna", "adzuna-api-key", "Adzuna API key covered; app ID/key tuple correlation planned."),
		mapImplemented("weather/air-quality", "airvisual", "airvisual-api-key", "AirVisual/IQAir API key coverage with provider and key label context."),
		mapPartial("travel", "amadeus", "amadeus-api-secret", "Amadeus API secret covered; client ID/secret tuple correlation planned."),
		mapImplemented("weather/environment", "ambee", "ambee-api-key", "Ambee API key coverage with provider and key label context."),
		mapImplemented("analytics", "amplitudeapikey", "amplitude-api-key", "Amplitude API key coverage with provider and key label context."),
		mapImplemented("screenshot", "apiflash", "apiflash-access-key", "APIFLASH access key coverage with provider and key label context."),
		mapImplemented("document", "apitemplate", "apitemplate-api-key", "APITemplate API key coverage with provider and key label context."),
		mapImplemented("product-analytics", "appcues", "appcues-api-key", "Appcues API key coverage with provider and key/token label context."),
		mapImplemented("app-analytics", "appfollow", "appfollow-api-key", "AppFollow API key coverage with provider and token/key label context."),
		mapImplemented("sales-engagement", "autoklose", "autoklose-api-key", "Autoklose API key coverage with provider and key/token label context."),
		mapImplemented("travel", "aviationstack", "aviationstack-api-key", "Aviationstack API key coverage with provider and access-key label context."),
		mapImplemented("social-media", "ayrshare", "ayrshare-api-key", "Ayrshare API key coverage with provider and key/token label context."),
		mapImplemented("business-intelligence", "besttime", "besttime-api-key", "BestTime API key coverage with provider and key label context."),
		mapImplemented("brand-data", "brandfetch", "brandfetch-api-key", "Brandfetch API key coverage with provider and key/token label context."),
		mapImplemented("screenshot", "browshot", "browshot-api-key", "Browshot API key coverage with provider and key label context."),
		mapImplemented("calendar/data", "calendarific", "calendarific-api-key", "Calendarific API key coverage with provider and key label context."),
		mapImplemented("environment", "carboninterface", "carboninterface-api-key", "Carbon Interface API key coverage with provider and key/token label context."),
		mapImplemented("document", "craftmypdf", "craftmypdf-api-key", "CraftMyPDF API key coverage with provider and key label context."),
		mapImplemented("data-provider", "currentsapi", "currentsapi-api-key", "CurrentsAPI key coverage with provider and key label context."),
		mapImplemented("email-validation", "debounce", "debounce-api-key", "DeBounce API key coverage with provider and key label context."),
		mapImplemented("language", "detectlanguage", "detectlanguage-api-key", "Detect Language API key coverage with provider and key label context."),
		mapImplemented("developer-docs", "readme", "readme-api-key", "ReadMe API key coverage."),
		mapImplemented("incident-management", "rootly", "rootly-api-key", "Rootly API key coverage."),
		mapImplemented("storage/web3", "web3storage", "web3storage-token", "Web3.Storage token coverage."),
		mapImplemented("product-management", "aha", "aha-api-key", "Aha API key coverage with tenant context."),
		mapImplemented("collaboration", "larksuiteapikey", "larksuite-app-secret", "LarkSuite app secret coverage with app ID context."),
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
