package detectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	DetectorID  string `json:"detector_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Commit      string `json:"commit,omitempty"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Secret      string `json:"secret"`
	Redacted    string `json:"redacted"`
	Verified    bool   `json:"verified"`
	Fingerprint string `json:"fingerprint"`
}

type Candidate struct {
	DetectorID string
	Name       string
	Severity   string
	Secret     string
	Start      int
	End        int
	Verifier   Verifier
}

type Verifier func(context.Context, string) bool

type Detector interface {
	Detect([]byte) []Candidate
	Info() Info
}

type Info struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Keywords   []string `json:"keywords,omitempty"`
	Verifiable bool     `json:"verifiable"`
}

type RegexDetector struct {
	ID          string
	Name        string
	Severity    string
	Keywords    []string
	Regex       *regexp.Regexp
	SecretGroup int
	Verifier    Verifier
}

func (d RegexDetector) Detect(b []byte) []Candidate {
	content := string(b)
	low := strings.ToLower(content)
	if len(d.Keywords) > 0 {
		ok := false
		for _, kw := range d.Keywords {
			if strings.Contains(low, strings.ToLower(kw)) {
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}
	}

	matches := d.Regex.FindAllStringSubmatchIndex(content, -1)
	out := make([]Candidate, 0, len(matches))
	for _, m := range matches {
		group := d.SecretGroup
		if group < 0 || group*2+1 >= len(m) || m[group*2] < 0 {
			group = 0
		}
		start, end := m[group*2], m[group*2+1]
		secret := content[start:end]
		if plausibleSecret(secret) {
			out = append(out, Candidate{DetectorID: d.ID, Name: d.Name, Severity: d.Severity, Secret: secret, Start: start, End: end, Verifier: d.Verifier})
		}
	}
	return out
}

func (d RegexDetector) Info() Info {
	return Info{ID: d.ID, Name: d.Name, Severity: d.Severity, Keywords: d.Keywords, Verifiable: d.Verifier != nil}
}

func RegistryInfo(ds []Detector) []Info {
	out := make([]Info, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Info())
	}
	return out
}

func NewRegex(id, name, severity string, keywords []string, expr string, group int, verifier Verifier) Detector {
	return RegexDetector{ID: id, Name: name, Severity: severity, Keywords: keywords, Regex: regexp.MustCompile(expr), SecretGroup: group, Verifier: verifier}
}

func DefaultRegistry() []Detector {
	return []Detector{
		NewRegex("aws-access-key", "AWS Access Key", "critical", []string{"AKIA", "ASIA"}, `\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`, 1, nil),
		NewRegex("aws-secret-key", "AWS Secret Access Key", "critical", []string{"aws_secret", "secret_access_key", "AWS_SECRET_ACCESS_KEY"}, `(?i)(aws(.{0,20})?(secret|private).{0,20})['\"\s:=]+([A-Za-z0-9/+=]{40})\b`, 4, nil),
		NewRegex("github-token", "GitHub Token", "critical", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github"}, `\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b`, 1, verifyGitHub),
		NewRegex("github-pat-v2", "GitHub Fine-Grained Token", "critical", []string{"github_pat_"}, `\b(github_pat_[A-Za-z0-9_]{80,255})\b`, 1, verifyGitHub),
		NewRegex("slack-token", "Slack Token", "critical", []string{"xoxb-", "xoxp-", "xoxa-"}, `\b((?:xox[baprs]|xoxa)-[A-Za-z0-9-]{10,200})\b`, 1, nil),
		NewRegex("stripe-key", "Stripe Secret Key", "critical", []string{"sk_live_", "rk_live_"}, `\b((?:sk|rk)_live_[A-Za-z0-9]{16,99})\b`, 1, nil),
		NewRegex("openai-key", "OpenAI API Key", "critical", []string{"sk-", "OPENAI"}, `\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,200})\b`, 1, verifyOpenAI),
		NewRegex("anthropic-key", "Anthropic API Key", "critical", []string{"sk-ant-"}, `\b(sk-ant-[A-Za-z0-9_-]{40,200})\b`, 1, nil),
		NewRegex("google-api-key", "Google API Key", "high", []string{"AIza"}, `\b(AIza[0-9A-Za-z_-]{35})\b`, 1, nil),
		NewRegex("google-oauth-client-secret", "Google OAuth Client Secret", "high", []string{"client_secret", "googleusercontent"}, `(?i)\b(client_secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{24})`, 2, nil),
		NewRegex("airtable-oauth-client-secret", "Airtable OAuth Client Secret", "critical", []string{"airtable", "airtable.com/oauth"}, `(?i)\b(?:airtable|airtable\.com/oauth)\b[\s\S]{0,240}\b(?:client[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("anypoint-oauth-client-secret", "Anypoint OAuth Client Secret", "critical", []string{"anypoint", "mulesoft"}, `(?i)\b(?:anypoint|mulesoft)\b[\s\S]{0,240}\b(?:client[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("asana-oauth-client-secret", "Asana OAuth Client Secret", "critical", []string{"asana", "app.asana.com/-/oauth"}, `(?i)\b(?:asana|app\.asana\.com/-/oauth)\b[\s\S]{0,240}\b(?:client[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("sendgrid-key", "SendGrid API Key", "critical", []string{"SG."}, `\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("twilio-key", "Twilio API Key", "high", []string{"SK", "twilio"}, `\b(SK[0-9a-fA-F]{32})\b`, 1, nil),
		NewRegex("mailgun-key", "Mailgun API Key", "high", []string{"key-", "mailgun"}, `\b(key-[0-9a-fA-F]{32})\b`, 1, nil),
		NewRegex("gitlab-token", "GitLab Token", "critical", []string{"glpat-", "gldt-"}, `\b((?:glpat|gldt)-[A-Za-z0-9_-]{20,128})\b`, 1, nil),
		NewRegex("bitbucket-app-password", "Bitbucket App Password", "high", []string{"bitbucket", "ATBB"}, `\b(ATBB[a-zA-Z0-9_-]{20,80})\b`, 1, nil),
		NewRegex("box-client-secret", "Box Client Secret", "critical", []string{"boxAppSettings", "api.box.com/oauth2/token", "box_subject_type", "box_subject_id"}, `(?i)\b(?:boxAppSettings|api\.box\.com/oauth2/token|box[_-]?subject[_-]?type|box[_-]?subject[_-]?id)\b[\s\S]{0,500}\b(?:clientSecret|client[_-]?secret|box[_-]?client[_-]?secret)\b['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("discord-token", "Discord Token", "critical", []string{"discord", "Bot "}, `\b([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,})\b`, 1, nil),
		NewRegex("discord-bot-token", "Discord Bot Token", "critical", []string{"discord", "Bot "}, `(?i)\bBot\s+([A-Za-z0-9._-]{50,90})\b`, 1, nil),
		NewRegex("telegram-bot-token", "Telegram Bot Token", "critical", []string{"bot", "telegram"}, `\b(\d{8,10}:[A-Za-z0-9_-]{35})\b`, 1, nil),
		NewRegex("npm-token", "npm Token", "critical", []string{"npm_", "//registry.npmjs.org"}, `\b(npm_[A-Za-z0-9]{36})\b`, 1, nil),
		NewRegex("pypi-token", "PyPI Token", "critical", []string{"pypi-"}, `\b(pypi-[A-Za-z0-9_-]{50,200})\b`, 1, nil),
		NewRegex("dockerhub-token", "Docker Hub Token", "high", []string{"dckr_pat_"}, `\b(dckr_pat_[A-Za-z0-9_-]{27,128})\b`, 1, nil),
		NewRegex("datadog-api-key", "Datadog API Key", "critical", []string{"datadog", "DD_API_KEY"}, `(?i)\b(datadog|dd_api_key).{0,20}['\"\s:=]+([a-f0-9]{32})\b`, 2, nil),
		NewRegex("new-relic-key", "New Relic Key", "high", []string{"NRAK-", "newrelic"}, `\b(NR(?:AK|II)-[A-Za-z0-9]{20,80})\b`, 1, nil),
		NewRegex("pagerduty-token", "PagerDuty Token", "high", []string{"pagerduty"}, `(?i)\bpagerduty.{0,20}['\"\s:=]+([A-Za-z0-9_+=-]{20,128})\b`, 1, nil),
		NewRegex("heroku-api-key", "Heroku API Key", "critical", []string{"heroku"}, `(?i)\bheroku.{0,20}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("cloudflare-api-token", "Cloudflare API Token", "critical", []string{"cloudflare"}, `(?i)\bcloudflare.{0,20}['\"\s:=]+([A-Za-z0-9_-]{35,80})\b`, 1, nil),
		NewRegex("digitalocean-token", "DigitalOcean Token", "critical", []string{"dop_v1_", "digitalocean"}, `\b(dop_v1_[A-Fa-f0-9]{64})\b`, 1, nil),
		NewRegex("azure-devops-pat", "Azure DevOps Personal Access Token", "critical", []string{"AZDO", "azure", "devops"}, `\b([A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5})\b`, 1, nil),
		NewRegex("terraform-cloud-token", "Terraform Cloud Token", "critical", []string{".atlasv1.", "terraform", "tfe"}, `\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{67})\b`, 1, nil),
		NewRegex("netlify-token", "Netlify Token", "high", []string{"nfp_", "netlify"}, `\b(nfp_[A-Za-z0-9_-]{40,})\b`, 1, nil),
		NewRegex("pulumi-token", "Pulumi Access Token", "critical", []string{"pul-", "pulumi"}, `\b(pul-[a-f0-9]{40})\b`, 1, nil),
		NewRegex("doppler-token", "Doppler Token", "critical", []string{"dp.pt.", "dp.st.", "dp.ct.", "doppler"}, `\b(dp\.(?:pt|st|ct|scim)\.[A-Za-z0-9_-]{20,})\b`, 1, nil),
		NewRegex("tailscale-key", "Tailscale Key", "critical", []string{"tskey-", "tailscale"}, `\b(tskey-(?:api|auth|client)-[A-Za-z0-9_-]{20,})\b`, 1, nil),
		NewRegex("ngrok-token", "ngrok Token", "critical", []string{"ngrok_api_", "ngrok_api_key_", "ngrok_pat_"}, `\b(ngrok_(?:api(?:_key)?|pat)_[A-Za-z0-9_]{20,})\b`, 1, nil),
		NewRegex("buildkite-token", "Buildkite Token", "critical", []string{"bkua_", "bkpa_", "bkca_", "buildkite"}, `\b(bk(?:ua|pa|ca)_[A-Za-z0-9]{30,})\b`, 1, nil),
		NewRegex("nuget-api-key", "NuGet API Key", "high", []string{"oy2", "nuget"}, `\b(oy2[A-Za-z0-9]{43})\b`, 1, nil),
		NewRegex("rubygems-api-key", "RubyGems API Key", "high", []string{"rubygems_"}, `\b(rubygems_[a-f0-9]{48})\b`, 1, nil),
		NewRegex("linear-api-key", "Linear API Key", "high", []string{"lin_api_"}, `\b(lin_api_[A-Za-z0-9]{40,128})\b`, 1, nil),
		NewRegex("notion-token", "Notion Token", "high", []string{"secret_", "notion"}, `\b(secret_[A-Za-z0-9]{32,80})\b`, 1, nil),
		NewRegex("postman-api-key", "Postman API Key", "high", []string{"PMAK-"}, `\b(PMAK-[A-Za-z0-9-]{50,120})\b`, 1, nil),
		NewRegex("supabase-key", "Supabase Key", "high", []string{"supabase", "eyJ"}, `\b(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b`, 1, nil),
		NewRegex("firebase-token", "Firebase Token", "high", []string{"firebase", "AAAA"}, `\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b`, 1, nil),
		NewRegex("mongodb-uri", "MongoDB Connection URI", "critical", []string{"mongodb://", "mongodb+srv://"}, `\b(mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)`, 1, nil),
		NewRegex("postgres-uri", "PostgreSQL Connection URI", "critical", []string{"postgres://", "postgresql://"}, `\b(postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)`, 1, nil),
		NewRegex("mysql-uri", "MySQL Connection URI", "critical", []string{"mysql://"}, `\b(mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)`, 1, nil),
		NewRegex("ftp-credential-url", "FTP Credential URL", "critical", []string{"ftp://", "ftps://", "sftp://"}, `\b((?:s?ftp|ftps)://[^:\s'\"/@]{1,120}:[^@\s'\"/]{8,120}@[^\s'\"<>]+)`, 1, nil),
		NewRegex("shopify-token", "Shopify Token", "high", []string{"shpat_", "shpca_", "shppa_", "shpss_"}, `\b(shp(?:at|ca|pa|ss)_[A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("shopify-oauth-client-secret", "Shopify OAuth Client Secret", "critical", []string{"shopify", "myshopify.com", "shopify_app_secret"}, `(?i)\b(?:shopify|myshopify\.com|shopify[_-]?app[_-]?secret)\b[\s\S]{0,240}\b(?:client[_-]?secret|app[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("square-token", "Square Token", "critical", []string{"sq0atp-", "sq0csp-"}, `\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,60})\b`, 1, nil),
		NewRegex("paypal-token", "PayPal Token", "high", []string{"paypal"}, `(?i)\bpaypal.{0,20}['\"\s:=]+([A-Za-z0-9_-]{40,128})\b`, 1, nil),
		NewRegex("razorpay-key", "Razorpay Key ID", "high", []string{"rzp_live_"}, `\b(rzp_live_[A-Za-z0-9]{14})\b`, 1, nil),
		NewRegex("slack-webhook", "Slack Webhook URL", "critical", []string{"hooks.slack.com"}, `\b(https://hooks\.slack\.com/(?:services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25}|workflows/T[A-Z0-9]+/A[A-Z0-9]+/[0-9]{17,19}/[A-Za-z0-9]{23,25}))\b`, 1, nil),
		NewRegex("discord-webhook", "Discord Webhook URL", "critical", []string{"discord.com/api/webhooks"}, `\b(https://discord\.com/api/webhooks/[0-9]{18,19}/[0-9A-Za-z-]{68})\b`, 1, nil),
		NewRegex("microsoft-teams-webhook", "Microsoft Teams Webhook URL", "critical", []string{"webhook.office.com"}, `\b(https://[A-Za-z0-9-]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9-]{36}@[A-Za-z0-9-]{36}/IncomingWebhook/[A-Za-z0-9]{32}/[A-Za-z0-9-]{36})\b`, 1, nil),
		NewRegex("grafana-token", "Grafana Token", "critical", []string{"glc_eyJ"}, `\b(glc_eyJ[A-Za-z0-9+/=]{60,160})\b`, 1, nil),
		NewRegex("grafana-service-account-token", "Grafana Service Account Token", "critical", []string{"glsa_"}, `\b(glsa_[0-9A-Za-z_]{41})\b`, 1, nil),
		NewRegex("sentry-user-token", "Sentry User Token", "critical", []string{"sntryu_"}, `\b(sntryu_[a-f0-9]{64})\b`, 1, nil),
		NewRegex("sentry-org-token", "Sentry Organization Token", "critical", []string{"sntrys_eyJ"}, `\b(sntrys_eyJ[A-Za-z0-9=_+/]{197})\b`, 1, nil),
		NewRegex("honeycomb-api-key", "Honeycomb API Key", "high", []string{"honeycomb"}, `(?i)\bhoneycomb.{0,40}['\"\s:=]+([0-9a-f]{32}|[0-9A-Za-z]{22})\b`, 1, nil),
		NewRegex("opsgenie-api-key", "Opsgenie API Key", "high", []string{"opsgenie"}, `(?i)\bopsgenie.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("splunk-observability-token", "Splunk Observability Token", "high", []string{"splunk", "signalfx", "X-Sf-Token"}, `(?i)\b(?:splunk|signalfx|x-sf-token).{0,40}['\"\s:=]+([A-Za-z0-9]{22})\b`, 1, nil),
		NewRegex("webex-bot-token", "Webex Bot Token", "critical", []string{"webex", "spark"}, `\b([A-Za-z0-9]{64}_[A-Za-z0-9]{4}_[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12})\b`, 1, nil),
		NewRegex("huggingface-token", "Hugging Face Token", "critical", []string{"hf_", "huggingface"}, `\b(hf_[A-Za-z0-9]{34,80})\b`, 1, nil),
		NewRegex("groq-api-key", "Groq API Key", "critical", []string{"gsk_", "groq"}, `\b(gsk_[A-Za-z0-9]{52})\b`, 1, nil),
		NewRegex("replicate-token", "Replicate Token", "critical", []string{"r8_", "replicate"}, `\b(r8_[A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("airtable-pat", "Airtable Personal Access Token", "critical", []string{"pat", "airtable"}, `\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`, 1, nil),
		NewRegex("asana-pat", "Asana Personal Access Token", "critical", []string{"asana"}, `\b([0-9]+/[0-9]{16,}(?:/[0-9]{16,})?:[A-Za-z0-9]{32,})\b`, 1, nil),
		NewRegex("clickup-token", "ClickUp Personal Token", "critical", []string{"pk_", "clickup"}, `\b(pk_[0-9]{7,9}_[0-9A-Z]{32})\b`, 1, nil),
		NewRegex("typeform-token", "Typeform Token", "critical", []string{"tfp_", "typeform"}, `\b(tfp_[A-Za-z0-9_]{40,59})\b`, 1, nil),
		NewRegex("hubspot-private-app-token", "HubSpot Private App Token", "critical", []string{"pat-na1-", "pat-eu1-", "hubspot"}, `\b(pat-(?:eu|na)1-[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12})\b`, 1, nil),
		NewRegex("mailchimp-key", "Mailchimp API Key", "high", []string{"mailchimp", "-us"}, `\b([0-9a-f]{32}-us[0-9]{1,2})\b`, 1, nil),
		NewRegex("klaviyo-key", "Klaviyo API Key", "high", []string{"klaviyo", "pk_"}, `\b(pk_(?:[0-9a-f]{34}|[A-Za-z0-9]{6}_[0-9a-f]{34}))\b`, 1, nil),
		NewRegex("braze-api-key", "Braze API Key", "critical", []string{"braze", "rest.iad", "rest.fra"}, `(?i)\b(?:braze|rest\.[a-z0-9-]+\.braze\.(?:com|eu))\b[\s\S]{0,160}\b(?:braze[_-]?api[_-]?key|api[_-]?key|rest[_-]?api[_-]?key|bearer|authorization)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("iterable-api-key", "Iterable API Key", "critical", []string{"iterable", "api.iterable.com", "Api-Key"}, `(?i)\b(?:iterable|api\.iterable\.com|api-key)\b[\s\S]{0,160}\b(?:api[_-]?key|iterable[_-]?api[_-]?key|api-key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("activecampaign-api-token", "ActiveCampaign API Token", "critical", []string{"activecampaign", "api-us", "Api-Token"}, `(?i)\b(?:activecampaign|api-token|[a-z0-9-]+\.api-us[0-9]+\.com/api/3)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|api-token|activecampaign[_-]?api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("marketo-client-secret", "Marketo Client Secret", "critical", []string{"marketo", "mktorest.com"}, `(?i)\b(?:marketo|mktorest\.com)\b[\s\S]{0,240}\b(?:client[_-]?secret|marketo[_-]?client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("tiktok-business-api-secret", "TikTok Business API Secret", "critical", []string{"tiktok", "business-api.tiktok.com", "Access-Token"}, `(?i)\b(?:tiktok|business-api\.tiktok\.com|access-token)\b[\s\S]{0,200}\b(?:access[_-]?token|access-token|app[_-]?secret|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("linkedin-client-secret", "LinkedIn Client Secret", "critical", []string{"linkedin", "api.linkedin.com"}, `(?i)\b(?:linkedin|api\.linkedin\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|linkedin[_-]?client[_-]?secret|access[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("sfmc-client-secret", "Salesforce Marketing Cloud Client Secret", "critical", []string{"marketingcloudapis.com", "sfmc", "pardot"}, `(?i)\b(?:auth\.marketingcloudapis\.com|sfmc|pardot|pi\.pardot\.com)\b[\s\S]{0,240}\b(?:client[_-]?secret|sfmc[_-]?client[_-]?secret|pardot[_-]?client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("google-ads-developer-token", "Google Ads Developer Token", "critical", []string{"google-ads.yaml", "developer-token", "googleads.googleapis.com"}, `(?i)\b(?:google-ads\.yaml|googleads\.googleapis\.com|developer-token|google[_-]?ads)\b[\s\S]{0,200}\b(?:developer[_-]?token|developer-token|google[_-]?ads[_-]?developer[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{16,128})\b`, 1, nil),
		NewRegex("branch-secret", "Branch Secret", "critical", []string{"branch_secret", "api2.branch.io", "branch.io"}, `(?i)\b(?:api2\.branch\.io|branch\.io|branch[_-]?secret)\b[\s\S]{0,200}\b(?:branch[_-]?secret|secret)\b\s*[:=]\s*['\"]?(secret_[A-Za-z0-9._-]{24,128}|[A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("appsflyer-api-token", "AppsFlyer API Token", "critical", []string{"appsflyer", "api.appsflyer.com"}, `(?i)\b(?:appsflyer|api\.appsflyer\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|dev[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("adjust-api-token", "Adjust API Token", "critical", []string{"adjust", "api.adjust.com"}, `(?i)\b(?:adjust|api\.adjust\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|user[_-]?token|authorization|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("attentive-api-key", "Attentive API Key", "critical", []string{"attentivemobile", "attentive"}, `(?i)\b(?:attentivemobile|api\.attentivemobile\.com|attentive)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|signing[_-]?secret|webhook[_-]?secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("nightfall-api-key", "Nightfall API Key", "critical", []string{"NF-", "nightfall"}, `\b(NF-[A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("endorlabs-token", "Endor Labs Token", "critical", []string{"endr+"}, `\b(endr\+[A-Za-z0-9-]{16})\b`, 1, nil),
		NewRegex("trufflehog-enterprise-key", "TruffleHog Enterprise Key", "critical", []string{"thog-key-", "thog"}, `\b(thog-key-[0-9a-f]{16})\b`, 1, nil),
		NewRegex("trufflehog-enterprise-secret", "TruffleHog Enterprise Secret", "critical", []string{"thog-secret-", "thog"}, `\b(thog-secret-[0-9a-f]{32})\b`, 1, nil),
		NewRegex("tines-webhook", "Tines Webhook URL", "critical", []string{"tines.com/webhook"}, `\b(https://[A-Za-z0-9-]+\.tines\.com/webhook/[a-z0-9]{32}/[a-z0-9]{32})\b`, 1, nil),
		NewRegex("pinecone-api-key", "Pinecone API Key", "critical", []string{"pcsk_"}, `\b(pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63})\b`, 1, nil),
		NewRegex("langsmith-api-key", "LangSmith API Key", "critical", []string{"lsv2_pt_", "lsv2_sk_"}, `\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b`, 1, nil),
		NewRegex("langfuse-secret-key", "Langfuse Secret Key", "critical", []string{"sk-lf-"}, `\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("elevenlabs-api-key", "ElevenLabs API Key", "critical", []string{"elevenlabs", "xi-api-key", "xi_api_key"}, `\b(sk_[a-f0-9]{48})\b`, 1, nil),
		NewRegex("xai-api-key", "xAI API Key", "critical", []string{"xai-"}, `\b(xai-[0-9A-Za-z_]{80})\b`, 1, nil),
		NewRegex("cohere-api-key", "Cohere API Key", "critical", []string{"cohere", "api.cohere.ai"}, `(?i)\b(?:cohere|api\.cohere\.ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mistral-api-key", "Mistral API Key", "critical", []string{"mistral", "api.mistral.ai"}, `(?i)\b(?:mistral|api\.mistral\.ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("togetherai-api-key", "Together AI API Key", "critical", []string{"together.ai", "api.together.xyz"}, `(?i)\b(?:together\.ai|api\.together\.xyz|together[_-]?ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("fireworksai-api-key", "Fireworks AI API Key", "critical", []string{"fireworks.ai", "api.fireworks.ai"}, `(?i)\b(?:fireworks\.ai|api\.fireworks\.ai|fireworks[_-]?ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("voyageai-api-key", "Voyage AI API Key", "critical", []string{"voyageai", "api.voyageai.com"}, `(?i)\b(?:voyageai|voyage[_-]?ai|api\.voyageai\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("perplexity-api-key", "Perplexity API Key", "critical", []string{"pplx-", "api.perplexity.ai"}, `(?i)\b(?:perplexity|api\.perplexity\.ai|pplx-)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?((?:pplx-)?[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("openrouter-api-key", "OpenRouter API Key", "critical", []string{"openrouter", "openrouter.ai", "sk-or-"}, `(?i)\b(?:openrouter|openrouter\.ai|sk-or-)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?((?:sk-or-[A-Za-z0-9._-]{24,256}|[A-Za-z0-9._-]{32,256}))\b`, 1, nil),
		NewRegex("ai21-api-key", "AI21 API Key", "critical", []string{"ai21", "api.ai21.com"}, `(?i)\b(?:ai21|api\.ai21\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("cerebras-api-key", "Cerebras API Key", "critical", []string{"cerebras", "api.cerebras.ai"}, `(?i)\b(?:cerebras|api\.cerebras\.ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("baseten-api-key", "Baseten API Key", "critical", []string{"baseten", "model-apis.baseten.co"}, `(?i)\b(?:baseten|model-apis\.baseten\.co|app\.baseten\.co)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("runpod-api-key", "Runpod API Key", "critical", []string{"runpod", "api.runpod.ai"}, `(?i)\b(?:runpod|api\.runpod\.ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("modal-api-token", "Modal API Token", "critical", []string{"modal", "api.modal.com"}, `(?i)\b(?:modal|api\.modal\.com|modal\.com)\b[\s\S]{0,160}\b(?:token[_-]?id|token[_-]?secret|api[_-]?token|api[_-]?key|authorization|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("fal-ai-api-key", "fal.ai API Key", "critical", []string{"fal.ai", "fal_key"}, `(?i)\b(?:fal\.ai|api\.fal\.ai|fal[_-]?key|fal[_-]?ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._:-]{32,256})\b`, 1, nil),
		NewRegex("novita-api-key", "Novita AI API Key", "critical", []string{"novita", "api.novita.ai"}, `(?i)\b(?:novita|api\.novita\.ai)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("predibase-api-token", "Predibase API Token", "critical", []string{"predibase", "serving.app.predibase.com"}, `(?i)\b(?:predibase|serving\.app\.predibase\.com|api\.predibase\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("octoai-api-token", "OctoAI API Token", "critical", []string{"octoai", "api.octoai.cloud"}, `(?i)\b(?:octoai|octo\.ai|api\.octoai\.cloud)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("qdrant-api-key", "Qdrant API Key", "critical", []string{"qdrant", "cloud.qdrant.io"}, `(?i)\b(?:qdrant|cloud\.qdrant\.io|api\.qdrant\.tech)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("weaviate-api-key", "Weaviate API Key", "critical", []string{"weaviate", "weaviate.cloud"}, `(?i)\b(?:weaviate|weaviate\.cloud|weaviate\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("zilliz-api-key", "Zilliz API Key", "critical", []string{"zilliz", "api.cloud.zilliz.com"}, `(?i)\b(?:zilliz|api\.cloud\.zilliz\.com|cloud\.zilliz\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("chroma-cloud-api-key", "Chroma Cloud API Key", "critical", []string{"trychroma", "chroma"}, `(?i)\b(?:trychroma|api\.trychroma\.com|chroma[_-]?cloud)\b[\s\S]{0,160}\b(?:api[_-]?key|authorization|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("voiceflow-api-key", "Voiceflow API Key", "critical", []string{"VF.", "voiceflow"}, `\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[A-Za-z0-9]{16})\b`, 1, nil),
		NewRegex("harness-pat", "Harness Personal Access Token", "critical", []string{"harness"}, `\b(pat\.[A-Za-z0-9]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20})\b`, 1, nil),
		NewRegex("zoho-crm-token", "Zoho CRM Token", "critical", []string{"1000.", "zoho"}, `\b(1000\.[a-f0-9]{32}\.[a-f0-9]{32})\b`, 1, nil),
		NewRegex("intercom-access-token", "Intercom Access Token", "critical", []string{"intercom", "dG9rO"}, `(?i)\bintercom.{0,40}['\"\s:=]+(dG9rO[A-Za-z0-9+/]{54}=)`, 1, nil),
		NewRegex("front-api-token", "Front API Token", "critical", []string{"front", "frontapp"}, `(?i)\b(?:front(?:\b|[_-])|frontapp\.com|api2\.frontapp\.com|front[_-]?api)\b?[\s\S]{0,160}?(?:['\"\s:=]+|\b(?:api[_-]?token|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?)([0-9A-Za-z]{36}\.[0-9A-Za-z._-]{188,244}|[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("segment-api-key", "Segment API Key", "high", []string{"segment"}, `(?i)\bsegment.{0,40}['\"\s:=]+([A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("posthog-personal-api-key", "PostHog Personal API Key", "critical", []string{"phx_", "posthog"}, `\b(phx_[A-Za-z0-9_]{43})\b`, 1, nil),
		NewRegex("launchdarkly-key", "LaunchDarkly Key", "critical", []string{"api-", "sdk-", "launchdarkly"}, `\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`, 1, nil),
		NewRegex("postmark-token", "Postmark Server Token", "high", []string{"postmark"}, `(?i)\bpostmark.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("coda-api-token", "Coda API Token", "high", []string{"coda"}, `(?i)\bcoda.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("calendly-api-key", "Calendly API Key", "high", []string{"calendly"}, `(?i)\bcalendly.{0,40}['\"\s:=]+(eyJ[A-Za-z0-9_-]{100,300}\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]+)\b`, 1, nil),
		NewRegex("monday-api-token", "Monday.com API Token", "high", []string{"monday"}, `(?i)\bmonday.{0,40}['\"\s:=]+(eyJ[A-Za-z0-9_-]{15,100}\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]{25,100})\b`, 1, nil),
		NewRegex("flyio-token", "Fly.io Token", "critical", []string{"FlyV1"}, `\b(FlyV1 fm\d+_[A-Za-z0-9+/=,_-]{500,700})\b`, 1, nil),
		NewRegex("cloudflare-ca-key", "Cloudflare CA Key", "critical", []string{"cloudflare", "v1.0-"}, `\b(v1\.0-[A-Za-z0-9-]{171})\b`, 1, nil),
		NewRegex("artifactory-access-token", "Artifactory Access Token", "critical", []string{"AKCp", "jfrog", "artifactory"}, `\b(AKCp[A-Za-z0-9]{69})\b`, 1, nil),
		NewRegex("artifactory-reference-token", "Artifactory Reference Token", "critical", []string{"cmVmdGtu"}, `\b(cmVmdGtu[A-Za-z0-9]{56})\b`, 1, nil),
		NewRegex("azure-app-config-connection-string", "Azure App Configuration Connection String", "critical", []string{".azconfig.io", "Endpoint=", "Secret="}, `(Endpoint=https://[A-Za-z0-9-]+\.azconfig\.io;Id=[A-Za-z0-9+/=]+;Secret=[A-Za-z0-9+/=]+)`, 1, nil),
		NewRegex("azure-storage-connection-string", "Azure Storage Connection String", "critical", []string{"AccountName", "AccountKey", "core.windows.net"}, `(DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/-]{86,88}={0,2};EndpointSuffix=core\.windows\.net)`, 1, nil),
		NewRegex("azure-cosmosdb-connection-string", "Azure Cosmos DB Connection String", "critical", []string{".documents.azure.com", ".table.cosmos.azure.com", "AccountKey"}, `(AccountEndpoint=https://[a-z0-9-]{3,44}\.(?:documents|table\.cosmos)\.azure\.com(?::443)?/;AccountKey=[A-Za-z0-9+/]{86}==;)`, 1, nil),
		NewRegex("azure-sas-url", "Azure SAS URL", "critical", []string{".blob.core.windows.net", "sig=", "sp="}, `(https://[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.blob\.core\.windows\.net/[A-Za-z0-9._~!$&'()*+,;=:@/%-]+\?sp=[racwdli]+&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z(?:&sip=\d{1,3}(?:\.\d{1,3}){3}(?:-\d{1,3}(?:\.\d{1,3}){3})?)?&spr=https(?:,https)?&sv=\d{4}-\d{2}-\d{2}&sr=[bcfso]&sig=[A-Za-z0-9%+/=]{10,})`, 1, nil),
		NewRegex("azure-function-key-url", "Azure Function Key URL", "critical", []string{"azurewebsites.net", "code="}, `https://[A-Za-z0-9-]{2,30}\.azurewebsites\.net/api/[A-Za-z0-9-]{2,30}[^\s'\"<>]*[?&]code=([A-Za-z0-9_-]{20,56}={0,2})`, 1, nil),
		NewRegex("spectralops-token", "SpectralOps Token", "critical", []string{"spu-"}, `\b(spu-[a-z0-9]{32})\b`, 1, nil),
		NewRegex("atlassian-api-token", "Atlassian API Token", "critical", []string{"ATCTT3xFfG", "atlassian"}, `\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`, 1, nil),
		NewRegex("jira-api-token", "Jira API Token", "critical", []string{"ATATT", "jira", "atlassian", "confluence"}, `\b(ATATT[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`, 1, nil),
		NewRegex("salesforce-access-token", "Salesforce Access Token", "critical", []string{"salesforce", ".my.salesforce.com", "00"}, `\b(00[A-Za-z0-9]{13}![A-Za-z0-9_.]{96})\b`, 1, nil),
		NewRegex("salesforce-refresh-token", "Salesforce Refresh Token", "critical", []string{"5AEP861", "salesforce"}, `\b(5AEP861[A-Za-z0-9._=]{80,})\b`, 1, nil),
		NewRegex("salesforce-consumer-key", "Salesforce Consumer Key", "high", []string{"3MVG9", "salesforce"}, `\b(3MVG9[0-9A-Za-z._+/=]{80,251})\b`, 1, nil),
		NewRegex("twilio-auth-token", "Twilio Auth Token", "critical", []string{"twilio", "auth_token", "AC"}, `(?i)\bAC[0-9a-f]{32}\b[\s\S]{0,160}\b(?:auth[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([0-9a-f]{32})\b`, 1, nil),
		NewRegex("openphone-api-key", "OpenPhone API Key", "critical", []string{"openphone", "api.openphone.com"}, `(?i)\b(?:openphone|api\.openphone\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("aircall-api-token", "Aircall API Token", "critical", []string{"aircall", "api.aircall.io"}, `(?i)\b(?:aircall|api\.aircall\.io)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?id|access[_-]?token|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("dialpad-api-key", "Dialpad API Key", "critical", []string{"dialpad", "dialpad.com"}, `(?i)\b(?:dialpad|dialpad\.com|dialpad[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("five9-api-secret", "Five9 API Secret", "critical", []string{"five9", "five9.com"}, `(?i)\b(?:five9|five9\.com)\b[\s\S]{0,160}\b(?:client[_-]?secret|api[_-]?secret|api[_-]?key|password|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("genesys-cloud-client-secret", "Genesys Cloud Client Secret", "critical", []string{"genesys", "mypurecloud"}, `(?i)\b(?:genesys|mypurecloud\.(?:com|ie|de|jp|com\.au)|api\.mypurecloud)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|oauth[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("talkdesk-api-token", "Talkdesk API Token", "critical", []string{"talkdesk", "talkdeskapp.com"}, `(?i)\b(?:talkdesk|talkdeskapp\.com|api\.talkdeskapp\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|client[_-]?secret|access[_-]?token|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("ringover-api-key", "Ringover API Key", "critical", []string{"ringover", "api.ringover.com"}, `(?i)\b(?:ringover|api\.ringover\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("justcall-api-key", "JustCall API Key", "critical", []string{"justcall", "api.justcall.io"}, `(?i)\b(?:justcall|api\.justcall\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?secret|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("callrail-api-key", "CallRail API Key", "critical", []string{"callrail", "api.callrail.com"}, `(?i)\b(?:callrail|api\.callrail\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("calltrackingmetrics-api-key", "CallTrackingMetrics API Key", "critical", []string{"calltrackingmetrics", "api.calltrackingmetrics.com"}, `(?i)\b(?:calltrackingmetrics|call[ _-]?tracking[ _-]?metrics|api\.calltrackingmetrics\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mailjet-basic-auth", "Mailjet Basic Auth Credential", "high", []string{"mailjet"}, `(?i)\bmailjet\b[\s\S]{0,80}\b([A-Za-z0-9]{87}=)`, 1, nil),
		NewRegex("okta-api-token", "Okta API Token", "critical", []string{".okta"}, `(?i)\b[a-z0-9-]{1,40}\.okta(?:preview|-emea)?\.com\b[\s\S]{0,200}\b(00[A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("urlscan-api-key", "urlscan.io API Key", "high", []string{"urlscan"}, `(?i)\burlscan\b.{0,40}\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`, 1, nil),
		NewRegex("openai-admin-key", "OpenAI Admin Key", "critical", []string{"sk-admin-", "T3BlbkFJ"}, `\b(sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58})\b`, 1, verifyOpenAI),
		NewRegex("deepseek-api-key", "DeepSeek API Key", "critical", []string{"deepseek", "DEEPSEEK_API_KEY"}, `(?i)\bdeepseek.{0,40}['\"\s:=]+(sk-[a-z0-9]{32})\b`, 1, nil),
		NewRegex("weightsandbiases-api-key", "Weights & Biases API Key", "critical", []string{"wandb", "WANDB_API_KEY", "weightsandbiases", "weights & biases"}, `(?i)\b(?:wandb|weights.?and.?biases).{0,40}['\"\s:=]+([0-9a-f]{40})\b`, 1, nil),
		NewRegex("assemblyai-api-key", "AssemblyAI API Key", "critical", []string{"assemblyai", "ASSEMBLYAI_API_KEY"}, `(?i)\bassemblyai.{0,40}['\"\s:=]+([0-9a-z]{32})\b`, 1, nil),
		NewRegex("deepgram-api-key", "Deepgram API Key", "critical", []string{"deepgram", "DEEPGRAM_API_KEY"}, `(?i)\bdeepgram.{0,40}['\"\s:=]+([0-9a-z]{40})\b`, 1, nil),
		NewRegex("edenai-api-key", "Eden AI API Key", "critical", []string{"edenai", "EDENAI_API_KEY"}, `(?i)\bedenai.{0,40}['\"\s:=]+([A-Za-z0-9]{36}\.[A-Za-z0-9]{92}\.[A-Za-z0-9_]{43})\b`, 1, nil),
		NewRegex("monkeylearn-api-key", "MonkeyLearn API Key", "high", []string{"monkeylearn", "MONKEYLEARN_API_KEY"}, `(?i)\bmonkeylearn.{0,40}['\"\s:=]+([0-9a-f]{40})\b`, 1, nil),
		NewRegex("contentful-pat", "Contentful Personal Access Token", "critical", []string{"CFPAT-"}, `\b(CFPAT-[A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("storyblok-personal-access-token", "Storyblok Personal Access Token", "critical", []string{"storyblok"}, `(?i)\bstoryblok.{0,40}['\"\s:=]+([0-9A-Za-z]{22}tt-[0-9]{6}-[A-Za-z0-9_-]{20})\b`, 1, nil),
		NewRegex("storyblok-access-token", "Storyblok Access Token", "high", []string{"storyblok"}, `(?i)\bstoryblok.{0,40}['\"\s:=]+([0-9A-Za-z]{22}tt)\b`, 1, nil),
		NewRegex("sanity-auth-token", "Sanity Auth Token", "critical", []string{"sanity"}, `(?i)\bsanity.{0,40}['\"\s:=]+(sk[A-Za-z0-9]{79})\b`, 1, nil),
		NewRegex("contentstack-api-key", "Contentstack API Key", "critical", []string{"contentstack", "cdn.contentstack.io"}, `(?i)\b(?:contentstack|cdn\.contentstack\.io|api\.contentstack\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|management[_-]?token|delivery[_-]?token|authtoken|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("datocms-api-token", "DatoCMS API Token", "critical", []string{"datocms", "dato.cms"}, `(?i)\b(?:datocms|dato[ _-]?cms|site-api\.datocms\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|read[_-]?only[_-]?token|full[_-]?access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("directus-api-token", "Directus API Token", "critical", []string{"directus", "directus.cloud"}, `(?i)\b(?:directus|directus\.cloud)\b[\s\S]{0,160}\b(?:static[_-]?token|api[_-]?token|access[_-]?token|admin[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("strapi-api-token", "Strapi API Token", "critical", []string{"strapi", "strapi.io"}, `(?i)\b(?:strapi|strapi\.io)\b[\s\S]{0,160}\b(?:api[_-]?token|admin[_-]?jwt[_-]?secret|transfer[_-]?token[_-]?salt|app[_-]?keys|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("prismic-api-token", "Prismic API Token", "critical", []string{"prismic", "prismic.io"}, `(?i)\b(?:prismic|prismic\.io|\.cdn\.prismic\.io)\b[\s\S]{0,160}\b(?:access[_-]?token|api[_-]?token|permanent[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("builderio-private-key", "Builder.io Private Key", "critical", []string{"builder.io", "builderio"}, `(?i)\b(?:builder\.io|builderio|cdn\.builder\.io)\b[\s\S]{0,160}\b(?:private[_-]?key|api[_-]?key|write[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("commercetools-client-secret", "commercetools Client Secret", "critical", []string{"commercetools", "commercetools.com"}, `(?i)\b(?:commercetools|auth\.[a-z0-9.-]*commercetools\.com|api\.[a-z0-9.-]*commercetools\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("bigcommerce-api-token", "BigCommerce API Token", "critical", []string{"bigcommerce", "mybigcommerce.com"}, `(?i)\b(?:bigcommerce|mybigcommerce\.com|api\.bigcommerce\.com)\b[\s\S]{0,200}\b(?:x-auth-token|api[_-]?token|access[_-]?token|client[_-]?secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("saleor-api-token", "Saleor API Token", "critical", []string{"saleor", "saleor.cloud"}, `(?i)\b(?:saleor|saleor\.cloud)\b[\s\S]{0,160}\b(?:api[_-]?token|auth[_-]?token|app[_-]?token|webhook[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("medusa-api-token", "Medusa API Token", "critical", []string{"medusa", "medusajs"}, `(?i)\b(?:medusa|medusajs|medusa\.js)\b[\s\S]{0,160}\b(?:api[_-]?token|admin[_-]?api[_-]?token|jwt[_-]?secret|cookie[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("elastic-email-api-key", "Elastic Email API Key", "critical", []string{"elasticemail", "elastic email"}, `(?i)\b(?:elasticemail|elastic[ _-]?email).{0,40}['\"\s:=]+([A-Za-z0-9_-]{96})\b`, 1, nil),
		NewRegex("shortcut-api-token", "Shortcut API Token", "high", []string{"shortcut"}, `(?i)\bshortcut.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("webflow-api-key", "Webflow API Key", "high", []string{"webflow"}, `(?i)\bwebflow.{0,40}['\"\s:=]+([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("mapbox-secret-token", "Mapbox Secret Token", "critical", []string{"sk.", "mapbox"}, `\b(sk\.[A-Za-z0-9.-]{80,240})\b`, 1, nil),
		NewRegex("locationiq-api-key", "LocationIQ API Key", "high", []string{"locationiq", "pk."}, `\b(pk\.[A-Za-z0-9-]{32})\b`, 1, nil),
		NewRegex("coinapi-key", "CoinAPI Key", "high", []string{"coinapi", "X-CoinAPI-Key"}, `\b([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})\b`, 1, nil),
		NewRegex("onfido-api-token", "Onfido API Token", "critical", []string{"api_live.", "api_sandbox.", "onfido"}, `\b(api_(?:live|sandbox)(?:_(?:us|ca))?\.[A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("sumsub-app-token", "Sumsub App Token", "critical", []string{"sumsub", "X-App-Token", "api.sumsub.com"}, `(?i)\b(?:sumsub|api\.sumsub\.com|x-app-token)\b[\s\S]{0,200}\b(?:x-app-token|app[_-]?token|secret[_-]?key|app[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("modern-treasury-api-key", "Modern Treasury API Key", "critical", []string{"moderntreasury", "modern treasury", "moderntreasury.com"}, `(?i)\b(?:moderntreasury|modern[ _-]?treasury|moderntreasury\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("treasury-prime-api-secret", "Treasury Prime API Secret", "critical", []string{"treasuryprime", "treasury prime"}, `(?i)\b(?:treasuryprime|treasury[ _-]?prime)\b[\s\S]{0,200}\b(?:api[_-]?secret|api[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("unit-api-token", "Unit API Token", "critical", []string{"api.unit.co", "api.s.unit.sh", "UNIT_API_TOKEN"}, `(?i)\b(?:api\.unit\.co|api\.s\.unit\.sh|unit[_-]?api[_-]?token|unit)\b[\s\S]{0,160}\b(?:api[_-]?token|org[_-]?api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("increase-api-key", "Increase API Key", "critical", []string{"increase", "api.increase.com"}, `(?i)\b(?:increase|api\.increase\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|webhook[_-]?secret|oauth[_-]?client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("lithic-api-key", "Lithic API Key", "critical", []string{"lithic", "api.lithic.com"}, `(?i)\b(?:lithic|api\.lithic\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("marqeta-api-token", "Marqeta API Token", "critical", []string{"marqeta", "sandbox-api.marqeta.com"}, `(?i)\b(?:marqeta|sandbox-api\.marqeta\.com)\b[\s\S]{0,200}\b(?:application[_-]?token|admin[_-]?access[_-]?token|api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("adyen-api-key", "Adyen API Key", "critical", []string{"adyen", "checkoutshopper", "ws_"}, `(?i)\b(?:adyen|checkoutshopper|ws_[0-9]+@Company\.[A-Za-z0-9_-]+)\b[\s\S]{0,200}\b(?:api[_-]?key|hmac[_-]?key|password|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("persona-api-key", "Persona API Key", "critical", []string{"withpersona", "persona"}, `(?i)\b(?:withpersona|api\.withpersona\.com|persona)\b[\s\S]{0,160}\b(?:persona[_-]?api[_-]?key|api[_-]?key|api[_-]?token|webhook[_-]?secret|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("fireblocks-api-key", "Fireblocks API Key", "critical", []string{"fireblocks", "X-API-Key"}, `(?i)\b(?:fireblocks|x-api-key|fireblocks_secret\.key)\b[\s\S]{0,200}\b(?:api[_-]?key|x-api-key|secret[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("alpaca-api-secret", "Alpaca API Secret", "critical", []string{"APCA-API-SECRET-KEY", "alpaca", "paper-api.alpaca.markets"}, `(?i)\b(?:alpaca|paper-api\.alpaca\.markets|apca-api-secret-key|apca_api_secret_key)\b[\s\S]{0,160}\b(?:api[_-]?secret[_-]?key|secret[_-]?key|apca-api-secret-key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("sportradar-api-key", "Sportradar API Key", "critical", []string{"sportradar", "api.sportradar.com"}, `(?i)\b(?:sportradar|api\.sportradar\.com)\b[\s\S]{0,160}\b(?:x-api-key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{24,128})\b`, 1, nil),
		NewRegex("apisports-api-key", "API-Sports API Key", "critical", []string{"api-sports", "x-apisports-key", "football.api-sports.io"}, `(?i)\b(?:api-sports|x-apisports-key|[a-z0-9.-]*\.api-sports\.io)\b[\s\S]{0,160}\b(?:x-apisports-key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("databet-secret", "DATA.BET Secret", "critical", []string{"databet", "data.bet", "feed.int.databet.cloud"}, `(?i)\b(?:databet|data\.bet|feed\.int\.databet\.cloud)\b[\s\S]{0,200}\b(?:widget[_-]?secret|secret[_-]?key|jwt[_-]?secret|client[_-]?secret|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("betfair-api-token", "Betfair API Token", "critical", []string{"betfair", "X-Application", "X-Authentication"}, `(?i)\b(?:betfair|api\.betfair\.com|identitysso\.betfair\.com|x-application|x-authentication)\b[\s\S]{0,200}\b(?:x-application|x-authentication|app[_-]?key|session[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("oddsjam-api-key", "OddsJam API Key", "critical", []string{"oddsjam", "api.oddsjam.com"}, `(?i)\b(?:oddsjam|api\.oddsjam\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("opticodds-api-key", "OpticOdds API Key", "critical", []string{"opticodds", "api.opticodds.com"}, `(?i)\b(?:opticodds|optic[ _-]?odds|api\.opticodds\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("geocomply-license-key", "GeoComply License Key", "critical", []string{"geocomply", "geoguard"}, `(?i)\b(?:geocomply|geoguard)\b[\s\S]{0,200}\b(?:license[_-]?key|client[_-]?key|secret|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("alloy-api-key", "Alloy API Key", "critical", []string{"alloy", "developer.alloy.com"}, `(?i)\b(?:alloy|developer\.alloy\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?secret|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("socure-api-key", "Socure API Key", "critical", []string{"socure", "api.socure.com"}, `(?i)\b(?:socure|api\.socure\.com|x-api-key)\b[\s\S]{0,160}\b(?:api[_-]?key|x-api-key|sdk[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("complyadvantage-api-key", "ComplyAdvantage API Key", "critical", []string{"complyadvantage", "comply advantage"}, `(?i)\b(?:complyadvantage|comply[ _-]?advantage|api\.complyadvantage\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("chainalysis-api-key", "Chainalysis API Key", "critical", []string{"chainalysis", "api.chainalysis.com"}, `(?i)\b(?:chainalysis|api\.chainalysis\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("trm-labs-api-key", "TRM Labs API Key", "critical", []string{"trmlabs", "trm labs"}, `(?i)\b(?:trmlabs|trm[ _-]?labs|api\.trmlabs\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("bitgo-access-token", "BitGo Access Token", "critical", []string{"bitgo", "app.bitgo.com"}, `(?i)\b(?:bitgo|app\.bitgo\.com|test\.bitgo\.com)\b[\s\S]{0,160}\b(?:access[_-]?token|api[_-]?token|token|bearer)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("circle-api-key", "Circle API Key", "critical", []string{"api.circle.com", "api-sandbox.circle.com", "CIRCLE_API_KEY"}, `(?i)\b(?:api\.circle\.com|api-sandbox\.circle\.com|circle[_-]?api[_-]?key|circle)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token|webhook[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("drivewealth-client-secret", "DriveWealth Client Secret", "critical", []string{"drivewealth", "bo-api.drivewealth"}, `(?i)\b(?:drivewealth|bo-api\.drivewealth)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("teller-signing-secret", "Teller Signing Secret", "critical", []string{"teller", "api.teller.io"}, `(?i)\b(?:teller|api\.teller\.io)\b[\s\S]{0,200}\b(?:signing[_-]?secret|private[_-]?key|certificate|api[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("truelayer-client-secret", "TrueLayer Client Secret", "critical", []string{"truelayer", "auth.truelayer.com"}, `(?i)\b(?:truelayer|auth\.truelayer\.com|api\.truelayer\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|signing[_-]?key|private[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("yapily-application-secret", "Yapily Application Secret", "critical", []string{"yapily", "api.yapily.com"}, `(?i)\b(?:yapily|api\.yapily\.com)\b[\s\S]{0,200}\b(?:application[_-]?secret|app[_-]?secret|api[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("tink-client-secret", "Tink Client Secret", "critical", []string{"tink", "oauth.tink.com"}, `(?i)\b(?:tink|oauth\.tink\.com|api\.tink\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("seon-api-key", "SEON API Key", "critical", []string{"seon", "api.seon.io"}, `(?i)\b(?:seon|api\.seon\.io|x-api-key)\b[\s\S]{0,160}\b(?:api[_-]?key|license[_-]?key|x-api-key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("jumio-client-secret", "Jumio Client Secret", "critical", []string{"jumio", "api.jumio.com"}, `(?i)\b(?:jumio|api\.jumio\.com|netverify)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("trulioo-api-key", "Trulioo API Key", "critical", []string{"trulioo", "api.globaldatacompany.com"}, `(?i)\b(?:trulioo|api\.trulioo\.com|api\.globaldatacompany\.com|x-trulioo-api-key)\b[\s\S]{0,200}\b(?:api[_-]?key|x-trulioo-api-key|secret|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("sardine-client-secret", "Sardine Client Secret", "critical", []string{"sardine", "api.sardine.ai"}, `(?i)\b(?:sardine|api\.sardine\.ai)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("sift-api-key", "Sift API Key", "critical", []string{"sift", "api.sift.com"}, `(?i)\b(?:sift|api\.sift\.com|account\.siftscience\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|rest[_-]?api[_-]?key|beacon[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("forter-api-key", "Forter API Key", "critical", []string{"forter", "api.forter.com"}, `(?i)\b(?:forter|api\.forter\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|site[_-]?id|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("riskified-api-key", "Riskified API Key", "critical", []string{"riskified", "api.riskified.com"}, `(?i)\b(?:riskified|api\.riskified\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|auth[_-]?token|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("etherscan-api-key", "Etherscan API Key", "high", []string{"etherscan", "apikey"}, `(?i)\betherscan.{0,40}\b([0-9A-Z]{34})\b`, 1, nil),
		NewRegex("bscscan-api-key", "BscScan API Key", "high", []string{"bscscan", "apikey"}, `(?i)\bbscscan.{0,40}\b([0-9A-Z]{34})\b`, 1, nil),
		NewRegex("guardian-api-key", "Guardian API Key", "high", []string{"guardianapi", "guardian", "content.guardianapis.com"}, `(?i)\b(?:guardianapi|guardian|content\.guardianapis\.com).{0,40}\b([0-9A-Za-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`, 1, nil),
		NewRegex("circleci-pat", "CircleCI Personal Access Token", "critical", []string{"CCIPAT_", "circleci"}, `\b(CCIPAT_[A-Za-z0-9]{22}_[A-Fa-f0-9]{40})\b`, 1, nil),
		NewRegex("sourcegraph-token", "Sourcegraph Token", "critical", []string{"sgp_"}, `\b(sgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}|sgp_[A-Fa-f0-9]{40})\b`, 1, nil),
		NewRegex("sourcegraph-cody-token", "Sourcegraph Cody Token", "critical", []string{"slk_"}, `\b(slk_[a-f0-9]{64})\b`, 1, nil),
		NewRegex("snyk-api-key", "Snyk API Key", "critical", []string{"snyk", "SNYK_TOKEN"}, `(?i)\bsnyk.{0,40}['\"\s:=]+([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`, 1, nil),
		NewRegex("uptimerobot-api-key", "UptimeRobot API Key", "high", []string{"uptimerobot", "UPTIMEROBOT_API_KEY"}, `(?i)\buptimerobot.{0,40}['\"\s:=]+([A-Za-z0-9]{9}-[A-Za-z0-9]{24})\b`, 1, nil),
		NewRegex("sumologic-access-id", "Sumo Logic Access ID", "high", []string{"sumo", "accessId", "access_id"}, `(?i)\b(?:sumo(?:logic)?|access[_-]?id).{0,40}['\"\s:=]+(su[A-Za-z0-9]{12})\b`, 1, nil),
		NewRegex("sumologic-access-key", "Sumo Logic Access Key", "high", []string{"sumo", "accessKey", "access_key"}, `(?i)\b(?:sumo(?:logic)?|access[_-]?key).{0,40}['\"\s:=]+([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("statuspage-api-key", "Statuspage API Key", "high", []string{"statuspage"}, `(?i)\bstatuspage.{0,40}['\"\s:=]+([0-9a-z-]{36})\b`, 1, nil),
		NewRegex("sendinblue-api-key", "Sendinblue API Key", "critical", []string{"xkeysib", "sendinblue", "brevo"}, `\b(xkeysib-[A-Za-z0-9_-]{81})\b`, 1, nil),
		NewRegex("teamwork-token", "Teamwork Token", "critical", []string{"teamwork", "teamworkcrm", "teamworkdesk", "tkn.v1_"}, `\b(tkn\.v1_[0-9A-Za-z]{71}=)`, 1, nil),
		NewRegex("salesblink-api-key", "Salesblink API Key", "high", []string{"salesblink", "key-"}, `(?i)\bsalesblink.{0,40}['\"\s:=]+(key-[A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("smooch-app-key", "Smooch App Key", "high", []string{"smooch", "act_"}, `(?i)\bsmooch.{0,40}['\"\s:=]+(act_[0-9a-z]{24})\b`, 1, nil),
		NewRegex("mailmodo-api-key", "Mailmodo API Key", "high", []string{"mailmodo"}, `(?i)\bmailmodo.{0,40}['\"\s:=]+([A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\b`, 1, nil),
		NewRegex("zapier-webhook", "Zapier Webhook URL", "critical", []string{"hooks.zapier.com/hooks/catch/"}, `\b(https://hooks\.zapier\.com/hooks/catch/[A-Za-z0-9/]{16})\b`, 1, nil),
		NewRegex("inngest-signing-key", "Inngest Signing Key", "critical", []string{"inngest", "signkey-"}, `(?i)\b(?:inngest|api\.inngest\.com|signkey-)\b[\s\S]{0,160}\b(?:signing[_-]?key|event[_-]?key|api[_-]?key|token|key)\b\s*[:=]\s*['\"]?((?:signkey-|test-signkey-|prod-signkey-)?[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("triggerdev-api-key", "Trigger.dev API Key", "critical", []string{"trigger.dev", "tr_dev_", "tr_prod_"}, `(?i)\b(?:trigger\.dev|api\.trigger\.dev|triggerdev|tr_dev_|tr_prod_)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|token|key)\b\s*[:=]\s*['\"]?((?:tr_(?:dev|prod)_[A-Za-z0-9._-]{24,256}|[A-Za-z0-9._-]{32,256}))\b`, 1, nil),
		NewRegex("temporal-cloud-api-key", "Temporal Cloud API Key", "critical", []string{"temporal", "temporal.io"}, `(?i)\b(?:temporal|temporal\.io|cloud\.temporal\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|client[_-]?secret|account[_-]?key|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("windmill-api-token", "Windmill API Token", "critical", []string{"windmill", "windmill.dev"}, `(?i)\b(?:windmill|windmill\.dev|app\.windmill\.dev)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("n8n-api-key", "n8n API Key", "critical", []string{"n8n", "n8n.io"}, `(?i)\b(?:n8n|n8n\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("workato-api-token", "Workato API Token", "critical", []string{"workato", "workato.com"}, `(?i)\b(?:workato|workato\.com|apim\.workato\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("trayio-api-token", "Tray.io API Token", "critical", []string{"tray.io", "trayio"}, `(?i)\b(?:tray\.io|trayio|api\.tray\.io)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("airbyte-api-token", "Airbyte API Token", "critical", []string{"airbyte", "api.airbyte.com"}, `(?i)\b(?:airbyte|api\.airbyte\.com|cloud\.airbyte\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|client[_-]?secret|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("fivetran-api-secret", "Fivetran API Secret", "critical", []string{"fivetran", "api.fivetran.com"}, `(?i)\b(?:fivetran|api\.fivetran\.com)\b[\s\S]{0,160}\b(?:api[_-]?secret|api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("hightouch-api-key", "Hightouch API Key", "critical", []string{"hightouch", "api.hightouch.com"}, `(?i)\b(?:hightouch|api\.hightouch\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("deno-deploy-token", "Deno Deploy Token", "critical", []string{"ddp_", "ddw_"}, `\b(dd[pw]_[A-Za-z0-9]{36})\b`, 1, nil),
		NewRegex("supabase-management-token", "Supabase Management Token", "critical", []string{"sbp_"}, `\b(sbp_[a-z0-9]{40})\b`, 1, nil),
		NewRegex("prefect-api-key", "Prefect API Key", "critical", []string{"pnu_"}, `\b(pnu_[A-Za-z0-9]{36})\b`, 1, nil),
		NewRegex("figma-pat", "Figma Personal Access Token", "critical", []string{"figma", "figd_", "figu_", "figo_"}, `\b(fig(?:d|u|o|ur|uh|or|oh)_[A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("saladcloud-api-key", "SaladCloud API Key", "critical", []string{"salad_cloud_"}, `\b(salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235})\b`, 1, nil),
		NewRegex("planetscale-token", "PlanetScale Token", "critical", []string{"pscale_tkn_"}, `\b(pscale_tkn_[A-Za-z0-9_]{43})\b`, 1, nil),
		NewRegex("planetscale-db-password", "PlanetScale Database Password", "critical", []string{"pscale_pw_", "connect.psdb.cloud"}, `\b(pscale_pw_[A-Za-z0-9_]{43})\b`, 1, nil),
		NewRegex("databricks-token", "Databricks Token", "critical", []string{"databricks", "dapi"}, `\b(dapi[0-9a-f]{32}(?:-\d)?)\b`, 1, nil),
		NewRegex("portainer-token", "Portainer Token", "critical", []string{"portainertoken", "ptr_"}, `\b(ptr_[A-Za-z0-9/_\-+=]{20,60})\b`, 1, nil),
		NewRegex("aws-appsync-api-key", "AWS AppSync API Key", "critical", []string{"da2-", "appsync-api"}, `\b(da2-[a-z0-9]{26})\b`, 1, nil),
		NewRegex("azure-openai-key", "Azure OpenAI Key", "critical", []string{".openai.azure.com", "api-key", "openai"}, `(?i)\b(?:api[_.-]?key|openai[_.-]?key)\b.{0,40}\b([a-f0-9]{32})\b`, 1, nil),
		NewRegex("azure-batch-key", "Azure Batch Key", "critical", []string{".batch.azure.com"}, `(?i)https://[a-z0-9-]{1,50}\.[a-z0-9-]{1,50}\.batch\.azure\.com[\s\S]{0,200}\b([A-Za-z0-9+/=]{88})\b`, 1, nil),
		NewRegex("azure-container-registry-password", "Azure Container Registry Password", "critical", []string{".azurecr.io", "+ACR"}, `\b([A-Za-z0-9+/]{42}\+ACR[A-Za-z0-9]{6})\b`, 1, nil),
		NewRegex("gcp-service-account-json", "GCP Service Account JSON", "critical", []string{"auth_provider_x509_cert_url", "private_key", "gserviceaccount.com"}, `(?s)(\{[^{}]*"type"\s*:\s*"service_account"[^{}]*"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[^\"]+"[^{}]*"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"[^{}]*"auth_provider_x509_cert_url"[^{}]*\})`, 1, nil),
		NewRegex("gcp-application-default-credentials", "GCP Application Default Credentials", "critical", []string{".apps.googleusercontent.com", "refresh_token", "client_secret"}, `(?s)(\{[^{}]*"client_id"\s*:\s*"[^"]+\.apps\.googleusercontent\.com"[^{}]*"client_secret"\s*:\s*"[^"]{20,}"[^{}]*"refresh_token"\s*:\s*"[^"]{20,}"[^{}]*\})`, 1, nil),
		NewRegex("redis-uri", "Redis URI", "critical", []string{"redis://", "rediss://"}, `\b(rediss?://[^:\s'"]{1,50}:[^@\s'"]{8,80}@[-.%\w:/]+)\b`, 1, nil),
		NewRegex("azure-redis-connection-string", "Azure Redis Connection String", "critical", []string{".redis.cache.windows.net", "password=", "ssl=True"}, `\b([A-Za-z0-9.-]{1,100}\.redis\.cache\.windows\.net:6380,password=[^,\s]{44},ssl=True,abortConnect=False)\b`, 1, nil),
		NewRegex("couchbase-capella-uri", "Couchbase Capella URI", "critical", []string{"couchbases://", ".cloud.couchbase.com"}, `\b(couchbases://[^:\s'"]{3,80}:[^@\s'"]{8,120}@cb\.[a-z0-9]+\.cloud\.couchbase\.com)\b`, 1, nil),
		NewRegex("closecrm-api-key", "Close CRM API Key", "high", []string{"api_", "close"}, `\b(api_[A-Za-z0-9.]{45})\b`, 1, nil),
		NewRegex("paystack-secret-key", "Paystack Secret Key", "critical", []string{"sk_live_", "sk_test_", "paystack"}, `\b(sk_(?:live|test)_[A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("wrike-access-token", "Wrike Access Token", "critical", []string{"wrike", "ey"}, `(?i)\bwrike.{0,40}\b(ey[A-Za-z0-9._-]{333})\b`, 1, nil),
		NewRegex("twitter-consumer-secret", "Twitter/X Consumer Secret", "high", []string{"twitter", "consumer_secret"}, `(?i)\btwitter.{0,40}\bconsumer[_-]?secret.{0,20}\b([A-Za-z0-9]{50})\b`, 1, nil),
		NewRegex("facebook-oauth-secret", "Facebook OAuth Secret", "high", []string{"facebook", "app_secret"}, `(?i)\bfacebook.{0,40}\bapp[_-]?secret.{0,20}\b([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("flutterwave-secret-key", "Flutterwave Secret Key", "critical", []string{"FLWSECK-"}, `\b(FLWSECK-[0-9a-z]{32}-X)\b`, 1, nil),
		NewRegex("pagarme-live-key", "Pagar.me Live Key", "critical", []string{"ak_live_"}, `\b(ak_live_[A-Za-z0-9]{30})\b`, 1, nil),
		NewRegex("rechargepayments-token", "Recharge Payments Token", "critical", []string{"sk_1x", "sk_2x", "sk_3x", "sk_5x", "sk_10x"}, `\b(sk(?:_test)?_(?:1|2|3|5|10)x[123]_[0-9a-fA-F]{64})\b`, 1, nil),
		NewRegex("lemonsqueezy-api-token", "Lemon Squeezy API Token", "critical", []string{"lemonsqueezy", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"}, `(?i)\blemonsqueezy.{0,40}\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[0-9A-Za-z]{314}\.[0-9A-Za-z_-]{512})\b`, 1, nil),
		NewRegex("plaid-access-token", "Plaid Access Token", "critical", []string{"access-sandbox-", "access-production-"}, `\b(access-(?:sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`, 1, nil),
		NewRegex("plaid-client-secret", "Plaid Client Secret", "critical", []string{"PLAID_SECRET", "plaid", "plaid.com"}, `(?i)\b(?:plaid|plaid\.com|plaid-secret|plaid_secret)\b[\s\S]{0,200}\b(?:plaid[_-]?secret|secret|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{24,256})\b`, 1, nil),
		NewRegex("cloudinary-url", "Cloudinary URL", "critical", []string{"cloudinary://"}, `\b(cloudinary://[0-9]{15}:[A-Za-z0-9_-]{27}@[A-Za-z0-9_-]{3,64})\b`, 1, nil),
		NewRegex("zendesk-api-token", "Zendesk API Token", "high", []string{"zendesk.com", "zendesk"}, `(?i)\b[a-z0-9-]{3,25}\.zendesk\.com\b[\s\S]{0,200}\b(?:zendesk|api[_-]?token|token)[A-Za-z0-9_-]*[\s\S]{0,60}\b([A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("freshdesk-api-key", "Freshdesk API Key", "high", []string{"freshdesk.com", "freshdesk"}, `(?i)\b[a-z0-9-]+\.freshdesk\.com\b[\s\S]{0,200}\b(?:freshdesk|api[_-]?key|token)[A-Za-z0-9_-]*[\s\S]{0,60}\b([0-9A-Za-z]{20})\b`, 1, nil),
		NewRegex("helpcrunch-api-key", "HelpCrunch API Key", "high", []string{"helpcrunch"}, `(?i)\bhelpcrunch[A-Za-z0-9_-]*.{0,80}\b([A-Za-z0-9+/=-]{328})\b`, 1, nil),
		NewRegex("line-messaging-token", "LINE Messaging Token", "critical", []string{"line_messaging", "LINE_MESSAGING"}, `(?i)\bline[_ -]?messaging[A-Za-z0-9_-]*.{0,100}\b([A-Za-z0-9+/]{171,172})\b`, 1, nil),
		NewRegex("courier-api-key", "Courier API Key", "critical", []string{"courier", "pk_"}, `(?i)\bcourier[A-Za-z0-9_-]*.{0,80}\b(pk_[A-Za-z0-9]+_[A-Za-z0-9]{28})\b`, 1, nil),
		NewRegex("moengage-api-secret", "MoEngage API Secret", "critical", []string{"moengage", "api.moengage.com"}, `(?i)\b(?:moengage|api\.moengage\.com)\b[\s\S]{0,180}\b(?:api[_-]?secret|app[_-]?secret|secret|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("clevertap-passcode", "CleverTap Passcode", "critical", []string{"clevertap", "X-CleverTap-Passcode"}, `(?i)\b(?:clevertap|x-clevertap-passcode|api\.clevertap\.com)\b[\s\S]{0,180}\b(?:passcode|account[_-]?passcode|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mparticle-api-secret", "mParticle API Secret", "critical", []string{"mparticle", "mParticle"}, `(?i)\b(?:mparticle|s2s\.mparticle\.com)\b[\s\S]{0,180}\b(?:api[_-]?secret|secret|server[_-]?key|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("hashicorp-vault-approle", "HashiCorp Vault AppRole Secret ID", "high", []string{"vault", "role_id", "secret_id"}, `(?i)\brole[_-]?id\b.{0,80}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b[\s\S]{0,200}\bsecret[_-]?id\b.{0,80}\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("mattermost-personal-token", "Mattermost Personal Token", "high", []string{"mattermost", "cloud.mattermost.com"}, `(?i)\bmattermost\b[\s\S]{0,160}\b([a-z0-9]{26})\b[\s\S]{0,160}\b[A-Za-z0-9-_]+\.cloud\.mattermost\.com\b`, 1, nil),
		NewRegex("cloudflare-global-api-key", "Cloudflare Global API Key", "critical", []string{"cloudflare", "global_api_key"}, `(?i)\bcloudflare.{0,80}global[_ -]?api[_ -]?key.{0,20}['\"\s:=]+([a-f0-9]{37})\b`, 1, nil),
		NewRegex("docker-auth-config", "Docker Auth Config", "critical", []string{"\"auths\"", "\"auth\""}, `(?s)("auths"\s*:\s*\{[^}]+"auth"\s*:\s*"[A-Za-z0-9+/]{20,}={0,2}")`, 1, nil),
		NewRegex("azure-search-key", "Azure Search Key", "critical", []string{".search.windows.net", "api-key"}, `(?i)\b[a-z0-9-]+\.search\.windows\.net\b[\s\S]{0,160}\bapi-key\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{52})\b`, 1, nil),
		NewRegex("azure-apim-subscription-key", "Azure API Management Subscription Key", "critical", []string{"ocp-apim-subscription-key"}, `(?i)\bocp-apim-subscription-key\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("azure-direct-management-key", "Azure Direct Management Key", "critical", []string{"directline.botframework.com", "directline", "botframework"}, `(?i)\b(?:directline\.botframework\.com|directline|botframework)\b[\s\S]{0,240}\b(?:management[_-]?key|direct[_-]?line[_-]?secret|secret|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("bing-subscription-key", "Bing Subscription Key", "critical", []string{"api.bing.microsoft.com", "bing.microsoft.com", "bing_search"}, `(?i)\b(?:api\.bing\.microsoft\.com|bing\.microsoft\.com|bing[_-]?search)\b[\s\S]{0,240}\b(?:ocp-apim-subscription-key|subscription[_-]?key|api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("auth0-domain-jwt", "Auth0 Management API Token", "critical", []string{"auth0.com", "eyJ"}, `(?i)\b[a-z0-9-]+\.auth0\.com\b[\s\S]{0,200}\b(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b`, 1, nil),
		NewRegex("virustotal-api-key", "VirusTotal API Key", "high", []string{"virustotal"}, `(?i)\bvirustotal.{0,40}['\"\s:=]+([a-f0-9]{64})\b`, 1, nil),
		NewRegex("shodan-api-key", "Shodan API Key", "high", []string{"shodan"}, `(?i)\bshodan.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("securitytrails-api-key", "SecurityTrails API Key", "high", []string{"securitytrails"}, `(?i)\bsecuritytrails.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("snowflake-url", "Snowflake URL", "critical", []string{"snowflake://"}, `\b(snowflake://[^:\s'"]+:[^@\s'"]{8,}@[A-Za-z0-9_.-]+(?:/[^\s'"]*)?)`, 1, nil),
		NewRegex("sqlserver-connection-string", "SQL Server Connection String", "critical", []string{"Server=", "Data Source=", "Password=", "PWD="}, `(?i)\b((?:Server|Data Source)=[^;\r\n]+;[^\r\n]*(?:User ID|UID)=[^;\r\n]+;[^\r\n]*(?:Password|PWD)=[^;\r\n]{8,};?)`, 1, nil),
		NewRegex("rabbitmq-uri", "RabbitMQ URI", "critical", []string{"amqp://", "amqps://"}, `\b(amqps?://[^:\s'"]{1,80}:[^@\s'"]{8,120}@[^/\s'"]+(?:/[^\s'"]*)?)`, 1, nil),
		NewRegex("newsapi-key", "NewsAPI Key", "high", []string{"newsapi", "newsapi.org"}, `(?i)\bnewsapi.{0,40}['\"\s:=]+([0-9a-f]{32})\b`, 1, nil),
		NewRegex("openweather-api-key", "OpenWeather API Key", "high", []string{"openweather", "api.openweathermap.org", "APPID"}, `(?i)\b(?:openweather|api\.openweathermap\.org|appid).{0,80}\b([0-9a-f]{32})\b`, 1, nil),
		NewRegex("tomorrowio-api-key", "Tomorrow.io API Key", "high", []string{"tomorrow.io", "tomorrowio"}, `(?i)\b(?:tomorrow\.io|tomorrowio).{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("here-api-key", "HERE API Key", "high", []string{"hereapi", "here.com", "platform.here.com"}, `(?i)\b(?:hereapi|here\.com|platform\.here\.com).{0,80}\b([A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("polygon-api-key", "Polygon.io API Key", "high", []string{"polygon.io", "POLYGON_API_KEY"}, `(?i)\b(?:polygon\.io|polygon_api_key).{0,40}['\"\s:=]+([A-Za-z0-9_-]{32})\b`, 1, nil),
		NewRegex("aws-session-token", "AWS Session Token", "critical", []string{"aws_session_token", "AWS_SESSION_TOKEN"}, `(?i)\baws[_-]?session[_-]?token\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{80,1000})\b`, 1, nil),
		NewRegex("alibaba-access-key", "Alibaba Cloud Access Key", "critical", []string{"LTAI", "alibaba", "aliyun"}, `\b(LTAI[A-Za-z0-9]{20})\b`, 1, nil),
		NewRegex("scaleway-secret-key", "Scaleway Secret Key", "critical", []string{"SCW_SECRET_KEY", "scaleway"}, `(?i)\b(?:scw[_-]?secret[_-]?key|scaleway.{0,20}(?:secret|token|key))\b\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("github-oauth-client-secret", "GitHub OAuth Client Secret", "critical", []string{"GITHUB_CLIENT_SECRET", "github_oauth", "github"}, `(?i)\b(?:github[_-]?oauth|github|github_client_secret)\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("github-app-private-key", "GitHub App Private Key", "critical", []string{"github_app", "GITHUB_APP", "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY"}, `(?is)\bgithub[_ -]?app(?:\b|_)[\s\S]{0,300}(-----BEGIN (?:RSA |)PRIVATE KEY-----.*?-----END (?:RSA |)PRIVATE KEY-----)`, 1, nil),
		NewRegex("gitlab-oauth-client-secret", "GitLab OAuth Client Secret", "critical", []string{"GITLAB_CLIENT_SECRET", "gitlab_oauth", "gitlab"}, `(?i)\b(?:gitlab[_-]?oauth|gitlab|gitlab_client_secret)\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([a-f0-9]{64})\b`, 1, nil),
		NewRegex("datadog-app-key", "Datadog Application Key", "critical", []string{"DD_APP_KEY", "datadog"}, `(?i)\b(?:dd[_-]?app[_-]?key|datadog.{0,20}app(?:lication)?[_-]?key)\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("braintree-access-token", "Braintree Access Token", "critical", []string{"access_token$production$", "access_token$sandbox$"}, `\b(access_token\$(?:production|sandbox)\$[A-Za-z0-9_]+\$[A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("coinbase-cdp-api-key", "Coinbase CDP API Key", "critical", []string{"coinbase", "organizations/", "apiKeys/"}, `\b(organizations/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/apiKeys/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("coinbase-exchange-secret", "Coinbase Exchange/Prime Secret", "critical", []string{"coinbase", "CB-ACCESS-SECRET", "CB-ACCESS-PASSPHRASE"}, `(?i)\b(?:coinbase|prime\.coinbase\.com|api\.exchange\.coinbase\.com|cb-access-secret|cb-access-passphrase)\b[\s\S]{0,200}\b(?:cb-access-secret|cb_access_secret|api[_-]?secret|secret|passphrase)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,256})\b`, 1, nil),
		NewRegex("webex-access-token", "Webex Access Token", "critical", []string{"webex", "WEBEX_ACCESS_TOKEN"}, `(?i)\bwebex\b.{0,60}\b(?:access[_-]?token|bearer[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{64}_[A-Za-z0-9]{4}_[A-Za-z0-9_-]{36})\b`, 1, nil),
		NewRegex("auth0-client-secret", "Auth0 OAuth Client Secret", "critical", []string{"auth0", "AUTH0_CLIENT_SECRET"}, `(?i)\b(?:auth0|auth0_client_secret)\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{48,128})\b`, 1, nil),
		NewRegex("onelogin-client-secret", "OneLogin Client Secret", "critical", []string{"onelogin", "ONELOGIN_CLIENT_SECRET"}, `(?i)\b(?:onelogin|one[ _-]?login)\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("detectify-api-key", "Detectify API Key", "high", []string{"detectify"}, `(?i)\bdetectify\b.{0,40}\b(?:api[_-]?key|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("wiz-client-secret", "Wiz Client Secret", "critical", []string{"wiz", "WIZ_CLIENT_SECRET"}, `(?i)\b(?:wiz|wiz_client_secret)\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("jupiterone-api-token", "JupiterOne API Token", "critical", []string{"jupiterone", "J1_API_TOKEN"}, `(?i)\b(?:jupiterone|j1[_-]?api[_-]?token)\b.{0,40}\b(?:api[_-]?token|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ldap-url", "LDAP Credential URL", "critical", []string{"ldap://", "ldaps://"}, `\b(ldaps?://[^:\s'\"]{1,120}:[^@\s'\"]{8,120}@[^\s'\"]+)`, 1, nil),
		NewRegex("loginradius-api-secret", "LoginRadius API Secret", "critical", []string{"loginradius"}, `(?i)\bloginradius\b[\s\S]{0,120}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("stytch-secret", "Stytch Secret", "critical", []string{"secret-test-", "secret-live-", "stytch"}, `\b(secret-(?:test|live)-[A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("openvpn-static-key", "OpenVPN Static Key", "critical", []string{"BEGIN OpenVPN Static key", "OpenVPN Static key"}, `(?s)(-----BEGIN OpenVPN Static key V1-----\s*[0-9a-f\s]{512,900}-----END OpenVPN Static key V1-----)`, 1, nil),
		NewRegex("azure-entra-client-secret", "Azure Entra Client Secret", "critical", []string{"AZURE_CLIENT_SECRET", "login.microsoftonline.com", "entra"}, `(?i)\b(?:azure[_-]?client[_-]?secret|entra|login\.microsoftonline\.com)\b[\s\S]{0,160}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([A-Za-z0-9_.~/-]{24,128})\b`, 1, nil),
		NewRegex("twitter-bearer-token", "Twitter/X Bearer Token", "critical", []string{"twitter", "TWITTER_BEARER_TOKEN", "AAAA"}, `(?i)\b(?:twitter|x_api|twitter_bearer_token).{0,60}\bbearer[_ -]?token\b\s*[:=]\s*['\"]?(AAAA[A-Za-z0-9%_-]{80,300})\b`, 1, nil),
		NewRegex("twitch-client-secret", "Twitch Client Secret", "critical", []string{"TWITCH_CLIENT_SECRET", "twitch"}, `(?i)\btwitch\b[\s\S]{0,120}\bclient[_-]?secret\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("twitch-access-token", "Twitch Access Token", "critical", []string{"twitch"}, `(?i)\btwitch\b.{0,60}\b(?:access[_-]?token|oauth[_-]?token|token)\b\s*[:=]\s*['\"]?([a-z0-9]{30})\b`, 1, nil),
		NewRegex("ipinfo-token", "IPinfo Token", "high", []string{"ipinfo"}, `(?i)\bipinfo\b.{0,40}\b(?:api[_-]?key|access[_-]?token|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("coinlayer-api-key", "CoinLayer API Key", "high", []string{"coinlayer"}, `(?i)\bcoinlayer\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("coinlib-api-key", "Coinlib API Key", "high", []string{"coinlib"}, `(?i)\bcoinlib\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("cryptocompare-api-key", "CryptoCompare API Key", "high", []string{"cryptocompare"}, `(?i)\bcryptocompare\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("bitcoinaverage-api-key", "BitcoinAverage API Key", "high", []string{"bitcoinaverage"}, `(?i)\bbitcoinaverage\b.{0,40}\b(?:api[_-]?key|public[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("worldcoinindex-api-key", "WorldCoinIndex API Key", "high", []string{"worldcoinindex"}, `(?i)\bworldcoinindex\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("blocknative-api-key", "Blocknative API Key", "high", []string{"blocknative"}, `(?i)\bblocknative\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9-]{32,64})\b`, 1, nil),
		NewRegex("fixerio-api-key", "Fixer.io API Key", "high", []string{"fixer.io", "fixerio"}, `(?i)\b(?:fixer\.io|fixerio)\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("currencylayer-api-key", "Currencylayer API Key", "high", []string{"currencylayer"}, `(?i)\bcurrencylayer\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("exchangerate-api-key", "ExchangeRate-API Key", "high", []string{"exchangerate-api", "exchangerateapi"}, `(?i)\b(?:exchangerate-api|exchangerateapi)\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{24})\b`, 1, nil),
		NewRegex("exchangeratesapi-api-key", "ExchangeRatesAPI Key", "high", []string{"exchangeratesapi"}, `(?i)\bexchangeratesapi\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("currencyfreaks-api-key", "CurrencyFreaks API Key", "high", []string{"currencyfreaks"}, `(?i)\bcurrencyfreaks\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("currencyscoop-api-key", "CurrencyScoop API Key", "high", []string{"currencyscoop"}, `(?i)\bcurrencyscoop\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("fastforex-api-key", "FastForex API Key", "high", []string{"fastforex"}, `(?i)\bfastforex\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("marketstack-api-key", "Marketstack API Key", "high", []string{"marketstack"}, `(?i)\bmarketstack\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("financialmodelingprep-api-key", "Financial Modeling Prep API Key", "high", []string{"financialmodelingprep"}, `(?i)\bfinancialmodelingprep\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("finnhub-api-key", "Finnhub API Key", "high", []string{"finnhub"}, `(?i)\bfinnhub\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{20})\b`, 1, nil),
		NewRegex("tradier-token", "Tradier Token", "high", []string{"tradier"}, `(?i)\btradier\b.{0,40}\b(?:access[_-]?token|bearer|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("twelvedata-api-key", "Twelve Data API Key", "high", []string{"twelvedata", "twelve data"}, `(?i)\b(?:twelvedata|twelve[ _-]?data)\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("vatlayer-api-key", "VATLayer API Key", "high", []string{"vatlayer"}, `(?i)\bvatlayer\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("worldweather-api-key", "World Weather Online API Key", "high", []string{"worldweatheronline", "world weather"}, `(?i)\b(?:worldweatheronline|world[ _-]?weather)\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("positionstack-api-key", "Positionstack API Key", "high", []string{"positionstack"}, `(?i)\bpositionstack\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("geocodio-api-key", "Geocodio API Key", "high", []string{"geocodio"}, `(?i)\bgeocodio\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{39})\b`, 1, nil),
		NewRegex("fastly-personal-token", "Fastly Personal Token", "critical", []string{"fastly"}, `(?i)\bfastly\b.{0,40}\b(?:api[_-]?token|personal[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32})\b`, 1, nil),
		NewRegex("telnyx-api-key", "Telnyx API Key", "critical", []string{"telnyx"}, `(?i)\btelnyx\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?(KEY[A-Za-z0-9_-]{32,80})\b`, 1, nil),
		NewRegex("vagrant-cloud-token", "Vagrant Cloud Token", "high", []string{"vagrant"}, `(?i)\bvagrant(?:cloud)?\b.{0,40}\b(?:token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("zeplin-token", "Zeplin Token", "high", []string{"zeplin"}, `(?i)\bzeplin\b.{0,40}\b(?:token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("vultr-api-key", "Vultr API Key", "critical", []string{"vultr"}, `(?i)\bvultr\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Fa-f0-9]{36})\b`, 1, nil),
		NewRegex("bitly-access-token", "Bitly Access Token", "high", []string{"bitly"}, `(?i)\bbitly\b.{0,40}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("algolia-admin-key", "Algolia Admin API Key", "critical", []string{"algolia"}, `(?i)\balgolia\b.{0,80}\b(?:admin[_-]?api[_-]?key|admin[_-]?key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("typesense-api-key", "Typesense API Key", "critical", []string{"typesense", "typesense.net"}, `(?i)\b(?:typesense|typesense\.net)\b[\s\S]{0,160}\b(?:x-typesense-api-key|api[_-]?key|admin[_-]?key|search[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("meilisearch-master-key", "Meilisearch Master Key", "critical", []string{"meilisearch", "meili"}, `(?i)\b(?:meilisearch|meili|x-meili-api-key)\b[\s\S]{0,160}\b(?:master[_-]?key|api[_-]?key|x-meili-api-key|admin[_-]?key|search[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("elastic-cloud-api-key", "Elastic Cloud API Key", "critical", []string{"elastic", "elastic-cloud", "cloud.elastic.co"}, `(?i)\b(?:elastic[_-]?cloud|cloud\.elastic\.co|elastic\.co)\b[\s\S]{0,180}\b(?:api[_-]?key|authorization|bearer|encoded[_-]?api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,512})\b`, 1, nil),
		NewRegex("elastic-app-search-key", "Elastic App Search Key", "critical", []string{"app-search", "ent-search", "elastic"}, `(?i)\b(?:app-search|ent-search|elastic[ _-]?app[ _-]?search)\b[\s\S]{0,160}\b(?:private[_-]?key|api[_-]?key|search[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("bonsai-elasticsearch-api-key", "Bonsai Elasticsearch API Key", "critical", []string{"bonsai", "bonsai.io"}, `(?i)\b(?:bonsai|bonsai\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("searchspring-api-key", "Searchspring API Key", "critical", []string{"searchspring", "searchspring.net"}, `(?i)\b(?:searchspring|searchspring\.net)\b[\s\S]{0,160}\b(?:api[_-]?key|site[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("constructorio-api-token", "Constructor.io API Token", "critical", []string{"constructor.io", "constructorio"}, `(?i)\b(?:constructor\.io|constructorio|ac\.cnstrc\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|secret[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("coveo-api-key", "Coveo API Key", "critical", []string{"coveo", "platform.cloud.coveo.com"}, `(?i)\b(?:coveo|platform\.cloud\.coveo\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("yext-api-key", "Yext API Key", "critical", []string{"yext", "api.yext.com"}, `(?i)\b(?:yext|api\.yext\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("opensearch-api-key", "OpenSearch API Key", "critical", []string{"opensearch", "opensearchservice"}, `(?i)\b(?:opensearch|opensearchservice|aoss\.amazonaws\.com)\b[\s\S]{0,180}\b(?:api[_-]?key|authorization|bearer|token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=._~/-]{32,512})\b`, 1, nil),
		NewRegex("airbrake-project-key", "Airbrake Project Key", "high", []string{"airbrake"}, `(?i)\bairbrake\b.{0,80}\b(?:project[_-]?key|project[_-]?id)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("airbrake-user-key", "Airbrake User Key", "high", []string{"airbrake"}, `(?i)\bairbrake\b.{0,80}\b(?:user[_-]?key|api[_-]?key)\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("bugsnag-api-key", "Bugsnag API Key", "high", []string{"bugsnag"}, `(?i)\bbugsnag\b.{0,40}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("infura-project-id", "Infura Project ID", "high", []string{"infura"}, `(?i)\binfura\b.{0,80}\b(?:project[_-]?id|api[_-]?key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("messagebird-api-key", "MessageBird API Key", "critical", []string{"messagebird", "live_", "test_"}, `(?i)\bmessagebird\b.{0,40}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?((?:live|test)_[A-Za-z0-9]{25})\b`, 1, nil),
		NewRegex("pinata-jwt", "Pinata JWT", "critical", []string{"pinata", "eyJ"}, `(?i)\bpinata\b[\s\S]{0,120}\b(?:jwt|api[_-]?jwt|token)\b\s*[:=]\s*['\"]?(eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b`, 1, nil),
		NewRegex("pushbullet-token", "Pushbullet Access Token", "high", []string{"pushbullet", "o."}, `(?i)\bpushbullet\b.{0,40}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?(o\.[A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("sendbird-api-token", "Sendbird API Token", "high", []string{"sendbird"}, `(?i)\bsendbird\b.{0,60}\b(?:api[_-]?token|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("stormglass-api-key", "StormGlass API Key", "high", []string{"stormglass"}, `(?i)\bstormglass\b.{0,40}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32})\b`, 1, nil),
		NewRegex("todoist-api-token", "Todoist API Token", "high", []string{"todoist"}, `(?i)\btodoist\b.{0,40}\b(?:api[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("uploadcare-secret-key", "Uploadcare Secret Key", "high", []string{"uploadcare"}, `(?i)\buploadcare\b.{0,80}\b(?:secret[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,64})\b`, 1, nil),
		NewRegex("bunny-api-key", "Bunny.net API Key", "critical", []string{"bunny.net", "bunnycdn"}, `(?i)\b(?:bunny\.net|bunnycdn|api\.bunny\.net|storage\.bunnycdn\.com)\b[\s\S]{0,160}\b(?:access[_-]?key|api[_-]?key|storage[_-]?password|password|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("imgix-api-token", "imgix API Token", "critical", []string{"imgix", "api.imgix.com"}, `(?i)\b(?:imgix|api\.imgix\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|secure[_-]?url[_-]?token|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("akamai-client-secret", "Akamai Client Secret", "critical", []string{"akamai", "client_secret", "edgerc"}, `(?i)\b(?:akamai|\.edgerc|edgegrid)\b[\s\S]{0,200}\b(?:client[_-]?secret|access[_-]?token|client[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("keycdn-api-key", "KeyCDN API Key", "critical", []string{"keycdn", "api.keycdn.com"}, `(?i)\b(?:keycdn|api\.keycdn\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("filestack-api-key", "Filestack API Key", "critical", []string{"filestack", "cdn.filestackcontent.com"}, `(?i)\b(?:filestack|cdn\.filestackcontent\.com|www\.filestackapi\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|app[_-]?secret|policy|signature|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._=-]{32,256})\b`, 1, nil),
		NewRegex("bytescale-api-key", "Bytescale API Key", "critical", []string{"bytescale", "upload.io"}, `(?i)\b(?:bytescale|upload\.io|api\.bytescale\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|secret[_-]?key|account[_-]?id|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("transloadit-auth-key", "Transloadit Auth Key", "critical", []string{"transloadit", "api2.transloadit.com"}, `(?i)\b(?:transloadit|api2\.transloadit\.com)\b[\s\S]{0,160}\b(?:auth[_-]?key|auth[_-]?secret|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("gumlet-api-key", "Gumlet API Key", "critical", []string{"gumlet", "api.gumlet.com"}, `(?i)\b(?:gumlet|api\.gumlet\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("imageengine-api-token", "ImageEngine API Token", "critical", []string{"imageengine", "control-api.imageengine.io"}, `(?i)\b(?:imageengine|control-api\.imageengine\.io)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|delivery[_-]?address[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("tinypng-api-key", "TinyPNG API Key", "critical", []string{"tinypng", "tinify"}, `(?i)\b(?:tinypng|tinify|api\.tinify\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("browserstack-access-key", "BrowserStack Access Key", "critical", []string{"BROWSERSTACK_ACCESS_KEY", "browserstack"}, `(?i)\b(?:browserstack|browserstack_access_key)\b.{0,80}\b(?:access[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{20})\b`, 1, nil),
		NewRegex("cloudsmith-api-key", "Cloudsmith API Key", "critical", []string{"cloudsmith"}, `(?i)\bcloudsmith\b.{0,80}\b(?:api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,128})\b`, 1, nil),
		NewRegex("eventbrite-private-token", "Eventbrite Private Token", "critical", []string{"eventbrite"}, `(?i)\beventbrite\b.{0,80}\b(?:private[_-]?token|oauth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,80})\b`, 1, nil),
		NewRegex("harvest-access-token", "Harvest Access Token", "critical", []string{"harvest"}, `(?i)\bharvest\b.{0,80}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("lokalise-token", "Lokalise Token", "critical", []string{"lokalise"}, `(?i)\blokalise\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("maxmind-license-key", "MaxMind License Key", "high", []string{"MAXMIND_LICENSE_KEY", "maxmind"}, `(?i)\b(?:maxmind|MAXMIND_LICENSE_KEY)\b.{0,80}\b(?:license[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{16})\b`, 1, nil),
		NewRegex("nylas-api-key", "Nylas API Key", "critical", []string{"nylas"}, `(?i)\bnylas\b.{0,80}\b(?:api[_-]?key|client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("pipedream-api-key", "Pipedream API Key", "critical", []string{"pipedream"}, `(?i)\bpipedream\b.{0,80}\b(?:api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("percy-token", "Percy Token", "critical", []string{"PERCY_TOKEN", "percy"}, `(?i)\b(?:percy|percy_token)\b.{0,80}\b(?:token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{20,80})\b`, 1, nil),
		NewRegex("crowdin-token", "Crowdin Token", "critical", []string{"crowdin"}, `(?i)\bcrowdin\b.{0,80}\b(?:personal[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("postageapp-api-key", "PostageApp API Key", "high", []string{"postageapp", "postage"}, `(?i)\bpostage(?:app)?\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("sendbird-organization-api-token", "Sendbird Organization API Token", "critical", []string{"sendbird"}, `(?i)\bsendbird\b.{0,100}\b(?:organization[_-]?api[_-]?token|org[_-]?api[_-]?token|organization[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,128})\b`, 1, nil),
		NewRegex("checkly-api-key", "Checkly API Key", "critical", []string{"checkly"}, `(?i)\bcheckly\b.{0,80}\b(?:api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("incidentio-api-key", "incident.io API Key", "critical", []string{"incident.io", "api.incident.io"}, `(?i)\b(?:incident\.io|api\.incident\.io|incidentio)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("firehydrant-api-key", "FireHydrant API Key", "critical", []string{"firehydrant", "api.firehydrant.io"}, `(?i)\b(?:firehydrant|api\.firehydrant\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token|service[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("squadcast-api-token", "Squadcast API Token", "critical", []string{"squadcast", "api.squadcast.com"}, `(?i)\b(?:squadcast|api\.squadcast\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token|refresh[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("ilert-api-key", "ilert API Key", "critical", []string{"ilert", "api.ilert.com"}, `(?i)\b(?:ilert|i-lert|api\.ilert\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("xmatters-api-token", "xMatters API Token", "critical", []string{"xmatters", "xmatters.com"}, `(?i)\b(?:xmatters|xmatters\.com|api\.xmatters\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token|password|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("semgrep-app-token", "Semgrep App Token", "critical", []string{"semgrep", "semgrep.dev"}, `(?i)\b(?:semgrep|semgrep\.dev|semgrep_app_token)\b[\s\S]{0,160}\b(?:app[_-]?token|api[_-]?token|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("socketdev-api-key", "Socket.dev API Key", "critical", []string{"socket.dev", "api.socket.dev"}, `(?i)\b(?:socket\.dev|api\.socket\.dev|socketdev)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("aikido-api-token", "Aikido API Token", "critical", []string{"aikido", "aikido.dev"}, `(?i)\b(?:aikido|aikido\.dev|app\.aikido\.dev)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("infisical-service-token", "Infisical Service Token", "critical", []string{"infisical", "st."}, `(?i)\b(?:infisical|app\.infisical\.com|st\.)\b[\s\S]{0,160}\b(?:service[_-]?token|client[_-]?secret|access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?((?:st\.)?[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("cronitor-api-key", "Cronitor API Key", "critical", []string{"cronitor", "cronitor.io"}, `(?i)\b(?:cronitor|cronitor\.io|cronitor_api_key)\b[\s\S]{0,160}\b(?:api[_-]?key|telemetry[_-]?key|ping[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("confluent-api-secret", "Confluent API Secret", "critical", []string{"confluent"}, `(?i)\bconfluent\b[\s\S]{0,160}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+_=.-]{40,128})\b`, 1, nil),
		NewRegex("docusign-client-secret", "DocuSign Client Secret", "critical", []string{"docusign"}, `(?i)\bdocusign\b[\s\S]{0,120}\b(?:client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gocardless-access-token", "GoCardless Access Token", "critical", []string{"gocardless", "live_", "sandbox_"}, `(?i)\bgocardless\b.{0,80}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?((?:live|sandbox)_[A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gumroad-access-token", "Gumroad Access Token", "high", []string{"gumroad"}, `(?i)\bgumroad\b.{0,80}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("hellosign-api-key", "HelloSign API Key", "high", []string{"hellosign", "dropboxsign"}, `(?i)\b(?:hellosign|dropbox[ _-]?sign)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("mailboxlayer-api-key", "Mailboxlayer API Key", "high", []string{"mailboxlayer"}, `(?i)\bmailboxlayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("mediastack-api-key", "Mediastack API Key", "high", []string{"mediastack"}, `(?i)\bmediastack\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("opencage-api-key", "OpenCage API Key", "high", []string{"opencage"}, `(?i)\bopencage\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("packagecloud-token", "Packagecloud Token", "critical", []string{"packagecloud"}, `(?i)\bpackagecloud\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{48})\b`, 1, nil),
		NewRegex("phrase-access-token", "Phrase Access Token", "critical", []string{"phrase"}, `(?i)\bphrase\b.{0,80}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("semaphore-api-token", "Semaphore API Token", "critical", []string{"semaphore"}, `(?i)\bsemaphore\b.{0,80}\b(?:api[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("scrutinizer-token", "Scrutinizer CI Token", "high", []string{"scrutinizer"}, `(?i)\bscrutinizer\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("saucelabs-access-key", "Sauce Labs Access Key", "critical", []string{"SAUCE_ACCESS_KEY", "saucelabs", "sauce labs"}, `(?i)\b(?:saucelabs|sauce[ _-]?labs|sauce_access_key)\b.{0,80}\b(?:access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9-]{32,36})\b`, 1, nil),
		NewRegex("lessannoyingcrm-api-key", "Less Annoying CRM API Key", "high", []string{"lessannoyingcrm", "less annoying crm"}, `(?i)\b(?:lessannoyingcrm|less[ _-]?annoying[ _-]?crm)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("meaningcloud-api-key", "MeaningCloud API Key", "high", []string{"meaningcloud"}, `(?i)\bmeaningcloud\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("openuv-api-key", "OpenUV API Key", "high", []string{"openuv"}, `(?i)\bopenuv\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("pandascore-api-key", "PandaScore API Key", "high", []string{"pandascore"}, `(?i)\bpandascore\b.{0,80}\b(?:api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("paperform-api-key", "Paperform API Key", "high", []string{"paperform"}, `(?i)\bpaperform\b.{0,80}\b(?:api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("parsehub-api-key", "ParseHub API Key", "high", []string{"parsehub"}, `(?i)\bparsehub\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("pdfshift-api-key", "PDFShift API Key", "high", []string{"pdfshift"}, `(?i)\bpdfshift\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("peopledatalabs-api-key", "People Data Labs API Key", "high", []string{"peopledatalabs", "people data labs"}, `(?i)\b(?:peopledatalabs|people[ _-]?data[ _-]?labs)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("plivo-auth-token", "Plivo Auth Token", "critical", []string{"plivo"}, `(?i)\bplivo\b.{0,80}\b(?:auth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,64})\b`, 1, nil),
		NewRegex("rapidapi-key", "RapidAPI Key", "critical", []string{"rapidapi"}, `(?i)\brapidapi\b.{0,80}\b(?:api[_-]?key|x-rapidapi-key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,64})\b`, 1, nil),
		NewRegex("scraperapi-key", "ScraperAPI Key", "high", []string{"scraperapi"}, `(?i)\bscraperapi\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("scrapestack-api-key", "Scrapestack API Key", "high", []string{"scrapestack"}, `(?i)\bscrapestack\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("scrapingbee-api-key", "ScrapingBee API Key", "high", []string{"scrapingbee"}, `(?i)\bscrapingbee\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{80})\b`, 1, nil),
		NewRegex("serpstack-api-key", "Serpstack API Key", "high", []string{"serpstack"}, `(?i)\bserpstack\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("shotstack-api-key", "Shotstack API Key", "high", []string{"shotstack"}, `(?i)\bshotstack\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("signalwire-api-token", "SignalWire API Token", "critical", []string{"signalwire"}, `(?i)\bsignalwire\b.{0,80}\b(?:api[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,128})\b`, 1, nil),
		NewRegex("testingbot-secret", "TestingBot Secret", "critical", []string{"testingbot"}, `(?i)\btestingbot\b.{0,80}\b(?:secret|api[_-]?secret|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("abstract-api-key", "Abstract API Key", "high", []string{"abstractapi", "abstract"}, `(?i)\b(?:abstractapi|abstract)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("alchemy-api-key", "Alchemy API Key", "critical", []string{"alchemy"}, `(?i)\balchemy\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32})\b`, 1, nil),
		NewRegex("apify-token", "Apify Token", "critical", []string{"apify"}, `(?i)\bapify\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?(apify_api_[A-Za-z0-9_-]{32,80})\b`, 1, nil),
		NewRegex("apilayer-key", "APILayer Key", "high", []string{"apilayer"}, `(?i)\bapilayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("bannerbear-api-key", "Bannerbear API Key", "high", []string{"bannerbear"}, `(?i)\bbannerbear\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("baremetrics-api-key", "Baremetrics API Key", "high", []string{"baremetrics"}, `(?i)\bbaremetrics\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("beamer-api-key", "Beamer API Key", "high", []string{"beamer"}, `(?i)\bbeamer\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("bitbar-api-key", "Bitbar API Key", "high", []string{"bitbar"}, `(?i)\bbitbar\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("blazemeter-api-key", "BlazeMeter API Key", "critical", []string{"blazemeter"}, `(?i)\bblazemeter\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("buttercms-api-token", "ButterCMS API Token", "high", []string{"buttercms"}, `(?i)\bbuttercms\b.{0,80}\b(?:api[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("canny-api-key", "Canny API Key", "high", []string{"canny"}, `(?i)\bcanny\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("chartmogul-api-key", "ChartMogul API Key", "critical", []string{"chartmogul"}, `(?i)\bchartmogul\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("clearbit-api-key", "Clearbit API Key", "critical", []string{"clearbit"}, `(?i)\bclearbit\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,64})\b`, 1, nil),
		NewRegex("clockify-api-key", "Clockify API Key", "high", []string{"clockify"}, `(?i)\bclockify\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{48})\b`, 1, nil),
		NewRegex("cloudconvert-api-key", "CloudConvert API Key", "critical", []string{"cloudconvert"}, `(?i)\bcloudconvert\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,128})\b`, 1, nil),
		NewRegex("cloudmersive-api-key", "Cloudmersive API Key", "high", []string{"cloudmersive"}, `(?i)\bcloudmersive\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9-]{36})\b`, 1, nil),
		NewRegex("convertapi-secret", "ConvertAPI Secret", "high", []string{"convertapi"}, `(?i)\bconvertapi\b.{0,80}\b(?:secret|api[_-]?secret|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("convertkit-api-secret", "ConvertKit API Secret", "critical", []string{"convertkit"}, `(?i)\bconvertkit\b.{0,80}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("dailyco-api-key", "Daily.co API Key", "critical", []string{"daily.co", "dailyco"}, `(?i)\b(?:daily\.co|dailyco)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("deepai-api-key", "DeepAI API Key", "high", []string{"deepai"}, `(?i)\bdeepai\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9-]{32,64})\b`, 1, nil),
		NewRegex("delighted-api-key", "Delighted API Key", "high", []string{"delighted"}, `(?i)\bdelighted\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("deputy-api-token", "Deputy API Token", "critical", []string{"deputy"}, `(?i)\bdeputy\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,128})\b`, 1, nil),
		NewRegex("fullstory-api-key", "FullStory API Key", "critical", []string{"fullstory"}, `(?i)\bfullstory\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("flagsmith-server-key", "Flagsmith Server Key", "critical", []string{"flagsmith", "flagsmith.com"}, `(?i)\b(?:flagsmith|api\.flagsmith\.com)\b[\s\S]{0,160}\b(?:server[_-]?key|environment[_-]?key|api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("growthbook-api-key", "GrowthBook API Key", "critical", []string{"growthbook", "growthbook.io"}, `(?i)\b(?:growthbook|growthbook\.io|api\.growthbook\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|secret[_-]?key|client[_-]?key|sdk[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("unleash-api-token", "Unleash API Token", "critical", []string{"unleash", "unleash-hosted.com"}, `(?i)\b(?:unleash|unleash-hosted\.com|app\.unleash-hosted\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|client[_-]?token|admin[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._:-]{32,256})\b`, 1, nil),
		NewRegex("splitio-api-key", "Split.io API Key", "critical", []string{"split.io", "splitio"}, `(?i)\b(?:split\.io|splitio|sdk\.split\.io|events\.split\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|sdk[_-]?key|admin[_-]?api[_-]?key|authorization[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("statsig-server-secret", "Statsig Server Secret", "critical", []string{"statsig", "secret-"}, `(?i)\b(?:statsig|api\.statsig\.com|secret-)\b[\s\S]{0,160}\b(?:server[_-]?secret|secret[_-]?key|sdk[_-]?secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?((?:secret-|server-)?[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("configcat-sdk-key", "ConfigCat SDK Key", "critical", []string{"configcat", "configcat.com"}, `(?i)\b(?:configcat|cdn-global\.configcat\.com|api\.configcat\.com)\b[\s\S]{0,160}\b(?:sdk[_-]?key|api[_-]?key|configcat[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._/-]{32,256})\b`, 1, nil),
		NewRegex("vwo-api-token", "VWO API Token", "critical", []string{"vwo", "vwo.com", "visualwebsiteoptimizer.com"}, `(?i)\b(?:vwo|vwo\.com|dev\.visualwebsiteoptimizer\.com|visualwebsiteoptimizer\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|account[_-]?token|sdk[_-]?key|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("abtasty-api-key", "AB Tasty API Key", "critical", []string{"abtasty", "ABTasty"}, `(?i)\b(?:abtasty|ab[ _-]?tasty|api\.abtasty\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("hotjar-api-token", "Hotjar API Token", "critical", []string{"hotjar", "hotjar.com"}, `(?i)\b(?:hotjar|api\.hotjar\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("logrocket-api-key", "LogRocket API Key", "critical", []string{"logrocket", "logrocket.com"}, `(?i)\b(?:logrocket|api\.logrocket\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|app[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("pendo-integration-key", "Pendo Integration Key", "critical", []string{"pendo", "pendo.io"}, `(?i)\b(?:pendo|app\.pendo\.io|api\.pendo\.io)\b[\s\S]{0,160}\b(?:integration[_-]?key|api[_-]?key|metadata[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("heap-api-key", "Heap API Key", "critical", []string{"heap", "heapanalytics.com"}, `(?i)\b(?:heap|heapanalytics\.com|api\.heap\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|app[_-]?id|env[_-]?id|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("contentsquare-api-key", "Contentsquare API Key", "critical", []string{"contentsquare", "content-square"}, `(?i)\b(?:contentsquare|content[ _-]?square|api\.contentsquare\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("gorgias-api-key", "Gorgias API Key", "critical", []string{"gorgias", "api.gorgias.com"}, `(?i)\b(?:gorgias|api\.gorgias\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("kustomer-api-token", "Kustomer API Token", "critical", []string{"kustomer", "api.kustomerapp.com"}, `(?i)\b(?:kustomer|api\.kustomerapp\.com|kustomerapp\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("crisp-api-token", "Crisp API Token", "critical", []string{"crisp.chat", "api.crisp.chat"}, `(?i)\b(?:crisp\.chat|api\.crisp\.chat|crisp[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|identifier|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("userpilot-api-key", "Userpilot API Key", "critical", []string{"userpilot", "api.userpilot.io"}, `(?i)\b(?:userpilot|api\.userpilot\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|server[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("chameleon-api-key", "Chameleon API Key", "critical", []string{"chameleon", "api.chameleon.io"}, `(?i)\b(?:chameleon|api\.chameleon\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|secret[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("productboard-api-token", "Productboard API Token", "critical", []string{"productboard", "api.productboard.com"}, `(?i)\b(?:productboard|api\.productboard\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("uservoice-api-token", "UserVoice API Token", "critical", []string{"uservoice", "api.uservoice.com"}, `(?i)\b(?:uservoice|api\.uservoice\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("productfruits-api-key", "Product Fruits API Key", "critical", []string{"productfruits", "product fruits"}, `(?i)\b(?:productfruits|product[ _-]?fruits|api\.productfruits\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("vitally-api-key", "Vitally API Key", "critical", []string{"vitally", "api.vitally.io"}, `(?i)\b(?:vitally|api\.vitally\.io)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("planhat-api-token", "Planhat API Token", "critical", []string{"planhat", "api.planhat.com"}, `(?i)\b(?:planhat|api\.planhat\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("geoapify-api-key", "Geoapify API Key", "high", []string{"geoapify"}, `(?i)\bgeoapify\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("graphhopper-api-key", "GraphHopper API Key", "high", []string{"graphhopper"}, `(?i)\bgraphhopper\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,64})\b`, 1, nil),
		NewRegex("hunter-api-key", "Hunter API Key", "high", []string{"hunter"}, `(?i)\bhunter\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("imagekit-private-key", "ImageKit Private Key", "critical", []string{"imagekit", "private_"}, `(?i)\bimagekit\b.{0,80}\b(?:private[_-]?key|api[_-]?private[_-]?key)\b\s*[:=]\s*['\"]?(private_[A-Za-z0-9]{24,80})\b`, 1, nil),
		NewRegex("kickbox-api-key", "Kickbox API Key", "high", []string{"kickbox"}, `(?i)\bkickbox\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("klipfolio-api-key", "Klipfolio API Key", "high", []string{"klipfolio"}, `(?i)\bklipfolio\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("lob-api-key", "Lob API Key", "critical", []string{"lob", "live_", "test_"}, `(?i)\blob\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?((?:live|test)_[A-Za-z0-9]{35})\b`, 1, nil),
		NewRegex("moosend-api-key", "Moosend API Key", "high", []string{"moosend"}, `(?i)\bmoosend\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9-]{36})\b`, 1, nil),
		NewRegex("neutrinoapi-api-key", "NeutrinoAPI API Key", "high", []string{"neutrinoapi", "neutrino api"}, `(?i)\b(?:neutrinoapi|neutrino[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("numverify-api-key", "Numverify API Key", "high", []string{"numverify"}, `(?i)\bnumverify\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("omnisend-api-key", "Omnisend API Key", "critical", []string{"omnisend"}, `(?i)\bomnisend\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("owlbot-api-key", "OwlBot API Key", "high", []string{"owlbot"}, `(?i)\bowlbot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("pandadoc-api-key", "PandaDoc API Key", "critical", []string{"pandadoc"}, `(?i)\bpandadoc\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("partnerstack-api-key", "PartnerStack API Key", "critical", []string{"partnerstack"}, `(?i)\bpartnerstack\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("pastebin-api-key", "Pastebin API Key", "high", []string{"pastebin"}, `(?i)\bpastebin\b.{0,80}\b(?:api[_-]?dev[_-]?key|api[_-]?key|dev[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("paymongo-secret-key", "PayMongo Secret Key", "critical", []string{"paymongo"}, `(?i)\bpaymongo\b.{0,80}\b(?:secret[_-]?key|key)\b\s*[:=]\s*['\"]?(sk_(?:live|test)_[A-Za-z0-9]{32,128})\b`, 1, nil),
		NewRegex("photoroom-api-key", "PhotoRoom API Key", "high", []string{"photoroom"}, `(?i)\bphotoroom\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("proxycrawl-api-token", "ProxyCrawl API Token", "high", []string{"proxycrawl"}, `(?i)\bproxycrawl\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("qase-api-token", "Qase API Token", "critical", []string{"qase"}, `(?i)\bqase\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("rebrandly-api-key", "Rebrandly API Key", "high", []string{"rebrandly"}, `(?i)\brebrandly\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32})\b`, 1, nil),
		NewRegex("repairshopr-api-key", "RepairShopr API Key", "high", []string{"repairshopr"}, `(?i)\brepairshopr\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("replyio-api-key", "Reply.io API Key", "high", []string{"reply.io", "replyio"}, `(?i)\b(?:reply\.io|replyio)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("restpack-htmltopdf-api-key", "Restpack HTML to PDF API Key", "high", []string{"restpack", "htmltopdf"}, `(?i)\brestpack\b.{0,120}\bhtml[_-]?to[_-]?pdf\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{48})\b`, 1, nil),
		NewRegex("restpack-screenshot-api-key", "Restpack Screenshot API Key", "high", []string{"restpack", "screenshot"}, `(?i)\brestpack\b.{0,120}\bscreenshot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{48})\b`, 1, nil),
		NewRegex("rocketreach-api-key", "RocketReach API Key", "critical", []string{"rocketreach"}, `(?i)\brocketreach\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("route4me-api-key", "Route4Me API Key", "high", []string{"route4me"}, `(?i)\broute4me\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("salesflare-api-key", "Salesflare API Key", "critical", []string{"salesflare"}, `(?i)\bsalesflare\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("attio-api-key", "Attio API Key", "critical", []string{"attio", "api.attio.com"}, `(?i)\b(?:attio|api\.attio\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("affinity-api-key", "Affinity API Key", "critical", []string{"affinity.co", "api.affinity.co"}, `(?i)\b(?:affinity\.co|api\.affinity\.co|affinity[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("height-api-key", "Height API Key", "high", []string{"height.app", "api.height.app"}, `(?i)\b(?:height\.app|api\.height\.app|height[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("gong-api-token", "Gong API Token", "critical", []string{"gong.io", "api.gong.io"}, `(?i)\b(?:gong\.io|api\.gong\.io|gong[_-]?api)\b[\s\S]{0,180}\b(?:access[_-]?key|access[_-]?key[_-]?secret|api[_-]?token|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("chorus-api-key", "Chorus API Key", "critical", []string{"chorus.ai", "api.chorus.ai"}, `(?i)\b(?:chorus\.ai|api\.chorus\.ai|chorus[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("outreach-api-token", "Outreach API Token", "critical", []string{"outreach.io", "api.outreach.io"}, `(?i)\b(?:outreach\.io|api\.outreach\.io|outreach[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("salesloft-api-key", "Salesloft API Key", "critical", []string{"salesloft", "api.salesloft.com"}, `(?i)\b(?:salesloft|api\.salesloft\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|oauth[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("clay-api-key", "Clay API Key", "critical", []string{"clay.com", "api.clay.com"}, `(?i)\b(?:clay\.com|api\.clay\.com|clay[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("instantly-api-key", "Instantly API Key", "critical", []string{"instantly.ai", "api.instantly.ai"}, `(?i)\b(?:instantly\.ai|api\.instantly\.ai|instantly[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("smartlead-api-key", "Smartlead API Key", "critical", []string{"smartlead.ai", "api.smartlead.ai"}, `(?i)\b(?:smartlead\.ai|api\.smartlead\.ai|server\.smartlead\.ai|smartlead[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("salesforce-pardot-client-secret", "Salesforce Pardot Client Secret", "critical", []string{"pardot", "pi.pardot.com"}, `(?i)\b(?:pardot|pi\.pardot\.com|salesforce[_-]?pardot)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|secret|refresh[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("greenhouse-harvest-api-key", "Greenhouse Harvest API Key", "critical", []string{"greenhouse.io", "harvest.greenhouse.io"}, `(?i)\b(?:greenhouse\.io|harvest\.greenhouse\.io|greenhouse[_-]?harvest)\b[\s\S]{0,160}\b(?:harvest[_-]?api[_-]?key|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("lever-api-key", "Lever API Key", "critical", []string{"lever.co", "api.lever.co"}, `(?i)\b(?:lever\.co|api\.lever\.co|lever[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("ashby-api-key", "Ashby API Key", "critical", []string{"ashbyhq.com", "api.ashbyhq.com"}, `(?i)\b(?:ashbyhq\.com|api\.ashbyhq\.com|ashby[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("workable-api-token", "Workable API Token", "critical", []string{"workable.com", "workable"}, `(?i)\b(?:workable\.com|api\.workable\.com|workable)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("smartrecruiters-api-key", "SmartRecruiters API Key", "critical", []string{"smartrecruiters.com", "api.smartrecruiters.com"}, `(?i)\b(?:smartrecruiters\.com|api\.smartrecruiters\.com|smartrecruiters)\b[\s\S]{0,160}\b(?:api[_-]?key|x-smarttoken|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("personio-api-secret", "Personio API Secret", "critical", []string{"personio.com", "api.personio.de"}, `(?i)\b(?:personio\.com|api\.personio\.de|personio)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|api[_-]?key|access[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("hibob-service-token", "HiBob Service Token", "critical", []string{"hibob", "api.hibob.com"}, `(?i)\b(?:hibob|bob\.com|api\.hibob\.com)\b[\s\S]{0,160}\b(?:service[_-]?token|api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("bamboohr-api-key", "BambooHR API Key", "critical", []string{"bamboohr.com", "api.bamboohr.com"}, `(?i)\b(?:bamboohr\.com|api\.bamboohr\.com|bamboohr)\b[\s\S]{0,160}\b(?:api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("rippling-api-token", "Rippling API Token", "critical", []string{"rippling.com", "api.rippling.com"}, `(?i)\b(?:rippling\.com|api\.rippling\.com|rippling)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("deel-api-token", "Deel API Token", "critical", []string{"deel.com", "api.deel.com"}, `(?i)\b(?:deel\.com|api\.deel\.com|deel[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("gusto-api-token", "Gusto API Token", "critical", []string{"gusto.com", "api.gusto.com"}, `(?i)\b(?:gusto\.com|api\.gusto\.com|gusto[_-]?api)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|bearer|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("workday-client-secret", "Workday Client Secret", "critical", []string{"workday.com", "workday"}, `(?i)\b(?:workday\.com|workday|wd[0-9]-impl-services[0-9]\.workday\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|refresh[_-]?token|access[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("adzuna-api-key", "Adzuna API Key", "high", []string{"adzuna"}, `(?i)\badzuna\b.{0,80}\b(?:api[_-]?key|key|app[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("airvisual-api-key", "AirVisual API Key", "high", []string{"airvisual", "iqair"}, `(?i)\b(?:airvisual|iqair)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("amadeus-api-secret", "Amadeus API Secret", "critical", []string{"amadeus"}, `(?i)\bamadeus\b.{0,120}\b(?:api[_-]?secret|client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ambee-api-key", "Ambee API Key", "high", []string{"ambee"}, `(?i)\bambee\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("amplitude-api-key", "Amplitude API Key", "high", []string{"amplitude"}, `(?i)\bamplitude\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("apiflash-access-key", "APIFLASH Access Key", "high", []string{"apiflash"}, `(?i)\bapiflash\b.{0,80}\b(?:access[_-]?key|api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("apitemplate-api-key", "APITemplate API Key", "high", []string{"apitemplate"}, `(?i)\bapitemplate\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("appcues-api-key", "Appcues API Key", "critical", []string{"appcues"}, `(?i)\bappcues\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("appfollow-api-key", "AppFollow API Key", "high", []string{"appfollow"}, `(?i)\bappfollow\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("autoklose-api-key", "Autoklose API Key", "critical", []string{"autoklose"}, `(?i)\bautoklose\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("aviationstack-api-key", "Aviationstack API Key", "high", []string{"aviationstack"}, `(?i)\baviationstack\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("ayrshare-api-key", "Ayrshare API Key", "critical", []string{"ayrshare"}, `(?i)\bayrshare\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("besttime-api-key", "BestTime API Key", "high", []string{"besttime"}, `(?i)\bbesttime\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("brandfetch-api-key", "Brandfetch API Key", "high", []string{"brandfetch"}, `(?i)\bbrandfetch\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("browshot-api-key", "Browshot API Key", "high", []string{"browshot"}, `(?i)\bbrowshot\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("calendarific-api-key", "Calendarific API Key", "high", []string{"calendarific"}, `(?i)\bcalendarific\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("carboninterface-api-key", "Carbon Interface API Key", "high", []string{"carboninterface", "carbon interface"}, `(?i)\b(?:carboninterface|carbon[ _-]?interface)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("craftmypdf-api-key", "CraftMyPDF API Key", "high", []string{"craftmypdf"}, `(?i)\bcraftmypdf\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("currentsapi-api-key", "CurrentsAPI Key", "high", []string{"currentsapi"}, `(?i)\bcurrentsapi\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("debounce-api-key", "DeBounce API Key", "high", []string{"debounce"}, `(?i)\bdebounce\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("detectlanguage-api-key", "Detect Language API Key", "high", []string{"detectlanguage", "detect language"}, `(?i)\b(?:detectlanguage|detect[ _-]?language)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("clarifai-api-key", "Clarifai API Key", "critical", []string{"clarifai"}, `(?i)\bclarifai\b.{0,80}\b(?:api[_-]?key|pat|personal[_-]?access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clicksend-api-key", "ClickSend API Key", "critical", []string{"clicksend"}, `(?i)\bclicksend\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("codemagic-api-token", "Codemagic API Token", "critical", []string{"codemagic"}, `(?i)\bcodemagic\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("databox-api-token", "Databox API Token", "high", []string{"databox"}, `(?i)\bdatabox\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("diffbot-api-token", "Diffbot API Token", "high", []string{"diffbot"}, `(?i)\bdiffbot\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("edamam-api-key", "Edamam API Key", "high", []string{"edamam"}, `(?i)\bedamam\b.{0,80}\b(?:api[_-]?key|app[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("ethplorer-api-key", "Ethplorer API Key", "high", []string{"ethplorer"}, `(?i)\bethplorer\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("faceplusplus-api-key", "Face++ API Key", "critical", []string{"faceplusplus", "face++"}, `(?i)\b(?:faceplusplus|face\+\+)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("geckoboard-api-key", "Geckoboard API Key", "high", []string{"geckoboard"}, `(?i)\bgeckoboard\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("hasura-admin-secret", "Hasura Admin Secret", "critical", []string{"hasura", "HASURA_GRAPHQL_ADMIN_SECRET"}, `(?i)\b(?:hasura|hasura_graphql_admin_secret)\b.{0,80}\b(?:admin[_-]?secret|graphql[_-]?admin[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_.~/-]{32,128})\b`, 1, nil),
		NewRegex("holidayapi-key", "Holiday API Key", "high", []string{"holidayapi", "holiday api"}, `(?i)\b(?:holidayapi|holiday[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("html2pdf-api-key", "HTML2PDF API Key", "high", []string{"html2pdf"}, `(?i)\bhtml2pdf\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("ip2location-api-key", "IP2Location API Key", "high", []string{"ip2location"}, `(?i)\bip2location\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("ipapi-api-key", "ipapi API Key", "high", []string{"ipapi"}, `(?i)\bipapi\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("ipinfodb-api-key", "IPInfoDB API Key", "high", []string{"ipinfodb"}, `(?i)\bipinfodb\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("jotform-api-key", "Jotform API Key", "high", []string{"jotform"}, `(?i)\bjotform\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("keenio-api-key", "Keen.io API Key", "critical", []string{"keen.io", "keenio"}, `(?i)\b(?:keen\.io|keenio)\b.{0,80}\b(?:api[_-]?key|master[_-]?key|write[_-]?key|read[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("languagelayer-api-key", "Languagelayer API Key", "high", []string{"languagelayer"}, `(?i)\blanguagelayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("linenotify-token", "LINE Notify Token", "critical", []string{"linenotify", "line notify"}, `(?i)\b(?:linenotify|line[ _-]?notify)\b.{0,80}\b(?:access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("linkpreview-api-key", "LinkPreview API Key", "high", []string{"linkpreview"}, `(?i)\blinkpreview\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("loggly-token", "Loggly Token", "high", []string{"loggly"}, `(?i)\bloggly\b.{0,80}\b(?:customer[_-]?token|source[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9-]{32,64})\b`, 1, nil),
		NewRegex("mixpanel-api-secret", "Mixpanel API Secret", "critical", []string{"mixpanel"}, `(?i)\bmixpanel\b.{0,120}\b(?:api[_-]?secret|secret|service[_-]?account[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mockaroo-api-key", "Mockaroo API Key", "high", []string{"mockaroo"}, `(?i)\bmockaroo\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("mux-token-secret", "Mux Token Secret", "critical", []string{"mux"}, `(?i)\bmux\b.{0,120}\b(?:token[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,128})\b`, 1, nil),
		NewRegex("nutritionix-api-key", "Nutritionix API Key", "high", []string{"nutritionix"}, `(?i)\bnutritionix\b.{0,80}\b(?:api[_-]?key|app[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("oanda-api-token", "OANDA API Token", "critical", []string{"oanda"}, `(?i)\boanda\b.{0,80}\b(?:api[_-]?token|personal[_-]?access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("onfleet-api-key", "Onfleet API Key", "critical", []string{"onfleet"}, `(?i)\bonfleet\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("pdflayer-api-key", "PDFLayer API Key", "high", []string{"pdflayer"}, `(?i)\bpdflayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("pepipost-api-key", "Pepipost API Key", "high", []string{"pepipost"}, `(?i)\bpepipost\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("pivotaltracker-api-token", "Pivotal Tracker API Token", "high", []string{"pivotaltracker", "pivotal tracker"}, `(?i)\b(?:pivotaltracker|pivotal[ _-]?tracker)\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("pixabay-api-key", "Pixabay API Key", "high", []string{"pixabay"}, `(?i)\bpixabay\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("podio-api-token", "Podio API Token", "critical", []string{"podio"}, `(?i)\bpodio\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("pubnub-publish-key", "PubNub Publish Key", "high", []string{"pubnub", "pub-c-"}, `\b(pub-c-[A-Za-z0-9-]{32,80})\b`, 1, nil),
		NewRegex("pubnub-subscribe-key", "PubNub Subscribe Key", "medium", []string{"pubnub", "sub-c-"}, `\b(sub-c-[A-Za-z0-9-]{32,80})\b`, 1, nil),
		NewRegex("pusher-channel-key", "Pusher Channel Key", "high", []string{"pusher"}, `(?i)\bpusher\b.{0,80}\b(?:channel[_-]?key|app[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{20,64})\b`, 1, nil),
		NewRegex("qualaroo-api-key", "Qualaroo API Key", "high", []string{"qualaroo"}, `(?i)\bqualaroo\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("rawg-api-key", "RAWG API Key", "high", []string{"rawg"}, `(?i)\brawg\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("ringcentral-client-secret", "RingCentral Client Secret", "critical", []string{"ringcentral"}, `(?i)\bringcentral\b.{0,120}\b(?:client[_-]?secret|app[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("scrapeowl-api-key", "ScrapeOwl API Key", "high", []string{"scrapeowl"}, `(?i)\bscrapeowl\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("scrapfly-api-key", "Scrapfly API Key", "high", []string{"scrapfly"}, `(?i)\bscrapfly\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("screenshotapi-key", "ScreenshotAPI Key", "high", []string{"screenshotapi"}, `(?i)\bscreenshotapi\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("screenshotlayer-api-key", "Screenshotlayer API Key", "high", []string{"screenshotlayer"}, `(?i)\bscreenshotlayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("selectpdf-api-key", "SelectPdf API Key", "high", []string{"selectpdf"}, `(?i)\bselectpdf\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("sheety-api-key", "Sheety API Key", "high", []string{"sheety"}, `(?i)\bsheety\b.{0,80}\b(?:api[_-]?key|bearer[_-]?token|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("shipday-api-key", "Shipday API Key", "critical", []string{"shipday"}, `(?i)\bshipday\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("signable-api-key", "Signable API Key", "critical", []string{"signable"}, `(?i)\bsignable\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("signnow-api-token", "signNow API Token", "critical", []string{"signnow", "api.signnow.com"}, `(?i)\b(?:signnow|api\.signnow\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|access[_-]?token|client[_-]?secret|bearer|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("adobe-sign-client-secret", "Adobe Sign Client Secret", "critical", []string{"adobesign", "adobe sign"}, `(?i)\b(?:adobesign|adobe[ _-]?sign|api\.adobesign\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|integration[_-]?key|access[_-]?token|refresh[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("signaturit-api-key", "Signaturit API Key", "critical", []string{"signaturit"}, `(?i)\bsignaturit\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("simplesat-api-key", "Simplesat API Key", "high", []string{"simplesat"}, `(?i)\bsimplesat\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("smartystreets-auth-token", "SmartyStreets Auth Token", "critical", []string{"smartystreets", "smarty streets"}, `(?i)\b(?:smartystreets|smarty[ _-]?streets)\b.{0,120}\b(?:auth[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("snipcart-api-key", "Snipcart API Key", "critical", []string{"snipcart"}, `(?i)\bsnipcart\b.{0,80}\b(?:secret[_-]?api[_-]?key|api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("spoonacular-api-key", "Spoonacular API Key", "high", []string{"spoonacular"}, `(?i)\bspoonacular\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("sportsmonk-api-token", "SportsMonk API Token", "high", []string{"sportsmonk"}, `(?i)\bsportsmonk\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("spotify-client-secret", "Spotify Client Secret", "critical", []string{"spotify"}, `(?i)\bspotify\b.{0,120}\b(?:client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("statuscake-api-key", "StatusCake API Key", "high", []string{"statuscake"}, `(?i)\bstatuscake\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("stockdata-api-key", "StockData API Key", "high", []string{"stockdata"}, `(?i)\bstockdata\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("storychief-api-key", "StoryChief API Key", "high", []string{"storychief"}, `(?i)\bstorychief\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("shippo-api-token", "Shippo API Token", "critical", []string{"shippo", "api.goshippo.com"}, `(?i)\b(?:shippo|api\.goshippo\.com|goshippo)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|bearer|token)\b\s*[:=]\s*['\"]?((?:shippo_(?:live|test)_)?[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("easypost-api-key", "EasyPost API Key", "critical", []string{"easypost", "api.easypost.com"}, `(?i)\b(?:easypost|api\.easypost\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?((?:EZAK|EZTK)[A-Za-z0-9._-]{24,256}|[A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("shipstation-api-secret", "ShipStation API Secret", "critical", []string{"shipstation", "ssapi.shipstation.com"}, `(?i)\b(?:shipstation|ssapi\.shipstation\.com)\b[\s\S]{0,200}\b(?:api[_-]?secret|api[_-]?key|access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("shipengine-api-key", "ShipEngine API Key", "critical", []string{"shipengine", "api.shipengine.com"}, `(?i)\b(?:shipengine|api\.shipengine\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("aftership-api-key", "AfterShip API Key", "critical", []string{"aftership", "api.aftership.com"}, `(?i)\b(?:aftership|api\.aftership\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|aftership[_-]?api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("easyship-api-token", "Easyship API Token", "critical", []string{"easyship", "api.easyship.com"}, `(?i)\b(?:easyship|api\.easyship\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|api[_-]?key|access[_-]?token|bearer|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("sendcloud-api-key", "Sendcloud API Key", "critical", []string{"sendcloud", "panel.sendcloud.sc"}, `(?i)\b(?:sendcloud|panel\.sendcloud\.sc|api\.sendcloud\.dev)\b[\s\S]{0,200}\b(?:api[_-]?key|api[_-]?secret|public[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("strava-client-secret", "Strava Client Secret", "critical", []string{"strava"}, `(?i)\bstrava\b.{0,120}\b(?:client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([a-f0-9]{40})\b`, 1, nil),
		NewRegex("swiftype-api-key", "Swiftype API Key", "high", []string{"swiftype"}, `(?i)\bswiftype\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tatum-api-key", "Tatum API Key", "critical", []string{"tatum"}, `(?i)\btatum\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("taxjar-api-token", "TaxJar API Token", "critical", []string{"taxjar"}, `(?i)\btaxjar\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("avalara-license-key", "Avalara License Key", "critical", []string{"avalara", "avatax"}, `(?i)\b(?:avalara|avatax|sandbox-rest\.avatax\.com|rest\.avatax\.com)\b[\s\S]{0,200}\b(?:license[_-]?key|account[_-]?id|api[_-]?key|password|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("vertex-tax-api-secret", "Vertex Tax API Secret", "critical", []string{"vertex", "vertexinc.com"}, `(?i)\b(?:vertexinc\.com|vertex|oseries|vertex[_-]?tax)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|trusted[_-]?id|secret|password|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("taxbit-api-key", "TaxBit API Key", "critical", []string{"taxbit", "api.taxbit.com"}, `(?i)\b(?:taxbit|api\.taxbit\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("textmagic-api-key", "TextMagic API Key", "critical", []string{"textmagic"}, `(?i)\btextmagic\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tiingo-api-token", "Tiingo API Token", "high", []string{"tiingo"}, `(?i)\btiingo\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("timecamp-api-token", "TimeCamp API Token", "high", []string{"timecamp"}, `(?i)\btimecamp\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("timezoneapi-key", "TimezoneAPI Key", "high", []string{"timezoneapi"}, `(?i)\btimezoneapi\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("toggltrack-api-token", "Toggl Track API Token", "high", []string{"toggl", "toggltrack"}, `(?i)\b(?:toggltrack|toggl)\b.{0,80}\b(?:api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("tomtom-api-key", "TomTom API Key", "high", []string{"tomtom"}, `(?i)\btomtom\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("transferwise-api-token", "Wise API Token", "critical", []string{"transferwise", "wise"}, `(?i)\b(?:transferwise|wise)\b.{0,80}\b(?:api[_-]?token|token|access[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("unsplash-access-key", "Unsplash Access Key", "high", []string{"unsplash"}, `(?i)\bunsplash\b.{0,80}\b(?:access[_-]?key|api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("userstack-api-key", "Userstack API Key", "high", []string{"userstack"}, `(?i)\buserstack\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("visualcrossing-api-key", "Visual Crossing API Key", "high", []string{"visualcrossing", "visual crossing"}, `(?i)\b(?:visualcrossing|visual[ _-]?crossing)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{24,64})\b`, 1, nil),
		NewRegex("voicegain-api-key", "Voicegain API Key", "critical", []string{"voicegain"}, `(?i)\bvoicegain\b.{0,80}\b(?:api[_-]?key|jwt|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("wepay-client-secret", "WePay Client Secret", "critical", []string{"wepay"}, `(?i)\bwepay\b.{0,120}\b(?:client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("yandex-api-key", "Yandex API Key", "high", []string{"yandex"}, `(?i)\byandex\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("yelp-api-key", "Yelp API Key", "high", []string{"yelp"}, `(?i)\byelp\b.{0,80}\b(?:api[_-]?key|key|bearer[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ynab-api-token", "YNAB API Token", "critical", []string{"youneedabudget", "ynab"}, `(?i)\b(?:youneedabudget|ynab)\b.{0,80}\b(?:api[_-]?token|personal[_-]?access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zenrows-api-key", "ZenRows API Key", "high", []string{"zenrows"}, `(?i)\bzenrows\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("zenscrape-api-key", "Zenscrape API Key", "high", []string{"zenscrape"}, `(?i)\bzenscrape\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("zenserp-api-key", "Zenserp API Key", "high", []string{"zenserp"}, `(?i)\bzenserp\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("zerobounce-api-key", "ZeroBounce API Key", "high", []string{"zerobounce"}, `(?i)\bzerobounce\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("zipcodebase-api-key", "Zipcodebase API Key", "high", []string{"zipcodebase"}, `(?i)\bzipcodebase\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("bitfinex-api-secret", "Bitfinex API Secret", "critical", []string{"bitfinex"}, `(?i)\bbitfinex\b.{0,120}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,128})\b`, 1, nil),
		NewRegex("bitmex-api-secret", "BitMEX API Secret", "critical", []string{"bitmex"}, `(?i)\bbitmex\b.{0,120}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,128})\b`, 1, nil),
		NewRegex("kucoin-api-secret", "KuCoin API Secret", "critical", []string{"kucoin"}, `(?i)\bkucoin\b.{0,120}\b(?:api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,128})\b`, 1, nil),
		NewRegex("smartsheet-access-token", "Smartsheet Access Token", "critical", []string{"smartsheet"}, `(?i)\bsmartsheets?\b.{0,80}\b(?:access[_-]?token|api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tableau-pat-secret", "Tableau Personal Access Token Secret", "critical", []string{"tableau"}, `(?i)\btableau\b.{0,120}\b(?:pat[_-]?secret|personal[_-]?access[_-]?token[_-]?secret|token[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("thousandeyes-token", "ThousandEyes Token", "critical", []string{"thousandeyes", "thousand eyes"}, `(?i)\b(?:thousandeyes|thousand[ _-]?eyes)\b.{0,80}\b(?:bearer[_-]?token|oauth[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("ticketmaster-api-key", "Ticketmaster API Key", "high", []string{"ticketmaster"}, `(?i)\bticketmaster\b.{0,80}\b(?:api[_-]?key|consumer[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("theoddsapi-key", "The Odds API Key", "high", []string{"theoddsapi", "the odds api"}, `(?i)\b(?:theoddsapi|the[ _-]?odds[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("thinkific-api-key", "Thinkific API Key", "critical", []string{"thinkific"}, `(?i)\bthinkific\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("canvas-instructure-access-token", "Canvas/Instructure Access Token", "critical", []string{"instructure.com", "canvas"}, `(?i)\b(?:instructure\.com|canvas\.instructure\.com|canvas[_-]?api|canvas)\b[\s\S]{0,160}\b(?:access[_-]?token|api[_-]?token|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("blackboard-rest-secret", "Blackboard REST Secret", "critical", []string{"blackboard.com", "blackboard"}, `(?i)\b(?:blackboard\.com|learn\.blackboard\.com|blackboard)\b[\s\S]{0,200}\b(?:application[_-]?secret|client[_-]?secret|rest[_-]?secret|api[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("moodle-webservice-token", "Moodle Web Service Token", "critical", []string{"moodle", "wstoken"}, `(?i)\b(?:moodle|wstoken|webservice/rest/server\.php)\b[\s\S]{0,160}\b(?:wstoken|webservice[_-]?token|api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("brightspace-client-secret", "Brightspace Client Secret", "critical", []string{"brightspace", "d2l"}, `(?i)\b(?:brightspace|d2l|desire2learn|auth\.brightspace\.com)\b[\s\S]{0,200}\b(?:client[_-]?secret|api[_-]?secret|secret|refresh[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("schoology-api-secret", "Schoology API Secret", "critical", []string{"schoology", "api.schoology.com"}, `(?i)\b(?:schoology|api\.schoology\.com)\b[\s\S]{0,200}\b(?:api[_-]?secret|consumer[_-]?secret|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("teachable-api-key", "Teachable API Key", "critical", []string{"teachable", "teachable.com"}, `(?i)\b(?:teachable|teachable\.com|developers\.teachable\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("kajabi-api-key", "Kajabi API Key", "critical", []string{"kajabi", "kajabi.com"}, `(?i)\b(?:kajabi|kajabi\.com|api\.kajabi\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("learnworlds-api-key", "LearnWorlds API Key", "critical", []string{"learnworlds", "learnworlds.com"}, `(?i)\b(?:learnworlds|learnworlds\.com|api\.learnworlds\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("talentlms-api-key", "TalentLMS API Key", "critical", []string{"talentlms", "talentlms.com"}, `(?i)\b(?:talentlms|talentlms\.com)\b[\s\S]{0,160}\b(?:api[_-]?key|api[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("docebo-api-token", "Docebo API Token", "critical", []string{"docebo", "docebo.com"}, `(?i)\b(?:docebo|docebo\.com|api\.docebo\.com)\b[\s\S]{0,160}\b(?:api[_-]?token|access[_-]?token|client[_-]?secret|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,256})\b`, 1, nil),
		NewRegex("ubidots-token", "Ubidots Token", "high", []string{"ubidots"}, `(?i)\bubidots\b.{0,80}\b(?:token|api[_-]?token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("uclassify-api-key", "uClassify API Key", "high", []string{"uclassify"}, `(?i)\buclassify\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("upcdatabase-api-key", "UPC Database API Key", "high", []string{"upcdatabase", "upc database"}, `(?i)\b(?:upcdatabase|upc[ _-]?database)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("uplead-api-key", "UpLead API Key", "critical", []string{"uplead"}, `(?i)\buplead\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("vbout-api-key", "VBOUT API Key", "high", []string{"vbout"}, `(?i)\bvbout\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("veriphone-api-key", "Veriphone API Key", "high", []string{"veriphone"}, `(?i)\bveriphone\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("walkscore-api-key", "Walk Score API Key", "high", []string{"walkscore", "walk score"}, `(?i)\b(?:walkscore|walk[ _-]?score)\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("websitepulse-api-key", "WebsitePulse API Key", "high", []string{"websitepulse"}, `(?i)\bwebsitepulse\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("whoxy-api-key", "Whoxy API Key", "high", []string{"whoxy"}, `(?i)\bwhoxy\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("wistia-api-token", "Wistia API Token", "critical", []string{"wistia"}, `(?i)\bwistia\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("wit-ai-token", "Wit.ai Token", "critical", []string{"wit.ai", "wit"}, `(?i)\b(?:wit\.ai|wit)\b.{0,80}\b(?:server[_-]?access[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ticket-tailor-api-key", "Ticket Tailor API Key", "high", []string{"tickettailor", "ticket tailor"}, `(?i)\b(?:tickettailor|ticket[ _-]?tailor)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tmetric-api-token", "TMetric API Token", "high", []string{"tmetric"}, `(?i)\btmetric\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("teamgate-api-key", "Teamgate API Key", "high", []string{"teamgate"}, `(?i)\bteamgate\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("teamworkspaces-token", "Teamwork Spaces Token", "high", []string{"teamworkspaces", "teamwork spaces"}, `(?i)\b(?:teamworkspaces|teamwork[ _-]?spaces)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("signupgenius-api-key", "SignUpGenius API Key", "high", []string{"signupgenius", "signup genius"}, `(?i)\b(?:signupgenius|signup[ _-]?genius)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("speechtextai-api-key", "SpeechText.AI API Key", "critical", []string{"speechtextai", "speechtext.ai"}, `(?i)\b(?:speechtextai|speechtext\.ai)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("sirv-api-token", "Sirv API Token", "high", []string{"sirv"}, `(?i)\bsirv\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("siteleaf-api-key", "Siteleaf API Key", "high", []string{"siteleaf"}, `(?i)\bsiteleaf\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("skrapp-api-key", "Skrapp API Key", "high", []string{"skrapp"}, `(?i)\bskrapp\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("skybiometry-api-key", "SkyBiometry API Key", "high", []string{"skybiometry"}, `(?i)\bskybiometry\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("simplynoted-api-key", "SimplyNoted API Key", "high", []string{"simplynoted", "simply noted"}, `(?i)\b(?:simplynoted|simply[ _-]?noted)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("simvoly-api-key", "Simvoly API Key", "high", []string{"simvoly"}, `(?i)\bsimvoly\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("sinch-message-api-token", "Sinch Message API Token", "critical", []string{"sinch"}, `(?i)\bsinch\b.{0,80}\b(?:message[_-]?api[_-]?token|api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("sslmate-api-key", "SSLMate API Key", "critical", []string{"sslmate"}, `(?i)\bsslmate\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("statuspal-api-key", "Statuspal API Key", "high", []string{"statuspal"}, `(?i)\bstatuspal\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("storecove-api-key", "Storecove API Key", "critical", []string{"storecove"}, `(?i)\bstorecove\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("stormboard-api-key", "Stormboard API Key", "high", []string{"stormboard"}, `(?i)\bstormboard\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("streak-api-key", "Streak API Key", "high", []string{"streak"}, `(?i)\bstreak\b.{0,80}\b(?:api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{32,64})\b`, 1, nil),
		NewRegex("stripo-api-key", "Stripo API Key", "high", []string{"stripo"}, `(?i)\bstripo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("sugester-api-token", "Sugester API Token", "high", []string{"sugester"}, `(?i)\bsugester\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("abyssale-api-key", "Abyssale API Key", "high", []string{"abyssale"}, `(?i)\babyssale\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("adafruit-io-key", "Adafruit IO Key", "high", []string{"adafruit", "adafruitio"}, `(?i)\b(?:adafruit[ _-]?io|adafruit)\b.{0,80}\b(?:aio[_-]?key|io[_-]?key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("adobe-io-client-secret", "Adobe IO Client Secret", "critical", []string{"adobeio", "adobe io"}, `(?i)\b(?:adobe[ _-]?io|adobe)\b.{0,80}\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("aeroworkflow-api-key", "Aero Workflow API Key", "high", []string{"aeroworkflow", "aero workflow"}, `(?i)\b(?:aeroworkflow|aero[ _-]?workflow)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("agora-app-certificate", "Agora App Certificate", "critical", []string{"agora"}, `(?i)\bagora\b.{0,80}\b(?:app[_-]?certificate|certificate|api[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Fa-f0-9]{32})\b`, 1, nil),
		NewRegex("airship-api-key", "Airship API Key", "critical", []string{"airship", "urbanairship"}, `(?i)\b(?:airship|urban[ _-]?airship)\b.{0,80}\b(?:api[_-]?key|app[_-]?key|master[_-]?secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("alconost-api-key", "Alconost API Key", "high", []string{"alconost"}, `(?i)\balconost\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("alegra-api-token", "Alegra API Token", "high", []string{"alegra"}, `(?i)\balegra\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("aletheia-api-key", "Aletheia API Key", "high", []string{"aletheia"}, `(?i)\baletheia\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("allsports-api-key", "AllSports API Key", "high", []string{"allsports", "all sports"}, `(?i)\b(?:allsports|all[ _-]?sports)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("anypoint-client-secret", "Anypoint Client Secret", "critical", []string{"anypoint", "mulesoft"}, `(?i)\b(?:anypoint|mulesoft)\b.{0,80}\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("apacta-api-key", "Apacta API Key", "high", []string{"apacta"}, `(?i)\bapacta\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("api2cart-api-key", "API2Cart API Key", "high", []string{"api2cart"}, `(?i)\bapi2cart\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("apideck-api-key", "Apideck API Key", "critical", []string{"apideck"}, `(?i)\bapideck\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("apifonica-api-key", "Apifonica API Key", "critical", []string{"apifonica"}, `(?i)\bapifonica\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("apimatic-api-key", "APIMatic API Key", "high", []string{"apimatic"}, `(?i)\bapimatic\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("apimetrics-api-key", "APImetrics API Key", "high", []string{"apimetrics"}, `(?i)\bapimetrics\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("appointedd-api-key", "Appointedd API Key", "high", []string{"appointedd"}, `(?i)\bappointedd\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("appoptics-api-token", "AppOptics API Token", "critical", []string{"appoptics"}, `(?i)\bappoptics\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("appsynergy-api-key", "AppSynergy API Key", "high", []string{"appsynergy", "app synergy"}, `(?i)\b(?:appsynergy|app[ _-]?synergy)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("apptivo-api-key", "Apptivo API Key", "high", []string{"apptivo"}, `(?i)\bapptivo\b.{0,80}\b(?:api[_-]?key|key|access[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("artsy-api-token", "Artsy API Token", "high", []string{"artsy"}, `(?i)\bartsy\b.{0,80}\b(?:api[_-]?token|token|client[_-]?secret|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("atera-api-key", "Atera API Key", "critical", []string{"atera"}, `(?i)\batera\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("atlassian-datacenter-token", "Atlassian Data Center Token", "critical", []string{"atlassian", "datacenter"}, `(?i)\batlassian\b.{0,80}\b(?:data[ _-]?center|datacenter)\b.{0,80}\b(?:personal[_-]?access[_-]?token|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("audd-api-token", "AudD API Token", "high", []string{"audd"}, `(?i)\baudd\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("autodesk-client-secret", "Autodesk Client Secret", "critical", []string{"autodesk"}, `(?i)\bautodesk\b.{0,80}\b(?:client[_-]?secret|api[_-]?key|access[_-]?token|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("autopilot-api-key", "Autopilot API Key", "high", []string{"autopilot"}, `(?i)\bautopilot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("axonaut-api-key", "Axonaut API Key", "high", []string{"axonaut"}, `(?i)\baxonaut\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("aylien-api-key", "AYLIEN API Key", "high", []string{"aylien"}, `(?i)\baylien\b.{0,80}\b(?:api[_-]?key|key|application[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("beebole-api-token", "Beebole API Token", "high", []string{"beebole"}, `(?i)\bbeebole\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("besnappy-api-key", "BeSnappy API Key", "high", []string{"besnappy", "be snappy"}, `(?i)\b(?:besnappy|be[ _-]?snappy)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("billomat-api-key", "Billomat API Key", "high", []string{"billomat"}, `(?i)\bbillomat\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("blitapp-api-key", "Blitapp API Key", "high", []string{"blitapp"}, `(?i)\bblitapp\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("blogger-api-key", "Blogger API Key", "high", []string{"blogger"}, `(?i)\bblogger\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("bombbomb-api-key", "BombBomb API Key", "high", []string{"bombbomb", "bomb bomb"}, `(?i)\b(?:bombbomb|bomb[ _-]?bomb)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("boostnote-api-token", "Boost Note API Token", "high", []string{"boostnote", "boost note"}, `(?i)\b(?:boostnote|boost[ _-]?note)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("borgbase-api-key", "BorgBase API Key", "critical", []string{"borgbase"}, `(?i)\bborgbase\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("buddyns-api-key", "BuddyNS API Key", "high", []string{"buddyns", "buddy ns"}, `(?i)\b(?:buddyns|buddy[ _-]?ns)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("budibase-api-key", "Budibase API Key", "critical", []string{"budibase"}, `(?i)\bbudibase\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("bugherd-api-key", "BugHerd API Key", "high", []string{"bugherd"}, `(?i)\bbugherd\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("bulbul-api-key", "Bulbul API Key", "high", []string{"bulbul"}, `(?i)\bbulbul\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("bulksms-api-token", "BulkSMS API Token", "critical", []string{"bulksms", "bulk sms"}, `(?i)\b(?:bulksms|bulk[ _-]?sms)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("caflou-api-key", "Caflou API Key", "high", []string{"caflou"}, `(?i)\bcaflou\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("calorieninja-api-key", "CalorieNinjas API Key", "high", []string{"calorieninja", "calorieninjas", "calorie ninjas"}, `(?i)\b(?:calorie[ _-]?ninjas?|calorieninjas?)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("campayn-api-key", "Campayn API Key", "high", []string{"campayn"}, `(?i)\bcampayn\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("captaindata-api-key", "Captain Data API Key", "high", []string{"captaindata", "captain data"}, `(?i)\b(?:captaindata|captain[ _-]?data)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cashboard-api-key", "Cashboard API Key", "high", []string{"cashboard"}, `(?i)\bcashboard\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("caspio-api-key", "Caspio API Key", "high", []string{"caspio"}, `(?i)\bcaspio\b.{0,80}\b(?:api[_-]?key|key|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("centralstationcrm-api-token", "CentralStationCRM API Token", "high", []string{"centralstationcrm", "central station crm"}, `(?i)\b(?:centralstationcrm|central[ _-]?station[ _-]?crm)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cexio-api-key", "CEX.IO API Key", "critical", []string{"cexio", "cex.io"}, `(?i)\b(?:cex\.io|cexio)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("chatbot-api-key", "ChatBot API Key", "critical", []string{"chatbot"}, `(?i)\bchatbot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("chatfuel-api-key", "Chatfuel API Key", "critical", []string{"chatfuel"}, `(?i)\bchatfuel\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("chec-api-key", "Chec API Key", "critical", []string{"chec", "chec.io"}, `(?i)\b(?:chec\.io|chec)\b.{0,80}\b(?:secret[_-]?key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("checkvist-api-token", "Checkvist API Token", "high", []string{"checkvist"}, `(?i)\bcheckvist\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cicero-api-key", "Cicero API Key", "high", []string{"cicero"}, `(?i)\bcicero\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clickhelp-api-key", "ClickHelp API Key", "high", []string{"clickhelp"}, `(?i)\bclickhelp\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cliengo-api-key", "Cliengo API Key", "high", []string{"cliengo"}, `(?i)\bcliengo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clientary-api-key", "Clientary API Key", "high", []string{"clientary"}, `(?i)\bclientary\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clinchpad-api-key", "ClinchPad API Key", "high", []string{"clinchpad"}, `(?i)\bclinchpad\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clockworksms-api-key", "Clockwork SMS API Key", "critical", []string{"clockworksms", "clockwork sms"}, `(?i)\b(?:clockworksms|clockwork[ _-]?sms)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("avaza-api-token", "Avaza API Token", "high", []string{"avaza"}, `(?i)\bavaza\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cloudelements-api-key", "Cloud Elements API Key", "critical", []string{"cloudelements", "cloud elements"}, `(?i)\b(?:cloudelements|cloud[ _-]?elements)\b.{0,80}\b(?:api[_-]?key|user[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("cloudimage-api-key", "Cloudimage API Key", "high", []string{"cloudimage"}, `(?i)\bcloudimage\b.{0,80}\b(?:api[_-]?key|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cloudplan-api-key", "Cloudplan API Key", "high", []string{"cloudplan"}, `(?i)\bcloudplan\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cloverly-api-key", "Cloverly API Key", "high", []string{"cloverly"}, `(?i)\bcloverly\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("cloze-api-key", "Cloze API Key", "high", []string{"cloze"}, `(?i)\bcloze\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("clustdoc-api-key", "Clustdoc API Key", "high", []string{"clustdoc"}, `(?i)\bclustdoc\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("codequiry-api-key", "Codequiry API Key", "high", []string{"codequiry"}, `(?i)\bcodequiry\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("collect2-api-key", "Collect2 API Key", "high", []string{"collect2"}, `(?i)\bcollect2\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("column-api-key", "Column API Key", "critical", []string{"column"}, `(?i)\bcolumn\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("commercejs-api-key", "Commerce.js API Key", "critical", []string{"commercejs", "commerce.js"}, `(?i)\b(?:commerce\.js|commercejs)\b.{0,80}\b(?:secret[_-]?key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("commodities-api-key", "Commodities API Key", "high", []string{"commodities"}, `(?i)\bcommodities\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("companyhub-api-key", "CompanyHub API Key", "high", []string{"companyhub", "company hub"}, `(?i)\b(?:companyhub|company[ _-]?hub)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("conversiontools-api-key", "ConversionTools API Key", "high", []string{"conversiontools", "conversion tools"}, `(?i)\b(?:conversiontools|conversion[ _-]?tools)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("convier-api-key", "Convier API Key", "high", []string{"convier"}, `(?i)\bconvier\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("countrylayer-api-key", "Countrylayer API Key", "high", []string{"countrylayer"}, `(?i)\bcountrylayer\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("currencycloud-api-key", "Currencycloud API Key", "critical", []string{"currencycloud", "currency cloud"}, `(?i)\b(?:currencycloud|currency[ _-]?cloud)\b.{0,80}\b(?:api[_-]?key|login[_-]?id|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("customerguru-api-key", "Customer.guru API Key", "high", []string{"customerguru", "customer.guru"}, `(?i)\b(?:customer\.guru|customerguru)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("d7network-api-token", "D7 Network API Token", "critical", []string{"d7network", "d7 network"}, `(?i)\b(?:d7network|d7[ _-]?network)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("dandelion-api-key", "Dandelion API Key", "high", []string{"dandelion"}, `(?i)\bdandelion\b.{0,80}\b(?:api[_-]?key|app[_-]?id|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dareboost-api-key", "Dareboost API Key", "high", []string{"dareboost"}, `(?i)\bdareboost\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("datagov-api-key", "Data.gov API Key", "high", []string{"data.gov", "datagov"}, `(?i)\b(?:data\.gov|datagov)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("demio-api-key", "Demio API Key", "high", []string{"demio"}, `(?i)\bdemio\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dfuse-api-key", "dfuse API Key", "critical", []string{"dfuse"}, `(?i)\bdfuse\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("diggernaut-api-key", "Diggernaut API Key", "high", []string{"diggernaut"}, `(?i)\bdiggernaut\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("disqus-api-key", "Disqus API Key", "high", []string{"disqus"}, `(?i)\bdisqus\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ditto-api-key", "Ditto API Key", "high", []string{"ditto"}, `(?i)\bditto\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dnscheck-api-key", "DNSCheck API Key", "high", []string{"dnscheck", "dns check"}, `(?i)\b(?:dnscheck|dns[ _-]?check)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("docparser-api-key", "Docparser API Key", "high", []string{"docparser"}, `(?i)\bdocparser\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("documo-api-key", "Documo API Key", "high", []string{"documo"}, `(?i)\bdocumo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dotdigital-api-key", "Dotdigital API Key", "critical", []string{"dotdigital", "dot digital"}, `(?i)\b(?:dotdigital|dot[ _-]?digital)\b.{0,80}\b(?:api[_-]?key|key|token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("dovico-api-key", "Dovico API Key", "high", []string{"dovico"}, `(?i)\bdovico\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dronahq-api-key", "DronaHQ API Key", "critical", []string{"dronahq", "drona hq"}, `(?i)\b(?:dronahq|drona[ _-]?hq)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("droneci-token", "Drone CI Token", "critical", []string{"droneci", "drone ci", "DRONE_TOKEN"}, `(?i)\b(?:droneci|drone[ _-]?ci|drone_token)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("duply-api-key", "Duply API Key", "high", []string{"duply"}, `(?i)\bduply\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dynalist-api-token", "Dynalist API Token", "high", []string{"dynalist"}, `(?i)\bdynalist\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("dyspatch-api-key", "Dyspatch API Key", "critical", []string{"dyspatch"}, `(?i)\bdyspatch\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("eagleeyenetworks-api-key", "Eagle Eye Networks API Key", "critical", []string{"eagleeyenetworks", "eagle eye networks"}, `(?i)\b(?:eagleeyenetworks|eagle[ _-]?eye[ _-]?networks)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("easyinsight-api-key", "Easy Insight API Key", "high", []string{"easyinsight", "easy insight"}, `(?i)\b(?:easyinsight|easy[ _-]?insight)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ecostruxureit-api-key", "EcoStruxure IT API Key", "critical", []string{"ecostruxureit", "ecostruxure it"}, `(?i)\b(?:ecostruxureit|ecostruxure[ _-]?it)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("eightxeight-api-key", "8x8 API Key", "critical", []string{"8x8", "eightxeight"}, `(?i)\b(?:8x8|eightxeight)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("dwolla-api-key", "Dwolla API Key", "critical", []string{"dwolla"}, `(?i)\bdwolla\b.{0,120}\b(?:api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("enablex-api-key", "EnableX API Key", "critical", []string{"enablex"}, `(?i)\benablex\b.{0,80}\b(?:api[_-]?key|app[_-]?id|secret|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("enigma-api-key", "Enigma API Key", "high", []string{"enigma"}, `(?i)\benigma\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("envoy-api-key", "Envoy API Key", "critical", []string{"envoy"}, `(?i)\benvoy\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("eraser-api-key", "Eraser API Key", "high", []string{"eraser"}, `(?i)\beraser\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("everhour-api-key", "Everhour API Key", "high", []string{"everhour"}, `(?i)\beverhour\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("exportsdk-api-key", "ExportSDK API Key", "high", []string{"exportsdk", "export sdk"}, `(?i)\b(?:exportsdk|export[ _-]?sdk)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("extractorapi-key", "Extractor API Key", "high", []string{"extractorapi", "extractor api"}, `(?i)\b(?:extractorapi|extractor[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("feedier-api-key", "Feedier API Key", "high", []string{"feedier"}, `(?i)\bfeedier\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fetchrss-api-key", "FetchRSS API Key", "high", []string{"fetchrss", "fetch rss"}, `(?i)\b(?:fetchrss|fetch[ _-]?rss)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fibery-api-token", "Fibery API Token", "high", []string{"fibery"}, `(?i)\bfibery\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fileio-api-key", "File.io API Key", "high", []string{"file.io", "fileio"}, `(?i)\b(?:file\.io|fileio)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("finage-api-key", "Finage API Key", "high", []string{"finage"}, `(?i)\bfinage\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("findl-api-key", "Findl API Key", "high", []string{"findl"}, `(?i)\bfindl\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("flatio-api-key", "Flatio API Key", "high", []string{"flatio"}, `(?i)\bflatio\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fleetbase-api-key", "Fleetbase API Key", "critical", []string{"fleetbase"}, `(?i)\bfleetbase\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("flexport-api-key", "Flexport API Key", "critical", []string{"flexport"}, `(?i)\bflexport\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("flickr-api-key", "Flickr API Key", "high", []string{"flickr"}, `(?i)\bflickr\b.{0,80}\b(?:api[_-]?key|key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("flightapi-key", "FlightAPI Key", "high", []string{"flightapi", "flight api"}, `(?i)\b(?:flightapi|flight[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("flightlabs-api-key", "FlightLabs API Key", "high", []string{"flightlabs", "flight labs"}, `(?i)\b(?:flightlabs|flight[ _-]?labs)\b.{0,80}\b(?:api[_-]?key|access[_-]?key|key)\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
		NewRegex("flightstats-api-key", "FlightStats API Key", "high", []string{"flightstats", "flight stats"}, `(?i)\b(?:flightstats|flight[ _-]?stats)\b.{0,80}\b(?:api[_-]?key|app[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("float-api-key", "Float API Key", "high", []string{"float"}, `(?i)\bfloat\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("flowflu-api-key", "Flowlu API Key", "high", []string{"flowflu", "flowlu"}, `(?i)\b(?:flowflu|flowlu)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fmfw-api-key", "FMFW API Key", "critical", []string{"fmfw"}, `(?i)\bfmfw\b.{0,80}\b(?:api[_-]?key|key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("formbucket-api-key", "FormBucket API Key", "high", []string{"formbucket", "form bucket"}, `(?i)\b(?:formbucket|form[ _-]?bucket)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("formcraft-api-key", "FormCraft API Key", "high", []string{"formcraft", "form craft"}, `(?i)\b(?:formcraft|form[ _-]?craft)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("formio-api-key", "Form.io API Key", "critical", []string{"form.io", "formio"}, `(?i)\b(?:form\.io|formio)\b.{0,80}\b(?:api[_-]?key|jwt[_-]?secret|secret|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("formsite-api-key", "Formsite API Key", "high", []string{"formsite"}, `(?i)\bformsite\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("foursquare-api-key", "Foursquare API Key", "high", []string{"foursquare"}, `(?i)\bfoursquare\b.{0,120}\b(?:api[_-]?key|client[_-]?secret|secret|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("frameio-api-token", "Frame.io API Token", "critical", []string{"frame.io", "frameio"}, `(?i)\b(?:frame\.io|frameio)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("freshbooks-api-key", "FreshBooks API Key", "high", []string{"freshbooks", "fresh books"}, `(?i)\b(?:freshbooks|fresh[ _-]?books)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("fulcrum-api-token", "Fulcrum API Token", "high", []string{"fulcrum"}, `(?i)\bfulcrum\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("fxmarket-api-key", "FXMarket API Key", "high", []string{"fxmarket", "fx market"}, `(?i)\b(?:fxmarket|fx[ _-]?market)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gengo-api-key", "Gengo API Key", "high", []string{"gengo"}, `(?i)\bgengo\b.{0,80}\b(?:api[_-]?key|key|private[_-]?key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("geocodify-api-key", "Geocodify API Key", "high", []string{"geocodify"}, `(?i)\bgeocodify\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("geoipifi-api-key", "Geo.ipify API Key", "high", []string{"geoipify", "geo.ipify"}, `(?i)\b(?:geo\.ipify|geoipify)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("getemail-api-key", "GetEmail API Key", "high", []string{"getemail", "get email"}, `(?i)\b(?:getemail|get[ _-]?email)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("getemails-api-key", "GetEmails API Key", "high", []string{"getemails", "get emails"}, `(?i)\b(?:getemails|get[ _-]?emails)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("getgeoapi-key", "GetGeoAPI Key", "high", []string{"getgeoapi", "get geo api"}, `(?i)\b(?:getgeoapi|get[ _-]?geo[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("getgist-api-key", "GetGist API Key", "high", []string{"getgist", "get gist"}, `(?i)\b(?:getgist|get[ _-]?gist)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("getsandbox-api-key", "GetSandbox API Key", "high", []string{"getsandbox", "get sandbox"}, `(?i)\b(?:getsandbox|get[ _-]?sandbox)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gitter-token", "Gitter Token", "high", []string{"gitter"}, `(?i)\bgitter\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("glassnode-api-key", "Glassnode API Key", "high", []string{"glassnode"}, `(?i)\bglassnode\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gocanvas-api-key", "GoCanvas API Key", "high", []string{"gocanvas", "go canvas"}, `(?i)\b(?:gocanvas|go[ _-]?canvas)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("godaddy-api-key", "GoDaddy API Key", "critical", []string{"godaddy", "go daddy"}, `(?i)\b(?:godaddy|go[ _-]?daddy)\b.{0,120}\b(?:api[_-]?key|key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("goodday-api-key", "GoodDay API Key", "high", []string{"goodday", "good day"}, `(?i)\b(?:goodday|good[ _-]?day)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("graphcms-api-token", "GraphCMS API Token", "critical", []string{"graphcms", "graph cms"}, `(?i)\b(?:graphcms|graph[ _-]?cms)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("groovehq-api-key", "GrooveHQ API Key", "high", []string{"groovehq", "groove hq"}, `(?i)\b(?:groovehq|groove[ _-]?hq)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gtmetrix-api-key", "GTmetrix API Key", "high", []string{"gtmetrix"}, `(?i)\bgtmetrix\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("guru-api-key", "Guru API Key", "high", []string{"guru"}, `(?i)\bguru\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("gyazo-api-token", "Gyazo API Token", "high", []string{"gyazo"}, `(?i)\bgyazo\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("happyscribe-api-key", "Happy Scribe API Key", "high", []string{"happyscribe", "happy scribe"}, `(?i)\b(?:happyscribe|happy[ _-]?scribe)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("hive-api-key", "Hive API Key", "high", []string{"hive"}, `(?i)\bhive\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("hiveage-api-key", "Hiveage API Key", "high", []string{"hiveage"}, `(?i)\bhiveage\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("holistic-api-key", "Holistic API Key", "high", []string{"holistic"}, `(?i)\bholistic\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("humanity-api-key", "Humanity API Key", "high", []string{"humanity"}, `(?i)\bhumanity\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("hybiscus-api-key", "Hybiscus API Key", "high", []string{"hybiscus"}, `(?i)\bhybiscus\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("hypertrack-api-key", "HyperTrack API Key", "critical", []string{"hypertrack"}, `(?i)\bhypertrack\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("ibmcloud-user-key", "IBM Cloud User Key", "critical", []string{"ibmcloud", "ibm cloud"}, `(?i)\b(?:ibmcloud|ibm[ _-]?cloud)\b.{0,120}\b(?:user[_-]?key|api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("iconfinder-api-key", "Iconfinder API Key", "high", []string{"iconfinder"}, `(?i)\biconfinder\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("iexapis-api-key", "IEX APIs Key", "high", []string{"iexapis", "iex apis"}, `(?i)\b(?:iexapis|iex[ _-]?apis)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("iexcloud-api-key", "IEX Cloud API Key", "high", []string{"iexcloud", "iex cloud"}, `(?i)\b(?:iexcloud|iex[ _-]?cloud)\b.{0,80}\b(?:api[_-]?key|publishable[_-]?token|secret[_-]?token|token|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("imagga-api-key", "Imagga API Key", "high", []string{"imagga"}, `(?i)\bimagga\b.{0,80}\b(?:api[_-]?key|key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("impala-api-key", "Impala API Key", "critical", []string{"impala"}, `(?i)\bimpala\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("insightly-api-key", "Insightly API Key", "high", []string{"insightly"}, `(?i)\binsightly\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("instabot-api-key", "Instabot API Key", "high", []string{"instabot"}, `(?i)\binstabot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("instamojo-api-key", "Instamojo API Key", "critical", []string{"instamojo"}, `(?i)\binstamojo\b.{0,80}\b(?:api[_-]?key|auth[_-]?token|token|key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("interseller-api-key", "Interseller API Key", "high", []string{"interseller"}, `(?i)\binterseller\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("intra42-api-key", "Intra42 API Key", "high", []string{"intra42"}, `(?i)\bintra42\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("intrinio-api-key", "Intrinio API Key", "high", []string{"intrinio"}, `(?i)\bintrinio\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("invoiceocean-api-key", "InvoiceOcean API Key", "high", []string{"invoiceocean", "invoice ocean"}, `(?i)\b(?:invoiceocean|invoice[ _-]?ocean)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("juro-api-key", "Juro API Key", "critical", []string{"juro"}, `(?i)\bjuro\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("kanban-api-key", "Kanban API Key", "high", []string{"kanban"}, `(?i)\bkanban\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("kanbantool-api-key", "Kanban Tool API Key", "high", []string{"kanbantool", "kanban tool"}, `(?i)\b(?:kanbantool|kanban[ _-]?tool)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("karmacrm-api-key", "karmaCRM API Key", "high", []string{"karmacrm", "karma crm"}, `(?i)\b(?:karmacrm|karma[ _-]?crm)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("knapsackpro-api-token", "Knapsack Pro API Token", "high", []string{"knapsackpro", "knapsack pro"}, `(?i)\b(?:knapsackpro|knapsack[ _-]?pro)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("kontent-api-key", "Kontent API Key", "high", []string{"kontent"}, `(?i)\bkontent\b.{0,80}\b(?:api[_-]?key|delivery[_-]?key|management[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("kylas-api-key", "Kylas API Key", "high", []string{"kylas"}, `(?i)\bkylas\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("leadfeeder-api-key", "Leadfeeder API Key", "high", []string{"leadfeeder"}, `(?i)\bleadfeeder\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("lendflow-api-key", "Lendflow API Key", "critical", []string{"lendflow"}, `(?i)\blendflow\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("lexigram-api-key", "Lexigram API Key", "high", []string{"lexigram"}, `(?i)\blexigram\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("kraken-api-secret", "Kraken API Secret", "critical", []string{"kraken"}, `(?i)\bkraken\b.{0,120}\b(?:api[_-]?secret|secret|private[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,256})\b`, 1, nil),
		NewRegex("larksuite-token", "LarkSuite Token", "critical", []string{"lark", "larksuite"}, `(?i)\b(?:larksuite|lark)\b.{0,120}\b(?:app[_-]?secret|tenant[_-]?access[_-]?token|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("liveagent-api-key", "LiveAgent API Key", "high", []string{"liveagent", "live agent"}, `(?i)\b(?:liveagent|live[ _-]?agent)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("livestorm-api-key", "Livestorm API Key", "high", []string{"livestorm"}, `(?i)\blivestorm\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("loadmill-api-key", "Loadmill API Key", "high", []string{"loadmill"}, `(?i)\bloadmill\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("loyverse-api-token", "Loyverse API Token", "high", []string{"loyverse"}, `(?i)\bloyverse\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("lunchmoney-api-token", "Lunch Money API Token", "high", []string{"lunchmoney", "lunch money"}, `(?i)\b(?:lunchmoney|lunch[ _-]?money)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("luno-api-secret", "Luno API Secret", "critical", []string{"luno"}, `(?i)\bluno\b.{0,120}\b(?:api[_-]?secret|secret|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,256})\b`, 1, nil),
		NewRegex("m3o-api-key", "M3O API Key", "high", []string{"m3o"}, `(?i)\bm3o\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("madkudu-api-key", "MadKudu API Key", "high", []string{"madkudu"}, `(?i)\bmadkudu\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("magicbell-api-key", "MagicBell API Key", "high", []string{"magicbell", "magic bell"}, `(?i)\b(?:magicbell|magic[ _-]?bell)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("magnetic-api-key", "Magnetic API Key", "high", []string{"magnetic"}, `(?i)\bmagnetic\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mailjetsms-api-token", "Mailjet SMS API Token", "critical", []string{"mailjetsms", "mailjet sms"}, `(?i)\b(?:mailjetsms|mailjet[ _-]?sms)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mailsac-api-key", "Mailsac API Key", "high", []string{"mailsac"}, `(?i)\bmailsac\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("manifest-api-key", "Manifest API Key", "high", []string{"manifest"}, `(?i)\bmanifest\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mavenlink-api-token", "Mavenlink API Token", "high", []string{"mavenlink"}, `(?i)\bmavenlink\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("meistertask-api-token", "MeisterTask API Token", "high", []string{"meistertask", "meister task"}, `(?i)\b(?:meistertask|meister[ _-]?task)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("meraki-api-key", "Meraki API Key", "critical", []string{"meraki"}, `(?i)\bmeraki\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mesibo-api-token", "Mesibo API Token", "critical", []string{"mesibo"}, `(?i)\bmesibo\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("metaapi-token", "MetaApi Token", "critical", []string{"metaapi", "meta api"}, `(?i)\b(?:metaapi|meta[ _-]?api)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("metabase-api-key", "Metabase API Key", "critical", []string{"metabase"}, `(?i)\bmetabase\b.{0,80}\b(?:api[_-]?key|key|token|session)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("metrilo-api-key", "Metrilo API Key", "high", []string{"metrilo"}, `(?i)\bmetrilo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mindmeister-api-token", "MindMeister API Token", "high", []string{"mindmeister", "mind meister"}, `(?i)\b(?:mindmeister|mind[ _-]?meister)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("miro-api-token", "Miro API Token", "critical", []string{"miro"}, `(?i)\bmiro\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mite-api-key", "mite API Key", "high", []string{"mite"}, `(?i)\bmite\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("mixmax-api-key", "Mixmax API Key", "high", []string{"mixmax"}, `(?i)\bmixmax\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("moderation-api-key", "Moderation API Key", "high", []string{"moderation"}, `(?i)\bmoderation\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("moonclerk-api-key", "MoonClerk API Key", "critical", []string{"moonclerk", "moon clerk"}, `(?i)\b(?:moonclerk|moon[ _-]?clerk)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("moralis-api-key", "Moralis API Key", "critical", []string{"moralis"}, `(?i)\bmoralis\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("mrticktock-api-key", "MrTickTock API Key", "high", []string{"mrticktock", "mr tick tock"}, `(?i)\b(?:mrticktock|mr[ _-]?tick[ _-]?tock)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("myfreshworks-api-key", "Freshworks API Key", "high", []string{"myfreshworks", "freshworks"}, `(?i)\b(?:myfreshworks|freshworks)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("myintervals-api-key", "MyIntervals API Key", "high", []string{"myintervals", "my intervals"}, `(?i)\b(?:myintervals|my[ _-]?intervals)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nasdaqdatalink-api-key", "Nasdaq Data Link API Key", "high", []string{"nasdaqdatalink", "nasdaq data link"}, `(?i)\b(?:nasdaqdatalink|nasdaq[ _-]?data[ _-]?link)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nethunt-api-key", "NetHunt API Key", "high", []string{"nethunt", "net hunt"}, `(?i)\b(?:nethunt|net[ _-]?hunt)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("netsuite-token-secret", "NetSuite Token Secret", "critical", []string{"netsuite", "net suite"}, `(?i)\b(?:netsuite|net[ _-]?suite)\b.{0,120}\b(?:token[_-]?secret|consumer[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("newscatcher-api-key", "NewsCatcher API Key", "high", []string{"newscatcher", "news catcher"}, `(?i)\b(?:newscatcher|news[ _-]?catcher)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nexmo-api-key", "Nexmo API Key", "critical", []string{"nexmo"}, `(?i)\bnexmo\b.{0,80}\b(?:api[_-]?key|key|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("nftport-api-key", "NFTPort API Key", "critical", []string{"nftport", "nft port"}, `(?i)\b(?:nftport|nft[ _-]?port)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("ngc-api-key", "NVIDIA NGC API Key", "critical", []string{"ngc", "nvidia"}, `(?i)\b(?:ngc|nvidia)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("nicereply-api-key", "Nicereply API Key", "high", []string{"nicereply", "nice reply"}, `(?i)\b(?:nicereply|nice[ _-]?reply)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nimble-api-key", "Nimble API Key", "high", []string{"nimble"}, `(?i)\bnimble\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("noticeable-api-key", "Noticeable API Key", "high", []string{"noticeable"}, `(?i)\bnoticeable\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nozbeteams-api-token", "Nozbe Teams API Token", "high", []string{"nozbeteams", "nozbe teams"}, `(?i)\b(?:nozbeteams|nozbe[ _-]?teams)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("nvapi-key", "NVAPI Key", "high", []string{"nvapi"}, `(?i)\bnvapi\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("onedesk-api-key", "OneDesk API Key", "high", []string{"onedesk", "one desk"}, `(?i)\b(?:onedesk|one[ _-]?desk)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("onepagecrm-api-key", "OnePageCRM API Key", "high", []string{"onepagecrm", "one page crm"}, `(?i)\b(?:onepagecrm|one[ _-]?page[ _-]?crm)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("oopspam-api-key", "OOPSpam API Key", "high", []string{"oopspam"}, `(?i)\boopspam\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("optimizely-api-key", "Optimizely API Key", "critical", []string{"optimizely"}, `(?i)\boptimizely\b.{0,80}\b(?:api[_-]?key|sdk[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("overloop-api-key", "Overloop API Key", "high", []string{"overloop"}, `(?i)\boverloop\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("paralleldots-api-key", "ParallelDots API Key", "high", []string{"paralleldots", "parallel dots"}, `(?i)\b(?:paralleldots|parallel[ _-]?dots)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("parsers-api-key", "Parsers API Key", "high", []string{"parsers"}, `(?i)\bparsers\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("parseur-api-key", "Parseur API Key", "high", []string{"parseur"}, `(?i)\bparseur\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("paydirt-api-key", "Paydirt API Key", "high", []string{"paydirt"}, `(?i)\bpaydirt\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("paymo-api-key", "Paymo API Key", "high", []string{"paymo"}, `(?i)\bpaymo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("planview-leankit-api-key", "Planview LeanKit API Key", "high", []string{"planviewleankit", "leankit"}, `(?i)\b(?:planviewleankit|planview[ _-]?leankit|leankit)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("planyo-api-key", "Planyo API Key", "high", []string{"planyo"}, `(?i)\bplanyo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("pollsapi-key", "Polls API Key", "high", []string{"pollsapi", "polls api"}, `(?i)\b(?:pollsapi|polls[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("poloniex-api-secret", "Poloniex API Secret", "critical", []string{"poloniex"}, `(?i)\bpoloniex\b.{0,120}\b(?:api[_-]?secret|secret|private[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,256})\b`, 1, nil),
		NewRegex("postbacks-api-key", "Postbacks API Key", "high", []string{"postbacks"}, `(?i)\bpostbacks\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("powrbot-api-key", "Powrbot API Key", "high", []string{"powrbot"}, `(?i)\bpowrbot\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("privacy-api-key", "Privacy.com API Key", "critical", []string{"privacy.com", "privacy"}, `(?i)\b(?:privacy\.com|privacy)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("prodpad-api-key", "ProdPad API Key", "high", []string{"prodpad"}, `(?i)\bprodpad\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("prospectcrm-api-key", "Prospect CRM API Key", "high", []string{"prospectcrm", "prospect crm"}, `(?i)\b(?:prospectcrm|prospect[ _-]?crm)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("protocolsio-api-token", "Protocols.io API Token", "high", []string{"protocols.io", "protocolsio"}, `(?i)\b(?:protocols\.io|protocolsio)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("purestake-api-key", "PureStake API Key", "critical", []string{"purestake"}, `(?i)\bpurestake\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("qubole-api-token", "Qubole API Token", "critical", []string{"qubole"}, `(?i)\bqubole\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("ramp-api-key", "Ramp API Key", "critical", []string{"ramp"}, `(?i)\bramp\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("raven-api-key", "Raven API Key", "high", []string{"raven"}, `(?i)\braven\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("reachmail-api-key", "ReachMail API Key", "high", []string{"reachmail", "reach mail"}, `(?i)\b(?:reachmail|reach[ _-]?mail)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("reallysimplesystems-api-key", "Really Simple Systems API Key", "high", []string{"reallysimplesystems", "really simple systems"}, `(?i)\b(?:reallysimplesystems|really[ _-]?simple[ _-]?systems)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("refiner-api-key", "Refiner API Key", "high", []string{"refiner"}, `(?i)\brefiner\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("rentman-api-token", "Rentman API Token", "high", []string{"rentman"}, `(?i)\brentman\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("requestfinance-api-key", "Request Finance API Key", "critical", []string{"requestfinance", "request finance"}, `(?i)\b(?:requestfinance|request[ _-]?finance)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("rev-ai-api-key", "Rev.ai API Key", "high", []string{"rev.ai", "rev ai"}, `(?i)\b(?:rev\.ai|rev[ _-]?ai)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("revampcrm-api-key", "Revamp CRM API Key", "high", []string{"revampcrm", "revamp crm"}, `(?i)\b(?:revampcrm|revamp[ _-]?crm)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("ritekit-api-key", "RiteKit API Key", "high", []string{"ritekit"}, `(?i)\britekit\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("roaring-api-key", "Roaring API Key", "high", []string{"roaring"}, `(?i)\broaring\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("robinhoodcrypto-api-secret", "Robinhood Crypto API Secret", "critical", []string{"robinhoodcrypto", "robinhood crypto"}, `(?i)\b(?:robinhoodcrypto|robinhood[ _-]?crypto)\b.{0,120}\b(?:api[_-]?secret|secret|private[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{32,256})\b`, 1, nil),
		NewRegex("rownd-api-key", "Rownd API Key", "critical", []string{"rownd"}, `(?i)\brownd\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("runrunit-api-key", "Runrun.it API Key", "high", []string{"runrun.it", "runrunit"}, `(?i)\b(?:runrun\.it|runrunit)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("salescookie-api-key", "SalesCookie API Key", "high", []string{"salescookie", "sales cookie"}, `(?i)\b(?:salescookie|sales[ _-]?cookie)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("salesmate-api-key", "Salesmate API Key", "high", []string{"salesmate"}, `(?i)\bsalesmate\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("satismeter-project-key", "SatisMeter Project Key", "high", []string{"satismeter", "satis meter"}, `(?i)\b(?:satismeter|satis[ _-]?meter)\b.{0,80}\b(?:project[_-]?key|project[_-]?token|write[_-]?key|api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("satismeter-write-key", "SatisMeter Write Key", "high", []string{"satismeter", "satis meter"}, `(?i)\b(?:satismeter|satis[ _-]?meter)\b.{0,80}\b(?:write[_-]?key|write[_-]?token|api[_-]?key|key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("scalr-api-key", "Scalr API Key", "critical", []string{"scalr"}, `(?i)\bscalr\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("scraperbox-api-key", "ScraperBox API Key", "high", []string{"scraperbox", "scraper box"}, `(?i)\b(?:scraperbox|scraper[ _-]?box)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("scrapingant-api-key", "ScrapingAnt API Key", "high", []string{"scrapingant", "scraping ant"}, `(?i)\b(?:scrapingant|scraping[ _-]?ant)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("serphouse-api-key", "SERPHouse API Key", "high", []string{"serphouse", "serp house"}, `(?i)\b(?:serphouse|serp[ _-]?house)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("sherpadesk-api-key", "SherpaDesk API Key", "high", []string{"sherpadesk", "sherpa desk"}, `(?i)\b(?:sherpadesk|sherpa[ _-]?desk)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("shutterstock-api-token", "Shutterstock API Token", "critical", []string{"shutterstock"}, `(?i)\bshutterstock\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("shutterstock-oauth-client-secret", "Shutterstock OAuth Client Secret", "critical", []string{"shutterstock", "api.shutterstock.com/oauth"}, `(?i)\b(?:shutterstock|api\.shutterstock\.com/oauth)\b[\s\S]{0,240}\b(?:client[_-]?secret|oauth[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._~/-]{32,128})\b`, 1, nil),
		NewRegex("sigopt-api-token", "SigOpt API Token", "critical", []string{"sigopt"}, `(?i)\bsigopt\b.{0,80}\b(?:api[_-]?token|client[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("simfin-api-key", "SimFin API Key", "high", []string{"simfin"}, `(?i)\bsimfin\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("square-app-secret", "Square App Secret", "critical", []string{"square"}, `(?i)\bsquare\b.{0,120}\b(?:app[_-]?secret|client[_-]?secret|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("squarespace-api-key", "Squarespace API Key", "critical", []string{"squarespace"}, `(?i)\bsquarespace\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("stitchdata-api-token", "Stitch Data API Token", "critical", []string{"stitchdata", "stitch data"}, `(?i)\b(?:stitchdata|stitch[ _-]?data)\b.{0,80}\b(?:api[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("supernotes-api-key", "Supernotes API Key", "high", []string{"supernotes"}, `(?i)\bsupernotes\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("surveyanyplace-api-key", "Survey Anyplace API Key", "high", []string{"surveyanyplace", "survey anyplace"}, `(?i)\b(?:surveyanyplace|survey[ _-]?anyplace)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("surveybot-api-key", "Surveybot API Key", "high", []string{"surveybot", "survey bot"}, `(?i)\b(?:surveybot|survey[ _-]?bot)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("surveysparrow-api-key", "SurveySparrow API Key", "high", []string{"surveysparrow", "survey sparrow"}, `(?i)\b(?:surveysparrow|survey[ _-]?sparrow)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("survicate-api-key", "Survicate API Key", "high", []string{"survicate"}, `(?i)\bsurvicate\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("swell-api-key", "Swell API Key", "critical", []string{"swell"}, `(?i)\bswell\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("tallyfy-api-key", "Tallyfy API Key", "high", []string{"tallyfy"}, `(?i)\btallyfy\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("technicalanalysisapi-key", "Technical Analysis API Key", "high", []string{"technicalanalysisapi", "technical analysis api"}, `(?i)\b(?:technicalanalysisapi|technical[ _-]?analysis[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tefter-api-key", "Tefter API Key", "high", []string{"tefter"}, `(?i)\btefter\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("teletype-api-key", "Teletype API Key", "high", []string{"teletype"}, `(?i)\bteletype\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tly-api-key", "T.LY API Key", "high", []string{"t.ly", "tly"}, `(?i)\b(?:t\.ly|tly)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tokeet-api-key", "Tokeet API Key", "high", []string{"tokeet"}, `(?i)\btokeet\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("travelpayouts-api-key", "Travelpayouts API Key", "high", []string{"travelpayouts", "travel payouts"}, `(?i)\b(?:travelpayouts|travel[ _-]?payouts)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("tru-api-key", "tru.ID API Key", "critical", []string{"tru.id", "tru"}, `(?i)\b(?:tru\.id|tru)\b.{0,80}\b(?:api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("twist-api-token", "Twist API Token", "critical", []string{"twist"}, `(?i)\btwist\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("tyntec-api-key", "tyntec API Key", "critical", []string{"tyntec"}, `(?i)\btyntec\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("typetalk-api-token", "Typetalk API Token", "critical", []string{"typetalk"}, `(?i)\btypetalk\b.{0,80}\b(?:api[_-]?token|access[_-]?token|token|api[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("unifyid-api-key", "UnifyID API Key", "critical", []string{"unifyid", "unify id"}, `(?i)\b(?:unifyid|unify[ _-]?id)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("unplugg-api-key", "Unplugg API Key", "high", []string{"unplugg"}, `(?i)\bunplugg\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("upwave-api-key", "Upwave API Key", "high", []string{"upwave"}, `(?i)\bupwave\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("userflow-api-key", "Userflow API Key", "critical", []string{"userflow"}, `(?i)\buserflow\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("verimail-api-key", "Verimail API Key", "high", []string{"verimail"}, `(?i)\bverimail\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("versioneye-api-key", "VersionEye API Key", "high", []string{"versioneye", "version eye"}, `(?i)\b(?:versioneye|version[ _-]?eye)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("viewneo-api-key", "viewneo API Key", "high", []string{"viewneo"}, `(?i)\bviewneo\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("voodoosms-api-key", "VoodooSMS API Key", "critical", []string{"voodoosms", "voodoo sms"}, `(?i)\b(?:voodoosms|voodoo[ _-]?sms)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("vouchery-api-key", "Vouchery API Key", "high", []string{"vouchery"}, `(?i)\bvouchery\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("vyte-api-key", "Vyte API Key", "high", []string{"vyte"}, `(?i)\bvyte\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("webscraper-api-key", "WebScraper API Key", "high", []string{"webscraper", "web scraper"}, `(?i)\b(?:webscraper|web[ _-]?scraper)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("webscraping-api-key", "WebScraping API Key", "high", []string{"webscraping", "web scraping"}, `(?i)\b(?:webscraping|web[ _-]?scraping)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("worksnaps-api-key", "Worksnaps API Key", "high", []string{"worksnaps"}, `(?i)\bworksnaps\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("workstack-api-key", "Workstack API Key", "high", []string{"workstack"}, `(?i)\bworkstack\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("yousign-api-key", "Yousign API Key", "critical", []string{"yousign"}, `(?i)\byousign\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("zenkit-api-key", "Zenkit API Key", "high", []string{"zenkit"}, `(?i)\bzenkit\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zipapi-key", "Zip API Key", "high", []string{"zipapi", "zip api"}, `(?i)\b(?:zipapi|zip[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zipbooks-api-key", "ZipBooks API Key", "high", []string{"zipbooks", "zip books"}, `(?i)\b(?:zipbooks|zip[ _-]?books)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zipcodeapi-key", "ZipCodeAPI Key", "high", []string{"zipcodeapi", "zipcode api", "zip code api"}, `(?i)\b(?:zipcodeapi|zipcode[ _-]?api|zip[ _-]?code[ _-]?api)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zonkafeedback-api-key", "Zonka Feedback API Key", "high", []string{"zonkafeedback", "zonka feedback"}, `(?i)\b(?:zonkafeedback|zonka[ _-]?feedback)\b.{0,80}\b(?:api[_-]?key|key|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,128})\b`, 1, nil),
		NewRegex("zulipchat-api-key", "Zulip Chat API Key", "critical", []string{"zulipchat", "zulip chat", "zulip"}, `(?i)\b(?:zulipchat|zulip[ _-]?chat|zulip)\b.{0,80}\b(?:api[_-]?key|key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9._-]{32,256})\b`, 1, nil),
		NewRegex("vercel-token", "Vercel Token", "critical", []string{"vercel", "VERCEL_TOKEN"}, `(?i)\bvercel.{0,40}['\"\s:=]+([A-Za-z0-9_-]{24,64})\b`, 1, nil),
		NewRegex("railway-token", "Railway Token", "critical", []string{"railway"}, `(?i)\brailway.{0,40}['\"\s:=]+([A-Za-z0-9_-]{24,64})\b`, 1, nil),
		NewRegex("travisci-token", "Travis CI Token", "high", []string{"travis", "TRAVIS_TOKEN"}, `(?i)\btravis(?:ci)?.{0,40}['\"\s:=]+([A-Za-z0-9]{22})\b`, 1, nil),
		NewRegex("betterstack-api-key", "BetterStack API Key", "high", []string{"betterstack", "better uptime"}, `(?i)\b(?:betterstack|better[ _-]?uptime).{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("customerio-api-key", "Customer.io API Key", "high", []string{"customer.io", "customerio"}, `(?i)\b(?:customer\.io|customerio).{0,40}['\"\s:=]+([A-Za-z0-9]{20,64})\b`, 1, nil),
		NewRegex("trello-api-key", "Trello API Key", "high", []string{"trello"}, `(?i)\btrello.{0,40}['\"\s:=]+([0-9a-f]{32})\b`, 1, nil),
		NewRegex("helpscout-api-key", "Help Scout API Key", "high", []string{"helpscout", "help scout"}, `(?i)\b(?:helpscout|help[ _-]?scout).{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("mailerlite-api-key", "MailerLite API Key", "high", []string{"mailerlite", "mailer lite"}, `(?i)\b(?:mailerlite|mailer[ _-]?lite).{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("mandrill-api-key", "Mandrill API Key", "high", []string{"mandrill"}, `(?i)\bmandrill.{0,40}['\"\s:=]+([A-Za-z0-9_-]{20,40})\b`, 1, nil),
		NewRegex("onesignal-api-key", "OneSignal API Key", "high", []string{"onesignal", "one signal"}, `(?i)\b(?:onesignal|one[ _-]?signal).{0,80}['\"\s:=]+([A-Za-z0-9_-]{48})\b`, 1, nil),
		NewRegex("copper-api-key", "Copper API Key", "high", []string{"copper"}, `(?i)\bcopper.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("capsulecrm-api-key", "Capsule CRM API Key", "high", []string{"capsule"}, `(?i)\bcapsule(?:crm)?.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("apollo-api-key", "Apollo API Key", "high", []string{"apollo"}, `(?i)\bapollo.{0,40}['\"\s:=]+([A-Za-z0-9_-]{32,80})\b`, 1, nil),
		NewRegex("lemlist-api-key", "Lemlist API Key", "high", []string{"lemlist"}, `(?i)\blemlist.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("getresponse-api-key", "GetResponse API Key", "high", []string{"getresponse", "get response"}, `(?i)\b(?:getresponse|get[ _-]?response).{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("alienvault-otx-api-key", "AlienVault OTX API Key", "high", []string{"alienvault", "otx"}, `(?i)\b(?:alienvault|otx).{0,40}['\"\s:=]+([a-f0-9]{64})\b`, 1, nil),
		NewRegex("censys-api-key", "Censys API Key", "high", []string{"censys"}, `(?i)\bcensys.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("vpnapi-key", "VPNAPI.io API Key", "high", []string{"vpnapi"}, `(?i)\bvpnapi(?:\.io)?.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("ipqualityscore-api-key", "IPQualityScore API Key", "high", []string{"ipqualityscore", "ipquality"}, `(?i)\b(?:ipqualityscore|ipquality).{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("ipstack-api-key", "IPstack API Key", "high", []string{"ipstack"}, `(?i)\bipstack.{0,40}['\"\s:=]+([a-f0-9]{32})\b`, 1, nil),
		NewRegex("ipgeolocation-api-key", "IPGeolocation API Key", "high", []string{"ipgeolocation"}, `(?i)\bipgeolocation.{0,40}['\"\s:=]+([a-f0-9]{32})\b`, 1, nil),
		NewRegex("zerotier-api-token", "ZeroTier API Token", "high", []string{"zerotier", "zero tier"}, `(?i)\b(?:zerotier|zero[ _-]?tier).{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("logzio-token", "Logz.io Token", "high", []string{"logz.io", "logzio"}, `(?i)\b(?:logz\.io|logzio).{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("codeclimate-token", "Code Climate Token", "high", []string{"codeclimate", "code climate"}, `(?i)\b(?:codeclimate|code[ _-]?climate).{0,40}['\"\s:=]+([a-f0-9]{64})\b`, 1, nil),
		NewRegex("codacy-api-token", "Codacy API Token", "high", []string{"codacy"}, `(?i)\bcodacy.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("coveralls-repo-token", "Coveralls Repo Token", "high", []string{"coveralls"}, `(?i)\bcoveralls.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("weatherstack-api-key", "Weatherstack API Key", "high", []string{"weatherstack"}, `(?i)\bweatherstack.{0,40}['\"\s:=]+([a-f0-9]{32})\b`, 1, nil),
		NewRegex("accuweather-api-key", "AccuWeather API Key", "high", []string{"accuweather"}, `(?i)\baccuweather.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("weatherbit-api-key", "Weatherbit API Key", "high", []string{"weatherbit"}, `(?i)\bweatherbit.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("mapquest-api-key", "MapQuest API Key", "high", []string{"mapquest"}, `(?i)\bmapquest.{0,40}['\"\s:=]+([A-Za-z0-9]{32})\b`, 1, nil),
		NewRegex("aiven-token", "Aiven Token", "high", []string{"aiven"}, `(?i)\baiven.{0,40}['\"\s:=]+([A-Za-z0-9/+=]{372})`, 1, nil),
		NewRegex("abuseipdb-api-key", "AbuseIPDB API Key", "high", []string{"abuseipdb"}, `(?i)\babuseipdb.{0,40}['\"\s:=]+([a-z0-9]{80})\b`, 1, nil),
		NewRegex("sonarcloud-token", "SonarCloud Token", "high", []string{"sonar", "SONAR_TOKEN"}, `(?i)\bsonar(?:cloud)?.{0,40}['\"\s:=]+([0-9a-z]{40})\b`, 1, nil),
		NewRegex("jumpcloud-api-key", "JumpCloud API Key", "high", []string{"jumpcloud"}, `(?i)\bjumpcloud.{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("pipedrive-api-token", "Pipedrive API Token", "high", []string{"pipedrive"}, `(?i)\bpipedrive.{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("sparkpost-api-key", "SparkPost API Key", "high", []string{"sparkpost"}, `(?i)\bsparkpost.{0,40}['\"\s:=]+([A-Za-z0-9]{40})\b`, 1, nil),
		NewRegex("dropbox-token", "Dropbox Token", "critical", []string{"sl.", "dropbox"}, `\b(sl\.(?:u\.)?[A-Za-z0-9_-]{130,})\b`, 1, nil),
		NewRegex("readme-api-key", "ReadMe API Key", "critical", []string{"rdme_"}, `\b(rdme_[a-z0-9]{70})\b`, 1, nil),
		NewRegex("rootly-api-key", "Rootly API Key", "critical", []string{"rootly_"}, `\b(rootly_[a-f0-9]{64})\b`, 1, nil),
		NewRegex("web3storage-token", "Web3 Storage Token", "critical", []string{"web3", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}, `\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]{25,100})\b`, 1, nil),
		NewRegex("stripe-payment-intent-client-secret", "Stripe PaymentIntent Client Secret", "high", []string{"pi_", "_secret_", "stripe"}, `\b(pi_[A-Za-z0-9]{24}_secret_[A-Za-z0-9]{25})\b`, 1, nil),
		NewRegex("checkout-secret-key", "Checkout.com Secret Key", "critical", []string{"checkout", "sk_test_", "sk_"}, `(?i)\bcheckout\b[\s\S]{0,120}\b((?:sk_|sk_test_)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("aha-api-key", "Aha API Key", "high", []string{".aha.io"}, `(?i)\b[a-z0-9-]+\.aha\.io\b[\s\S]{0,200}\b([a-f0-9]{64})\b`, 1, nil),
		NewRegex("larksuite-app-secret", "LarkSuite App Secret", "high", []string{"lark", "larksuite", "cli_"}, `(?i)\b(cli_[A-Za-z0-9]{16})\b[\s\S]{0,160}\b([A-Za-z0-9]{32})\b`, 2, nil),
		NewRegex("jwt", "JSON Web Token", "medium", []string{"eyJ"}, `\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`, 1, nil),
		NewRegex("private-key", "Private Key", "critical", []string{"BEGIN", "PRIVATE KEY"}, `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`, 0, nil),
		NewRegex("ssh-private-key", "SSH Private Key", "critical", []string{"OPENSSH PRIVATE KEY", "RSA PRIVATE KEY"}, `-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----[\s\S]+?-----END (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----`, 0, nil),
		NewRegex("basic-auth-url", "Basic Auth URL", "high", []string{"://"}, `\b[a-z][a-z0-9+.-]*://[^\s:/?#]+:([^\s@/?#]{8,})@[^\s]+`, 1, nil),
		NewRegex("generic-assigned-secret", "Assigned Secret", "medium", []string{"password", "passwd", "secret", "token", "api_key", "apikey"}, `(?i)\b(password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{16,})`, 2, nil),
	}
}

func ToFinding(c Candidate, file, commit string, b []byte, verify bool) Finding {
	line, col := lineColumn(b, c.Start)
	f := Finding{DetectorID: c.DetectorID, Name: c.Name, Severity: c.Severity, File: file, Commit: commit, Line: line, Column: col, Secret: c.Secret, Redacted: Redact(c.Secret)}
	h := sha256.Sum256([]byte(c.DetectorID + "\x00" + c.Secret + "\x00" + file + "\x00" + commit))
	f.Fingerprint = hex.EncodeToString(h[:])
	if verify && c.Verifier != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		f.Verified = c.Verifier(ctx, c.Secret)
	}
	return f
}

func Redact(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func plausibleSecret(s string) bool {
	if len(strings.TrimSpace(s)) < 8 {
		return false
	}
	if strings.Count(s, "0") == len(s) || strings.Count(s, "x") == len(s) {
		return false
	}
	if looksLikeVariableReference(s) {
		return false
	}
	if looksLikeRegexFragment(s) {
		return false
	}
	return true
}

var variableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)

func looksLikeVariableReference(s string) bool {
	t := strings.Trim(strings.TrimSpace(s), `'"`)
	if len(t) < 2 {
		return false
	}

	if strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}") {
		return true
	}
	if strings.HasPrefix(t, "%{") && strings.HasSuffix(t, "}") {
		return true
	}
	if strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") {
		return true
	}
	if strings.HasPrefix(t, "$(") && strings.HasSuffix(t, ")") {
		return true
	}
	if strings.HasPrefix(t, "$") && variableNamePattern.MatchString(strings.TrimPrefix(t, "$")) {
		return true
	}

	if !variableNamePattern.MatchString(t) {
		return false
	}
	if !strings.Contains(t, "_") && t != strings.ToUpper(t) {
		return false
	}
	for _, part := range strings.FieldsFunc(t, func(r rune) bool { return r == '_' || r == '.' }) {
		if len(part) >= 12 {
			return false
		}
	}

	lower := strings.ToLower(t)
	variableTerms := []string{"api", "key", "secret", "token", "password", "passwd", "pwd", "credential", "credentials", "client"}
	for _, term := range variableTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func looksLikeRegexFragment(s string) bool {
	return strings.Contains(s, `[^`) || strings.Contains(s, `\s`) || strings.Contains(s, `\w`) || strings.Contains(s, `(?:`) || strings.Contains(s, `(?i)`)
}

func lineColumn(b []byte, pos int) (int, int) {
	line, col := 1, 1
	for i := 0; i < len(b) && i < pos; i++ {
		if b[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

type customFile struct {
	Detectors []customDetector `json:"detectors"`
}
type customDetector struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Keywords    []string `json:"keywords"`
	Regex       string   `json:"regex"`
	SecretGroup int      `json:"secret_group"`
}

func LoadCustomFile(path string) ([]Detector, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf customFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, err
	}
	out := make([]Detector, 0, len(cf.Detectors))
	for _, d := range cf.Detectors {
		if d.ID == "" || d.Regex == "" {
			return nil, errors.New("custom detector requires id and regex")
		}
		name := d.Name
		if name == "" {
			name = d.ID
		}
		sev := d.Severity
		if sev == "" {
			sev = "medium"
		}
		out = append(out, NewRegex(d.ID, name, sev, d.Keywords, d.Regex, d.SecretGroup, nil))
	}
	return out, nil
}

func verifyGitHub(ctx context.Context, token string) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func verifyOpenAI(ctx context.Context, token string) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.openai.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
