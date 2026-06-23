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
		NewRegex("sendgrid-key", "SendGrid API Key", "critical", []string{"SG."}, `\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("twilio-key", "Twilio API Key", "high", []string{"SK", "twilio"}, `\b(SK[0-9a-fA-F]{32})\b`, 1, nil),
		NewRegex("mailgun-key", "Mailgun API Key", "high", []string{"key-", "mailgun"}, `\b(key-[0-9a-fA-F]{32})\b`, 1, nil),
		NewRegex("gitlab-token", "GitLab Token", "critical", []string{"glpat-", "gldt-"}, `\b((?:glpat|gldt)-[A-Za-z0-9_-]{20,128})\b`, 1, nil),
		NewRegex("bitbucket-app-password", "Bitbucket App Password", "high", []string{"bitbucket", "ATBB"}, `\b(ATBB[a-zA-Z0-9_-]{20,80})\b`, 1, nil),
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
		NewRegex("shopify-token", "Shopify Token", "high", []string{"shpat_", "shpca_", "shppa_", "shpss_"}, `\b(shp(?:at|ca|pa|ss)_[A-Za-z0-9]{32})\b`, 1, nil),
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
		NewRegex("voiceflow-api-key", "Voiceflow API Key", "critical", []string{"VF.", "voiceflow"}, `\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[A-Za-z0-9]{16})\b`, 1, nil),
		NewRegex("harness-pat", "Harness Personal Access Token", "critical", []string{"harness"}, `\b(pat\.[A-Za-z0-9]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20})\b`, 1, nil),
		NewRegex("zoho-crm-token", "Zoho CRM Token", "critical", []string{"1000.", "zoho"}, `\b(1000\.[a-f0-9]{32}\.[a-f0-9]{32})\b`, 1, nil),
		NewRegex("intercom-access-token", "Intercom Access Token", "critical", []string{"intercom", "dG9rO"}, `(?i)\bintercom.{0,40}['\"\s:=]+(dG9rO[A-Za-z0-9+/]{54}=)`, 1, nil),
		NewRegex("front-api-token", "Front API Token", "critical", []string{"front", "frontapp"}, `(?i)\bfront.{0,40}['\"\s:=]+([0-9A-Za-z]{36}\.[0-9A-Za-z._-]{188,244})\b`, 1, nil),
		NewRegex("segment-api-key", "Segment API Key", "high", []string{"segment"}, `(?i)\bsegment.{0,40}['\"\s:=]+([A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43})\b`, 1, nil),
		NewRegex("posthog-personal-api-key", "PostHog Personal API Key", "critical", []string{"phx_", "posthog"}, `\b(phx_[A-Za-z0-9_]{43})\b`, 1, nil),
		NewRegex("launchdarkly-key", "LaunchDarkly Key", "critical", []string{"api-", "sdk-", "launchdarkly"}, `\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`, 1, nil),
		NewRegex("postmark-token", "Postmark Server Token", "high", []string{"postmark"}, `(?i)\bpostmark.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("coda-api-token", "Coda API Token", "high", []string{"coda"}, `(?i)\bcoda.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("calendly-api-key", "Calendly API Key", "high", []string{"calendly"}, `(?i)\bcalendly.{0,40}['\"\s:=]+(eyJ[A-Za-z0-9_-]{100,300}\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]+)\b`, 1, nil),
		NewRegex("monday-api-token", "Monday.com API Token", "high", []string{"monday"}, `(?i)\bmonday.{0,40}['\"\s:=]+(eyJ[A-Za-z0-9_-]{15,100}\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]{25,100})\b`, 1, nil),
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
	if looksLikeRegexFragment(s) {
		return false
	}
	return true
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
