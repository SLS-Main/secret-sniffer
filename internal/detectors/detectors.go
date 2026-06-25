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
		NewRegex("elastic-email-api-key", "Elastic Email API Key", "critical", []string{"elasticemail", "elastic email"}, `(?i)\b(?:elasticemail|elastic[ _-]?email).{0,40}['\"\s:=]+([A-Za-z0-9_-]{96})\b`, 1, nil),
		NewRegex("shortcut-api-token", "Shortcut API Token", "high", []string{"shortcut"}, `(?i)\bshortcut.{0,40}['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("webflow-api-key", "Webflow API Key", "high", []string{"webflow"}, `(?i)\bwebflow.{0,40}['\"\s:=]+([A-Za-z0-9]{64})\b`, 1, nil),
		NewRegex("mapbox-secret-token", "Mapbox Secret Token", "critical", []string{"sk.", "mapbox"}, `\b(sk\.[A-Za-z0-9.-]{80,240})\b`, 1, nil),
		NewRegex("locationiq-api-key", "LocationIQ API Key", "high", []string{"locationiq", "pk."}, `\b(pk\.[A-Za-z0-9-]{32})\b`, 1, nil),
		NewRegex("coinapi-key", "CoinAPI Key", "high", []string{"coinapi", "X-CoinAPI-Key"}, `\b([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})\b`, 1, nil),
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
		NewRegex("cloudinary-url", "Cloudinary URL", "critical", []string{"cloudinary://"}, `\b(cloudinary://[0-9]{15}:[A-Za-z0-9_-]{27}@[A-Za-z0-9_-]{3,64})\b`, 1, nil),
		NewRegex("zendesk-api-token", "Zendesk API Token", "high", []string{"zendesk.com", "zendesk"}, `(?i)\b[a-z0-9-]{3,25}\.zendesk\.com\b[\s\S]{0,200}\b(?:zendesk|api[_-]?token|token)[A-Za-z0-9_-]*[\s\S]{0,60}\b([A-Za-z0-9_-]{40})\b`, 1, nil),
		NewRegex("freshdesk-api-key", "Freshdesk API Key", "high", []string{"freshdesk.com", "freshdesk"}, `(?i)\b[a-z0-9-]+\.freshdesk\.com\b[\s\S]{0,200}\b(?:freshdesk|api[_-]?key|token)[A-Za-z0-9_-]*[\s\S]{0,60}\b([0-9A-Za-z]{20})\b`, 1, nil),
		NewRegex("helpcrunch-api-key", "HelpCrunch API Key", "high", []string{"helpcrunch"}, `(?i)\bhelpcrunch[A-Za-z0-9_-]*.{0,80}\b([A-Za-z0-9+/=-]{328})\b`, 1, nil),
		NewRegex("line-messaging-token", "LINE Messaging Token", "critical", []string{"line_messaging", "LINE_MESSAGING"}, `(?i)\bline[_ -]?messaging[A-Za-z0-9_-]*.{0,100}\b([A-Za-z0-9+/]{171,172})\b`, 1, nil),
		NewRegex("courier-api-key", "Courier API Key", "critical", []string{"courier", "pk_"}, `(?i)\bcourier[A-Za-z0-9_-]*.{0,80}\b(pk_[A-Za-z0-9]+_[A-Za-z0-9]{28})\b`, 1, nil),
		NewRegex("hashicorp-vault-approle", "HashiCorp Vault AppRole Secret ID", "high", []string{"vault", "role_id", "secret_id"}, `(?i)\brole[_-]?id\b.{0,80}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b[\s\S]{0,200}\bsecret[_-]?id\b.{0,80}\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, 1, nil),
		NewRegex("mattermost-personal-token", "Mattermost Personal Token", "high", []string{"mattermost", "cloud.mattermost.com"}, `(?i)\bmattermost\b[\s\S]{0,160}\b([a-z0-9]{26})\b[\s\S]{0,160}\b[A-Za-z0-9-_]+\.cloud\.mattermost\.com\b`, 1, nil),
		NewRegex("cloudflare-global-api-key", "Cloudflare Global API Key", "critical", []string{"cloudflare", "global_api_key"}, `(?i)\bcloudflare.{0,80}global[_ -]?api[_ -]?key.{0,20}['\"\s:=]+([a-f0-9]{37})\b`, 1, nil),
		NewRegex("docker-auth-config", "Docker Auth Config", "critical", []string{"\"auths\"", "\"auth\""}, `(?s)("auths"\s*:\s*\{[^}]+"auth"\s*:\s*"[A-Za-z0-9+/]{20,}={0,2}")`, 1, nil),
		NewRegex("azure-search-key", "Azure Search Key", "critical", []string{".search.windows.net", "api-key"}, `(?i)\b[a-z0-9-]+\.search\.windows\.net\b[\s\S]{0,160}\bapi-key\b\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{52})\b`, 1, nil),
		NewRegex("azure-apim-subscription-key", "Azure API Management Subscription Key", "critical", []string{"ocp-apim-subscription-key"}, `(?i)\bocp-apim-subscription-key\b\s*[:=]\s*['\"]?([a-f0-9]{32})\b`, 1, nil),
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
