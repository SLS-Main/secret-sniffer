package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRegistryFindsGitHubToken(t *testing.T) {
	input := []byte("token := \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"")
	var found bool
	for _, d := range DefaultRegistry() {
		for _, c := range d.Detect(input) {
			if c.DetectorID == "github-token" {
				found = true
				if c.Secret != "ghp_abcdefghijklmnopqrstuvwxyz0123456789" {
					t.Fatalf("unexpected secret: %q", c.Secret)
				}
			}
		}
	}
	if !found {
		t.Fatal("expected github-token finding")
	}
}

func TestDefaultRegistryFindsExpandedParityTokens(t *testing.T) {
	cases := []struct {
		id     string
		input  string
		secret string
	}{
		{"azure-devops-pat", strings.Repeat("a", 75) + "AZDO" + strings.Repeat("b", 5), strings.Repeat("a", 75) + "AZDO" + strings.Repeat("b", 5)},
		{"terraform-cloud-token", strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("A", 67), strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("A", 67)},
		{"netlify-token", "nfp_" + strings.Repeat("A", 40), "nfp_" + strings.Repeat("A", 40)},
		{"pulumi-token", "pul-" + strings.Repeat("a", 40), "pul-" + strings.Repeat("a", 40)},
		{"doppler-token", "dp.st." + strings.Repeat("A", 40), "dp.st." + strings.Repeat("A", 40)},
		{"tailscale-key", "tskey-api-" + strings.Repeat("A", 32), "tskey-api-" + strings.Repeat("A", 32)},
		{"ngrok-token", "ngrok_api_" + strings.Repeat("A", 32), "ngrok_api_" + strings.Repeat("A", 32)},
		{"buildkite-token", "bkua_" + strings.Repeat("a", 40), "bkua_" + strings.Repeat("a", 40)},
		{"nuget-api-key", "oy2" + strings.Repeat("a", 43), "oy2" + strings.Repeat("a", 43)},
		{"rubygems-api-key", "rubygems_" + strings.Repeat("a", 48), "rubygems_" + strings.Repeat("a", 48)},
		{"slack-webhook", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvw", "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvw"},
		{"discord-webhook", "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("A", 68), "https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("A", 68)},
		{"microsoft-teams-webhook", "https://example.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/IncomingWebhook/0123456789abcdef0123456789abcdef/99999999-8888-7777-6666-555555555555", "https://example.webhook.office.com/webhookb2/11111111-2222-3333-4444-555555555555@aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/IncomingWebhook/0123456789abcdef0123456789abcdef/99999999-8888-7777-6666-555555555555"},
		{"grafana-token", "glc_eyJ" + strings.Repeat("A", 80), "glc_eyJ" + strings.Repeat("A", 80)},
		{"grafana-service-account-token", "glsa_" + strings.Repeat("A", 41), "glsa_" + strings.Repeat("A", 41)},
		{"sentry-user-token", "sntryu_" + strings.Repeat("a", 64), "sntryu_" + strings.Repeat("a", 64)},
		{"sentry-org-token", "sntrys_eyJ" + strings.Repeat("A", 197), "sntrys_eyJ" + strings.Repeat("A", 197)},
		{"honeycomb-api-key", "HONEYCOMB_API_KEY=" + strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{"opsgenie-api-key", "OPSGENIE_API_KEY=123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
		{"splunk-observability-token", "X-Sf-Token: AbCdEfGhIjKlMnOpQrSt12", "AbCdEfGhIjKlMnOpQrSt12"},
		{"webex-bot-token", "webex " + strings.Repeat("A", 64) + "_AB12_12345678-1234-1234-1234-123456789abc", strings.Repeat("A", 64) + "_AB12_12345678-1234-1234-1234-123456789abc"},
		{"huggingface-token", "hf_" + strings.Repeat("A", 34), "hf_" + strings.Repeat("A", 34)},
		{"groq-api-key", "gsk_" + strings.Repeat("A", 52), "gsk_" + strings.Repeat("A", 52)},
		{"replicate-token", "r8_" + strings.Repeat("A", 40), "r8_" + strings.Repeat("A", 40)},
		{"airtable-pat", "patAbC123dEf4567X." + strings.Repeat("a", 64), "patAbC123dEf4567X." + strings.Repeat("a", 64)},
		{"asana-pat", "asana 123/1234567890123456/9876543210987654:abcdefghijklmnopqrstuvwxyzABCDEF123456", "123/1234567890123456/9876543210987654:abcdefghijklmnopqrstuvwxyzABCDEF123456"},
		{"clickup-token", "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "pk_1234567_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
		{"typeform-token", "tfp_" + strings.Repeat("A", 44), "tfp_" + strings.Repeat("A", 44)},
		{"hubspot-private-app-token", "pat-na1-12345678-1234-1234-1234-123456789abc", "pat-na1-12345678-1234-1234-1234-123456789abc"},
		{"mailchimp-key", strings.Repeat("a", 32) + "-us12", strings.Repeat("a", 32) + "-us12"},
		{"klaviyo-key", "klaviyo pk_" + strings.Repeat("a", 34), "pk_" + strings.Repeat("a", 34)},
		{"razorpay-key", "rzp_live_AbCdEf12345678", "rzp_live_AbCdEf12345678"},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			if !registryFinds(tc.id, tc.input, tc.secret) {
				t.Fatalf("expected %s to find %q in %q", tc.id, tc.secret, tc.input)
			}
		})
	}
}

func registryFinds(id, input, secret string) bool {
	for _, d := range DefaultRegistry() {
		for _, c := range d.Detect([]byte(input)) {
			if c.DetectorID == id && c.Secret == secret {
				return true
			}
		}
	}
	return false
}

func TestRedact(t *testing.T) {
	got := Redact("abcdefghijklmnop")
	if got != "abcd********mnop" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestPlausibleSecretRejectsRegexFragments(t *testing.T) {
	if plausibleSecret(`[^\s*\"]+`) {
		t.Fatal("expected regex fragment to be rejected")
	}
}

func TestLoadCustomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.json")
	err := os.WriteFile(path, []byte(`{
		"detectors": [{
			"id": "internal",
			"name": "Internal",
			"keywords": ["internal_key"],
			"regex": "internal_key=([a-z0-9]{16})",
			"secret_group": 1
		}]
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	ds, err := LoadCustomFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 {
		t.Fatalf("expected one detector, got %d", len(ds))
	}
	candidates := ds[0].Detect([]byte("internal_key=abcdefghijklmnop"))
	if len(candidates) != 1 || candidates[0].Secret != "abcdefghijklmnop" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestRegistryInfo(t *testing.T) {
	infos := RegistryInfo(DefaultRegistry())
	if len(infos) == 0 {
		t.Fatal("expected detector info")
	}
	if infos[0].ID == "" || infos[0].Name == "" || infos[0].Severity == "" {
		t.Fatalf("incomplete detector info: %#v", infos[0])
	}
}
