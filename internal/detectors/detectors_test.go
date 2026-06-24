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
		{"nightfall-api-key", "NF-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6", "NF-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"},
		{"endorlabs-token", "endr+AbCdEfGhIjKlMn12", "endr+AbCdEfGhIjKlMn12"},
		{"trufflehog-enterprise-key", "thog-key-0123456789abcdef", "thog-key-0123456789abcdef"},
		{"trufflehog-enterprise-secret", "thog-secret-0123456789abcdef0123456789abcdef", "thog-secret-0123456789abcdef0123456789abcdef"},
		{"tines-webhook", "https://acme.tines.com/webhook/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210", "https://acme.tines.com/webhook/0123456789abcdef0123456789abcdef/fedcba9876543210fedcba9876543210"},
		{"pinecone-api-key", "pcsk_abc12_" + strings.Repeat("A", 63), "pcsk_abc12_" + strings.Repeat("A", 63)},
		{"langsmith-api-key", "lsv2_pt_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 10), "lsv2_pt_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 10)},
		{"langfuse-secret-key", "sk-lf-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "sk-lf-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"elevenlabs-api-key", "elevenlabs sk_" + strings.Repeat("a", 48), "sk_" + strings.Repeat("a", 48)},
		{"xai-api-key", "xai-" + strings.Repeat("A", 80), "xai-" + strings.Repeat("A", 80)},
		{"voiceflow-api-key", "VF.DM." + strings.Repeat("a", 24) + "." + strings.Repeat("A", 16), "VF.DM." + strings.Repeat("a", 24) + "." + strings.Repeat("A", 16)},
		{"harness-pat", "harness pat." + strings.Repeat("A", 22) + "." + strings.Repeat("a", 24) + "." + strings.Repeat("B", 20), "pat." + strings.Repeat("A", 22) + "." + strings.Repeat("a", 24) + "." + strings.Repeat("B", 20)},
		{"zoho-crm-token", "1000." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32), "1000." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)},
		{"intercom-access-token", "intercom_token=\"dG9rO" + strings.Repeat("A", 54) + "=\"", "dG9rO" + strings.Repeat("A", 54) + "="},
		{"front-api-token", "front_token=\"" + strings.Repeat("A", 36) + "." + strings.Repeat("B", 188) + "\"", strings.Repeat("A", 36) + "." + strings.Repeat("B", 188)},
		{"segment-api-key", "segment_key=\"" + strings.Repeat("A", 43) + "." + strings.Repeat("B", 43) + "\"", strings.Repeat("A", 43) + "." + strings.Repeat("B", 43)},
		{"posthog-personal-api-key", "phx_" + strings.Repeat("A", 43), "phx_" + strings.Repeat("A", 43)},
		{"launchdarkly-key", "api-123e4567-e89b-42d3-a456-426614174000", "api-123e4567-e89b-42d3-a456-426614174000"},
		{"postmark-token", "postmark_token=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"coda-api-token", "coda_api_key=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"calendly-api-key", "calendly_token=\"eyJ" + strings.Repeat("A", 120) + ".eyJ" + strings.Repeat("B", 120) + "." + strings.Repeat("C", 40) + "\"", "eyJ" + strings.Repeat("A", 120) + ".eyJ" + strings.Repeat("B", 120) + "." + strings.Repeat("C", 40)},
		{"monday-api-token", "monday_token=\"eyJ" + strings.Repeat("A", 30) + ".eyJ" + strings.Repeat("B", 150) + "." + strings.Repeat("C", 40) + "\"", "eyJ" + strings.Repeat("A", 30) + ".eyJ" + strings.Repeat("B", 150) + "." + strings.Repeat("C", 40)},
		{"flyio-token", "FlyV1 fm1_" + strings.Repeat("A", 520), "FlyV1 fm1_" + strings.Repeat("A", 520)},
		{"cloudflare-ca-key", "cloudflare v1.0-" + strings.Repeat("A", 171), "v1.0-" + strings.Repeat("A", 171)},
		{"artifactory-access-token", "AKCp" + strings.Repeat("A", 69), "AKCp" + strings.Repeat("A", 69)},
		{"artifactory-reference-token", "cmVmdGtu" + strings.Repeat("A", 56), "cmVmdGtu" + strings.Repeat("A", 56)},
		{"azure-app-config-connection-string", "Endpoint=https://demo-app.azconfig.io;Id=AbCdEfGhIjKlMnOpQrStUv==;Secret=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==", "Endpoint=https://demo-app.azconfig.io;Id=AbCdEfGhIjKlMnOpQrStUv==;Secret=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=="},
		{"azure-storage-connection-string", "DefaultEndpointsProtocol=https;AccountName=prodstorageacct;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net", "DefaultEndpointsProtocol=https;AccountName=prodstorageacct;AccountKey=" + strings.Repeat("A", 86) + "==;EndpointSuffix=core.windows.net"},
		{"azure-cosmosdb-connection-string", "AccountEndpoint=https://prod-cosmos.documents.azure.com:443/;AccountKey=" + strings.Repeat("A", 86) + "==;", "AccountEndpoint=https://prod-cosmos.documents.azure.com:443/;AccountKey=" + strings.Repeat("A", 86) + "==;"},
		{"azure-sas-url", "https://prodstorage.blob.core.windows.net/container/blob.txt?sp=r&st=2026-01-01T00:00:00Z&se=2026-12-31T23:59:59Z&spr=https&sv=2024-01-01&sr=b&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2B", "https://prodstorage.blob.core.windows.net/container/blob.txt?sp=r&st=2026-01-01T00:00:00Z&se=2026-12-31T23:59:59Z&spr=https&sv=2024-01-01&sr=b&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%2B"},
		{"azure-function-key-url", "https://demo-func.azurewebsites.net/api/process?code=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-"},
		{"spectralops-token", "spu-a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6", "spu-a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6"},
		{"atlassian-api-token", "ATCTT3xFfG" + strings.Repeat("A", 64) + "=12345678", "ATCTT3xFfG" + strings.Repeat("A", 64) + "=12345678"},
		{"jira-api-token", "ATATT" + strings.Repeat("A", 64) + "=12345678", "ATATT" + strings.Repeat("A", 64) + "=12345678"},
		{"salesforce-access-token", "salesforce 00D000000000001!" + strings.Repeat("A", 96), "00D000000000001!" + strings.Repeat("A", 96)},
		{"salesforce-refresh-token", "5AEP861" + strings.Repeat("A", 80), "5AEP861" + strings.Repeat("A", 80)},
		{"salesforce-consumer-key", "3MVG9" + strings.Repeat("A", 80), "3MVG9" + strings.Repeat("A", 80)},
		{"twilio-auth-token", "AC0123456789abcdef0123456789abcdef auth_token=\"0123456789abcdef0123456789abcdef\"", "0123456789abcdef0123456789abcdef"},
		{"mailjet-basic-auth", "mailjet basic auth " + strings.Repeat("A", 87) + "=", strings.Repeat("A", 87) + "="},
		{"okta-api-token", "tenant.okta.com token = 00abcdefghijklmnopqrstuvwxyz0123456789ABCD", "00abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"urlscan-api-key", "urlscan api_key = 123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-426614174000"},
		{"openai-admin-key", "sk-admin-" + strings.Repeat("A", 58) + "T3BlbkFJ" + strings.Repeat("B", 58), "sk-admin-" + strings.Repeat("A", 58) + "T3BlbkFJ" + strings.Repeat("B", 58)},
		{"deepseek-api-key", "DEEPSEEK_API_KEY=\"sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\"", "sk-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
		{"weightsandbiases-api-key", "WANDB_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"assemblyai-api-key", "ASSEMBLYAI_API_KEY=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"deepgram-api-key", "DEEPGRAM_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"edenai-api-key", "EDENAI_API_KEY=\"" + strings.Repeat("A", 36) + "." + strings.Repeat("B", 92) + "." + strings.Repeat("C", 43) + "\"", strings.Repeat("A", 36) + "." + strings.Repeat("B", 92) + "." + strings.Repeat("C", 43)},
		{"monkeylearn-api-key", "MONKEYLEARN_API_KEY=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"contentful-pat", "CFPAT-" + strings.Repeat("a", 43), "CFPAT-" + strings.Repeat("a", 43)},
		{"storyblok-personal-access-token", "storyblok_token=\"" + strings.Repeat("A", 22) + "tt-123456-" + strings.Repeat("B", 20) + "\"", strings.Repeat("A", 22) + "tt-123456-" + strings.Repeat("B", 20)},
		{"storyblok-access-token", "storyblok_access=\"" + strings.Repeat("A", 22) + "tt\"", strings.Repeat("A", 22) + "tt"},
		{"sanity-auth-token", "sanity_token=\"sk" + strings.Repeat("A", 79) + "\"", "sk" + strings.Repeat("A", 79)},
		{"elastic-email-api-key", "elasticemail_api_key=\"" + strings.Repeat("A", 96) + "\"", strings.Repeat("A", 96)},
		{"shortcut-api-token", "shortcut_token=\"123e4567-e89b-12d3-a456-426614174000\"", "123e4567-e89b-12d3-a456-426614174000"},
		{"webflow-api-key", "webflow_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"mapbox-secret-token", "mapbox_token=\"sk." + strings.Repeat("A", 90) + "\"", "sk." + strings.Repeat("A", 90)},
		{"locationiq-api-key", "locationiq_key=\"pk." + strings.Repeat("A", 32) + "\"", "pk." + strings.Repeat("A", 32)},
		{"coinapi-key", "X-CoinAPI-Key: ABCD1234-EF56-7890-ABCD-1234567890AB", "ABCD1234-EF56-7890-ABCD-1234567890AB"},
		{"etherscan-api-key", "etherscan apikey " + strings.Repeat("A", 34), strings.Repeat("A", 34)},
		{"bscscan-api-key", "bscscan apikey " + strings.Repeat("B", 34), strings.Repeat("B", 34)},
		{"guardian-api-key", "content.guardianapis.com api-key 12345678-abcd-1234-abcd-123456789abc", "12345678-abcd-1234-abcd-123456789abc"},
		{"circleci-pat", "CCIPAT_" + strings.Repeat("A", 22) + "_" + strings.Repeat("a", 40), "CCIPAT_" + strings.Repeat("A", 22) + "_" + strings.Repeat("a", 40)},
		{"sourcegraph-token", "sgp_0123456789abcdef_" + strings.Repeat("a", 40), "sgp_0123456789abcdef_" + strings.Repeat("a", 40)},
		{"sourcegraph-cody-token", "slk_" + strings.Repeat("a", 64), "slk_" + strings.Repeat("a", 64)},
		{"snyk-api-key", "SNYK_TOKEN=\"00000000-0000-4000-8000-000000000000\"", "00000000-0000-4000-8000-000000000000"},
		{"uptimerobot-api-key", "UPTIMEROBOT_API_KEY=\"FAKE12345-FAKE12345678901234567890\"", "FAKE12345-FAKE12345678901234567890"},
		{"sumologic-access-id", "sumologic access_id=\"suFAKE12345678\"", "suFAKE12345678"},
		{"sumologic-access-key", "sumologic access_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"statuspage-api-key", "statuspage token=\"00000000-0000-4000-8000-000000000000\"", "00000000-0000-4000-8000-000000000000"},
		{"sendinblue-api-key", "xkeysib-" + strings.Repeat("A", 81), "xkeysib-" + strings.Repeat("A", 81)},
		{"teamwork-token", "tkn.v1_" + strings.Repeat("A", 71) + "=", "tkn.v1_" + strings.Repeat("A", 71) + "="},
		{"salesblink-api-key", "salesblink_api_key=\"key-" + strings.Repeat("A", 64) + "\"", "key-" + strings.Repeat("A", 64)},
		{"smooch-app-key", "smooch_app_key=\"act_" + strings.Repeat("a", 24) + "\"", "act_" + strings.Repeat("a", 24)},
		{"mailmodo-api-key", "mailmodo_key=\"AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD\"", "AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD"},
		{"zapier-webhook", "https://hooks.zapier.com/hooks/catch/ABCDEF12/GHIJKLM", "https://hooks.zapier.com/hooks/catch/ABCDEF12/GHIJKLM"},
		{"deno-deploy-token", "ddp_" + strings.Repeat("A", 36), "ddp_" + strings.Repeat("A", 36)},
		{"supabase-management-token", "sbp_" + strings.Repeat("a", 40), "sbp_" + strings.Repeat("a", 40)},
		{"prefect-api-key", "pnu_" + strings.Repeat("A", 36), "pnu_" + strings.Repeat("A", 36)},
		{"figma-pat", "figd_" + strings.Repeat("A", 40), "figd_" + strings.Repeat("A", 40)},
		{"saladcloud-api-key", "salad_cloud_abc1234_" + strings.Repeat("A", 28), "salad_cloud_abc1234_" + strings.Repeat("A", 28)},
		{"planetscale-token", "pscale_tkn_" + strings.Repeat("A", 43), "pscale_tkn_" + strings.Repeat("A", 43)},
		{"planetscale-db-password", "pscale_pw_" + strings.Repeat("A", 43), "pscale_pw_" + strings.Repeat("A", 43)},
		{"databricks-token", "databricks dapi" + strings.Repeat("a", 32), "dapi" + strings.Repeat("a", 32)},
		{"portainer-token", "portainertoken=ptr_" + strings.Repeat("A", 32), "ptr_" + strings.Repeat("A", 32)},
		{"aws-appsync-api-key", "https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql api_key=da2-abcdefghijklmnopqrstuvwxyz", "da2-abcdefghijklmnopqrstuvwxyz"},
		{"azure-openai-key", "https://demo.openai.azure.com api-key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"azure-batch-key", "https://acct.region.batch.azure.com key=" + strings.Repeat("A", 88), strings.Repeat("A", 88)},
		{"azure-container-registry-password", "myregistry.azurecr.io " + strings.Repeat("a", 42) + "+ACRbbbbbb", strings.Repeat("a", 42) + "+ACRbbbbbb"},
		{"gcp-service-account-json", `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n","client_email":"fake@proj.iam.gserviceaccount.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}`, `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n","client_email":"fake@proj.iam.gserviceaccount.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}`},
		{"gcp-application-default-credentials", `{"client_id":"fake.apps.googleusercontent.com","client_secret":"` + strings.Repeat("A", 24) + `","refresh_token":"` + strings.Repeat("B", 32) + `"}`, `{"client_id":"fake.apps.googleusercontent.com","client_secret":"` + strings.Repeat("A", 24) + `","refresh_token":"` + strings.Repeat("B", 32) + `"}`},
		{"redis-uri", "rediss://default:FakeRedisPass123@example.redis.cache.windows.net:6380", "rediss://default:FakeRedisPass123@example.redis.cache.windows.net:6380"},
		{"azure-redis-connection-string", "demo.redis.cache.windows.net:6380,password=" + strings.Repeat("A", 44) + ",ssl=True,abortConnect=False", "demo.redis.cache.windows.net:6380,password=" + strings.Repeat("A", 44) + ",ssl=True,abortConnect=False"},
		{"couchbase-capella-uri", "couchbases://user:Passw0rd!@cb.abc123.cloud.couchbase.com", "couchbases://user:Passw0rd!@cb.abc123.cloud.couchbase.com"},
		{"closecrm-api-key", "api_" + strings.Repeat("A", 45), "api_" + strings.Repeat("A", 45)},
		{"paystack-secret-key", "sk_test_" + strings.Repeat("A", 40), "sk_test_" + strings.Repeat("A", 40)},
		{"wrike-access-token", "wrike token ey" + strings.Repeat("A", 333), "ey" + strings.Repeat("A", 333)},
		{"twitter-consumer-secret", "twitter consumer_secret " + strings.Repeat("A", 50), strings.Repeat("A", 50)},
		{"facebook-oauth-secret", "facebook app_secret " + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"flutterwave-secret-key", "FLWSECK-0123456789abcdef0123456789abcdef-X", "FLWSECK-0123456789abcdef0123456789abcdef-X"},
		{"pagarme-live-key", "ak_live_0123456789abcdefghijklmnopqrst", "ak_live_0123456789abcdefghijklmnopqrst"},
		{"rechargepayments-token", "sk_1x1_" + strings.Repeat("a", 64), "sk_1x1_" + strings.Repeat("a", 64)},
		{"lemonsqueezy-api-token", "lemonsqueezy token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 314) + "." + strings.Repeat("B", 512), "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 314) + "." + strings.Repeat("B", 512)},
		{"plaid-access-token", "access-sandbox-01234567-89ab-cdef-0123-456789abcdef", "access-sandbox-01234567-89ab-cdef-0123-456789abcdef"},
		{"cloudinary-url", "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@demo-cloud", "cloudinary://123456789012345:AbCdEfGhIjKlMnOpQrStUvWxYz1@demo-cloud"},
		{"zendesk-api-token", "acme.zendesk.com ZENDESK_API_TOKEN=" + strings.Repeat("A", 40), strings.Repeat("A", 40)},
		{"freshdesk-api-key", "acme.freshdesk.com FRESHDESK_API_KEY=a1B2c3D4e5F6g7H8i9J0", "a1B2c3D4e5F6g7H8i9J0"},
		{"helpcrunch-api-key", "HELPCRUNCH_TOKEN=" + strings.Repeat("A", 328), strings.Repeat("A", 328)},
		{"line-messaging-token", "LINE_MESSAGING_TOKEN=" + strings.Repeat("A", 172), strings.Repeat("A", 172)},
		{"courier-api-key", "COURIER_AUTH_TOKEN=pk_live_" + strings.Repeat("A", 28), "pk_live_" + strings.Repeat("A", 28)},
		{"hashicorp-vault-approle", "vault role_id=11111111-2222-3333-4444-555555555555 secret_id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"mattermost-personal-token", "mattermost token abc123def456ghi789jkl012mn team.cloud.mattermost.com", "abc123def456ghi789jkl012mn"},
		{"cloudflare-global-api-key", "cloudflare global_api_key=0123456789abcdef0123456789abcdef01234", "0123456789abcdef0123456789abcdef01234"},
		{"docker-auth-config", `{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQxMjM0NTY3ODkw"}}}`, `"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQxMjM0NTY3ODkw"`},
		{"azure-search-key", "https://acme.search.windows.net api-key: " + strings.Repeat("A", 52), strings.Repeat("A", 52)},
		{"azure-apim-subscription-key", "Ocp-Apim-Subscription-Key: 0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"auth0-domain-jwt", "tenant.auth0.com token=eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24), "eyJ" + strings.Repeat("A", 24) + ".eyJ" + strings.Repeat("B", 24) + "." + strings.Repeat("C", 24)},
		{"virustotal-api-key", "virustotal_api_key=" + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"shodan-api-key", "SHODAN_API_KEY=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"securitytrails-api-key", "securitytrails_key=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"snowflake-url", "snowflake://svc:Sup3rSecret@xy12345.us-east-1/db", "snowflake://svc:Sup3rSecret@xy12345.us-east-1/db"},
		{"sqlserver-connection-string", "Server=tcp:x.database.windows.net;User ID=app;Password=P@ssw0rd123;", "Server=tcp:x.database.windows.net;User ID=app;Password=P@ssw0rd123;"},
		{"rabbitmq-uri", "amqps://user:VerySecret123@mq.example/vhost", "amqps://user:VerySecret123@mq.example/vhost"},
		{"newsapi-key", "newsapi_key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"openweather-api-key", "openweather APPID=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"},
		{"tomorrowio-api-key", "tomorrow.io apikey=AbCdEfGhIjKlMnOpQrStUvWxYz123456", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"},
		{"here-api-key", "platform.here.com apiKey " + strings.Repeat("A", 43), strings.Repeat("A", 43)},
		{"polygon-api-key", "POLYGON_API_KEY=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
		{"aws-session-token", "aws_session_token=\"" + strings.Repeat("A", 120) + "\"", strings.Repeat("A", 120)},
		{"alibaba-access-key", "alibaba access_key=LTAI" + strings.Repeat("A", 20), "LTAI" + strings.Repeat("A", 20)},
		{"ipinfo-token", "ipinfo token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"coinlayer-api-key", "coinlayer api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"coinlib-api-key", "coinlib api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"cryptocompare-api-key", "cryptocompare api_key=\"" + strings.Repeat("A", 64) + "\"", strings.Repeat("A", 64)},
		{"bitcoinaverage-api-key", "bitcoinaverage public_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"worldcoinindex-api-key", "worldcoinindex api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"blocknative-api-key", "blocknative api_key=\"" + strings.Repeat("A", 36) + "\"", strings.Repeat("A", 36)},
		{"fixerio-api-key", "fixer.io access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"currencylayer-api-key", "currencylayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"exchangerate-api-key", "exchangerate-api api_key=\"" + strings.Repeat("A", 24) + "\"", strings.Repeat("A", 24)},
		{"exchangeratesapi-api-key", "exchangeratesapi access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"currencyfreaks-api-key", "currencyfreaks api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"currencyscoop-api-key", "currencyscoop api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"fastforex-api-key", "fastforex api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"marketstack-api-key", "marketstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"financialmodelingprep-api-key", "financialmodelingprep api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"finnhub-api-key", "finnhub api_key=\"" + strings.Repeat("A", 20) + "\"", strings.Repeat("A", 20)},
		{"tradier-token", "tradier access_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"twelvedata-api-key", "twelvedata api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"vatlayer-api-key", "vatlayer access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"worldweather-api-key", "worldweatheronline api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"positionstack-api-key", "positionstack access_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"geocodio-api-key", "geocodio api_key=\"" + strings.Repeat("A", 39) + "\"", strings.Repeat("A", 39)},
		{"vercel-token", "VERCEL_TOKEN=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"railway-token", "railway_token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"travisci-token", "TRAVIS_TOKEN=\"" + strings.Repeat("A", 22) + "\"", strings.Repeat("A", 22)},
		{"betterstack-api-key", "betterstack_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"customerio-api-key", "customer.io key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"trello-api-key", "trello_api_key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"helpscout-api-key", "helpscout key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"mailerlite-api-key", "mailerlite_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mandrill-api-key", "mandrill_key=\"" + strings.Repeat("A", 22) + "\"", strings.Repeat("A", 22)},
		{"onesignal-api-key", "onesignal_rest_api_key=\"" + strings.Repeat("A", 48) + "\"", strings.Repeat("A", 48)},
		{"copper-api-key", "copper_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"capsulecrm-api-key", "capsulecrm_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"apollo-api-key", "apollo_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"lemlist-api-key", "lemlist_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"getresponse-api-key", "getresponse_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"alienvault-otx-api-key", "alienvault_otx_key=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"censys-api-key", "censys_api_key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"vpnapi-key", "vpnapi.io key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ipqualityscore-api-key", "ipqualityscore key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"ipstack-api-key", "ipstack key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"ipgeolocation-api-key", "ipgeolocation key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"zerotier-api-token", "zerotier token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"logzio-token", "logz.io token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"codeclimate-token", "codeclimate repo token=\"" + strings.Repeat("a", 64) + "\"", strings.Repeat("a", 64)},
		{"codacy-api-token", "codacy token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"coveralls-repo-token", "coveralls token=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"weatherstack-api-key", "weatherstack key=\"" + strings.Repeat("a", 32) + "\"", strings.Repeat("a", 32)},
		{"accuweather-api-key", "accuweather key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"weatherbit-api-key", "weatherbit key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"mapquest-api-key", "mapquest key=\"" + strings.Repeat("A", 32) + "\"", strings.Repeat("A", 32)},
		{"aiven-token", "aiven_token=\"" + strings.Repeat("A", 372) + "\"", strings.Repeat("A", 372)},
		{"abuseipdb-api-key", "abuseipdb_key=\"" + strings.Repeat("a", 80) + "\"", strings.Repeat("a", 80)},
		{"sonarcloud-token", "SONAR_TOKEN=\"" + strings.Repeat("a", 40) + "\"", strings.Repeat("a", 40)},
		{"jumpcloud-api-key", "jumpcloud_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"pipedrive-api-token", "pipedrive_token=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"sparkpost-api-key", "sparkpost_api_key=\"" + strings.Repeat("A", 40) + "\"", strings.Repeat("A", 40)},
		{"dropbox-token", "sl.u." + strings.Repeat("A", 140), "sl.u." + strings.Repeat("A", 140)},
		{"readme-api-key", "rdme_" + strings.Repeat("a", 70), "rdme_" + strings.Repeat("a", 70)},
		{"rootly-api-key", "rootly_" + strings.Repeat("a", 64), "rootly_" + strings.Repeat("a", 64)},
		{"web3storage-token", "web3 " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + strings.Repeat("A", 120) + "." + strings.Repeat("B", 40), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + strings.Repeat("A", 120) + "." + strings.Repeat("B", 40)},
		{"stripe-payment-intent-client-secret", "pi_" + strings.Repeat("A", 24) + "_secret_" + strings.Repeat("B", 25), "pi_" + strings.Repeat("A", 24) + "_secret_" + strings.Repeat("B", 25)},
		{"checkout-secret-key", "checkout sk_test_12345678-1234-1234-1234-123456789abc", "sk_test_12345678-1234-1234-1234-123456789abc"},
		{"aha-api-key", "example.aha.io token=" + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"larksuite-app-secret", "larksuite app_id=cli_ABCDEFGHIJKLMNOP app_secret=" + strings.Repeat("A", 32), strings.Repeat("A", 32)},
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
