package detectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func verifyBearerGET(ctx context.Context, secret, endpoint string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyHeaderGET(ctx context.Context, secret, endpoint, header, prefix string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set(header, prefix+secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyJSONPOST(ctx context.Context, secret, endpoint, header, prefix, body string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(header, prefix+secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyEndpoints(ctx context.Context, endpoints []string, verify func(string) VerificationResult) VerificationResult {
	var unknown *VerificationResult
	var rejected VerificationResult
	for _, endpoint := range endpoints {
		result := verify(endpoint)
		if result.Status == VerificationVerified {
			return result
		}
		if result.Status == VerificationUnknown && unknown == nil {
			copy := result
			unknown = &copy
		}
		rejected = result
	}
	if unknown != nil {
		return *unknown
	}
	return rejected
}

func verifySlack(ctx context.Context, secret string) VerificationResult {
	result := verifyBearerGET(ctx, secret, "https://slack.com/api/auth.test")
	if result.Status == VerificationVerified && strings.Contains(result.Response, `"ok":false`) {
		result.Status = VerificationUnverified
		result.ErrorCategory = "invalid_credentials"
		result.Message = "provider rejected credential"
	}
	return result
}

func verifyStripe(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.stripe.com/v1/balance")
}

func verifyHeroku(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.heroku.com/account/rate-limits", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	return verifyHTTPRequest(ctx, req)
}

func verifyNewRelic(ctx context.Context, secret string) VerificationResult {
	if strings.HasPrefix(secret, "NRII-") {
		return VerificationResult{Status: VerificationUnsupported, Message: "New Relic ingest keys do not have a safe read verifier"}
	}
	endpoints := []string{"https://api.newrelic.com/graphql", "https://api.eu.newrelic.com/graphql", "https://api.jp.newrelic.com/graphql"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{"query":"{ requestContext { userId } }"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("API-Key", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyGraphQLIdentity("userId"))
	})
}

func verifyDoppler(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.doppler.com/v3/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusBadRequest {
			return VerificationResult{}, false
		}
		if strings.Contains(strings.ToLower(string(body)), "invalid auth token") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyAnthropic(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	return verifyHTTPRequest(ctx, req)
}

func verifyGoogleAPIKey(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://generativelanguage.googleapis.com/v1beta/models?key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifySendGrid(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.sendgrid.com/v3/scopes")
}

func verifyMailgun(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.mailgun.net/v3/domains", "https://api.eu.mailgun.net/v3/domains"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.SetBasicAuth("api", secret)
		return verifyHTTPRequest(ctx, req)
	})
}

func verifyGitLab(ctx context.Context, secret string) VerificationResult {
	if strings.HasPrefix(secret, "gldt-") {
		return VerificationResult{Status: VerificationUnsupported, Message: "deploy token requires repository context"}
	}
	return verifyBearerGET(ctx, secret, "https://gitlab.com/api/v4/user")
}

func verifyDiscordBot(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://discord.com/api/v10/users/@me", "Authorization", "Bot ")
}

func verifyTelegramBot(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.telegram.org/bot"+url.PathEscape(secret)+"/getMe", nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyNPM(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://registry.npmjs.org/-/whoami")
}

func verifyRubyGems(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://rubygems.org/api/v1/gems.json", "Authorization", "")
}

func verifyDigitalOcean(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.digitalocean.com/v2/account")
}

func verifyCloudflare(ctx context.Context, secret string) VerificationResult {
	result := verifyBearerGET(ctx, secret, "https://api.cloudflare.com/client/v4/user/tokens/verify")
	if result.Status == VerificationVerified && !strings.Contains(result.Response, `"status":"active"`) {
		if strings.Contains(result.Response, `"status":"disabled"`) || strings.Contains(result.Response, `"status":"expired"`) {
			result.Status = VerificationUnverified
			result.ErrorCategory = "invalid_credentials"
			result.Message = "provider rejected credential"
		} else {
			result.Status = VerificationUnknown
			result.ErrorCategory = "provider_response"
			result.Message = "provider returned an unexpected verification response"
		}
	}
	return result
}

func verifyDatadog(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://api.datadoghq.com/api/v1/validate",
		"https://api.us3.datadoghq.com/api/v1/validate",
		"https://api.us5.datadoghq.com/api/v1/validate",
		"https://api.datadoghq.eu/api/v1/validate",
		"https://api.ap1.datadoghq.com/api/v1/validate",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		result := verifyHeaderGET(ctx, secret, endpoint, "DD-API-KEY", "")
		if result.Status == VerificationVerified && !strings.Contains(result.Response, `"valid":true`) {
			result.Status = VerificationUnknown
			result.ErrorCategory = "provider_response"
			result.Message = "provider returned an unexpected verification response"
		}
		return result
	})
}

func verifyPagerDuty(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pagerduty.com/users?limit=1", nil)
	req.Header.Set("Authorization", "Token token="+secret)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	return verifyHTTPRequest(ctx, req)
}

func verifyNgrok(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ngrok.com/agent_ingresses", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("ngrok-version", "2")
	return verifyHTTPRequest(ctx, req)
}

func verifyAzureDevOpsPAT(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":"+secret)))
	return verifyHTTPRequest(ctx, req)
}

func verifyTerraformCloud(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.terraform.io/api/v2/account/details")
}

func verifyNetlify(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.netlify.com/api/v1/user")
}

func verifyPulumi(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.pulumi.com/api/user/stacks", "Authorization", "token ")
}

func verifyTailscale(ctx context.Context, secret string) VerificationResult {
	body := "key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/secret-scanning/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return verifyHTTPRequest(ctx, req)
}

func verifyBuildkite(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.buildkite.com/v2/access-token")
}

func verifyPostHog(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://us.posthog.com/api/users/@me/", "https://eu.posthog.com/api/users/@me/"}, func(endpoint string) VerificationResult {
		result := verifyBearerGET(ctx, secret, endpoint)
		if result.Status == VerificationUnverified {
			result.Status = VerificationUnknown
			result.ErrorCategory = "endpoint_context"
			result.Message = "token may belong to another PostHog deployment"
		}
		return result
	})
}

func verifyLaunchDarkly(ctx context.Context, secret string) VerificationResult {
	if strings.HasPrefix(secret, "sdk-") {
		return VerificationResult{Status: VerificationUnsupported, Message: "LaunchDarkly SDK keys do not have a side-effect-free REST verifier"}
	}
	endpoints := []string{
		"https://app.launchdarkly.com/api/v2/caller-identity",
		"https://app.eu.launchdarkly.com/api/v2/caller-identity",
		"https://app.launchdarkly.us/api/v2/caller-identity",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "Authorization", "")
	})
}

func verifyCoda(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://coda.io/apis/v1/whoami")
}

func verifyCalendly(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.calendly.com/users/me")
}

func verifyMonday(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.monday.com/v2", strings.NewReader(`{"query":"query { me { id } }"}`))
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyGraphQLIdentity("id"))
}

func verifyURLScan(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://urlscan.io/user/quotas/", "API-Key", "")
}

func verifyCircleCI(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://circleci.com/api/v2/me", "Circle-Token", "")
}

func verifySnyk(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://api.snyk.io/rest/self?version=2024-10-15",
		"https://api.us.snyk.io/rest/self?version=2024-10-15",
		"https://api.eu.snyk.io/rest/self?version=2024-10-15",
		"https://api.au.snyk.io/rest/self?version=2024-10-15",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "Authorization", "token ")
	})
}

func verifyVercel(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.vercel.com/v2/user")
}

func verifyRunpod(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.runpod.io/v2/pods")
}

func verifyBetterStack(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://betterstack.com/api/v2/team-members", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := strings.ToLower(string(body))
		if statusCode == http.StatusUnprocessableEntity && strings.Contains(response, "global") && strings.Contains(response, "team") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a multi-team token"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyAiven(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.aiven.io/v1/project", "Authorization", "aivenv1 ")
}

func verifySourcegraphCody(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://cody-gateway.sourcegraph.com/v1/limits")
}

func verifyOpenPhone(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.quo.com/v1/users?maxResults=1", "Authorization", "")
}

func verifyCallRail(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.callrail.com/v3/a.json?per_page=1", nil)
	req.Header.Set("Authorization", `Token token="`+secret+`"`)
	return verifyHTTPRequest(ctx, req)
}

func verifyFront(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api2.frontapp.com/me")
}

func verifyTypeform(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.typeform.com/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && strings.Contains(string(body), "AUTHENTICATION_FAILED") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyMailchimp(ctx context.Context, secret string) VerificationResult {
	separator := strings.LastIndex(secret, "-")
	if separator < 0 || separator == len(secret)-1 {
		return VerificationResult{Status: VerificationUnsupported, Message: "Mailchimp key does not include a data center"}
	}
	dataCenter := secret[separator+1:]
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+dataCenter+".api.mailchimp.com/3.0/ping", nil)
	req.SetBasicAuth("secret-sniffer", secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyIterable(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.iterable.com/api/users/getFields", "https://api.eu.iterable.com/api/users/getFields"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Api-Key", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
			if statusCode == http.StatusUnauthorized {
				return unknownVerificationResult("authorization", "key type, region, or privileges could not be confirmed"), true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyLangSmith(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://api.smith.langchain.com/api/v1/workspaces",
		"https://eu.api.smith.langchain.com/api/v1/workspaces",
		"https://apac.api.smith.langchain.com/api/v1/workspaces",
		"https://aws.api.smith.langchain.com/api/v1/workspaces",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "X-API-Key", "")
	})
}

func verifyLinear(ctx context.Context, secret string) VerificationResult {
	return verifyJSONPOST(ctx, secret, "https://api.linear.app/graphql", "Authorization", "", `{"query":"{ viewer { id name } }"}`)
}

func verifyNotion(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.notion.com/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Notion-Version", "2022-06-28")
	return verifyHTTPRequest(ctx, req)
}

func verifyPostman(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.getpostman.com/collections", "X-Api-Key", "")
}

func verifySentry(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://sentry.io/api/0/auth/validate/")
}

func verifyHoneycomb(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.honeycomb.io/1/auth", "https://api.eu1.honeycomb.io/1/auth"}, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "X-Honeycomb-Team", "")
	})
}

func verifyOpsgenie(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.opsgenie.com/v2/account", "https://api.eu.opsgenie.com/v2/account"}, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "Authorization", "GenieKey ")
	})
}

func verifyDiscordWebhook(ctx context.Context, secret string) VerificationResult {
	if !strings.HasPrefix(secret, "https://discord.com/api/webhooks/") {
		return VerificationResult{Status: VerificationUnsupported}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, secret, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyWebex(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://webexapis.com/v1/people/me")
}

func verifyHuggingFace(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://huggingface.co/api/whoami-v2")
}

func verifyGroq(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.groq.com/openai/v1/models")
}

func verifyReplicate(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.replicate.com/v1/account")
}

func verifyAirtable(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.airtable.com/v0/meta/whoami")
}

func verifyAsana(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.asana.com/api/1.0/users/me")
}

func verifyClickUp(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.clickup.com/api/v2/user", "Authorization", "")
}

func verifyHubSpot(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.hubapi.com/account-info/v3/api-usage/daily/private-apps")
}

func verifyKlaviyo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://a.klaviyo.com/api/profiles?page[size]=1", nil)
	req.Header.Set("Authorization", "Klaviyo-API-Key "+secret)
	req.Header.Set("revision", "2025-10-15")
	return verifyHTTPRequest(ctx, req)
}

func verifyPostmark(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.postmarkapp.com/server", "X-Postmark-Server-Token", "")
}

func verifyAtlassian(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.atlassian.com/admin/v1/orgs")
}

func verifyIntercom(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.intercom.io/me", "https://api.eu.intercom.io/me", "https://api.au.intercom.io/me"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Intercom-Version", "2.16")
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode != http.StatusUnauthorized {
				return VerificationResult{}, false
			}
			response := strings.ToLower(string(body))
			for _, code := range []string{"token_revoked", "token_blocked", "token_not_found", "token_expired"} {
				if strings.Contains(response, code) {
					return invalidCredentialResult(), true
				}
			}
			return unknownVerificationResult("authorization", "token region or authorization could not be confirmed"), true
		})
	})
}

func verifyPinecone(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pinecone.io/indexes", nil)
	req.Header.Set("Api-Key", secret)
	req.Header.Set("X-Pinecone-Api-Version", "2025-10")
	return verifyHTTPRequest(ctx, req)
}

func verifyElevenLabs(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.elevenlabs.io/v1/user", "xi-api-key", "")
}

func verifyXAI(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.x.ai/v1/models")
}

func verifyCohere(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.cohere.com/v1/models")
}

func verifyMistral(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.mistral.ai/v1/models")
}

func verifyTogetherAI(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.together.ai/v1/models")
}

func verifyFireworksAI(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.fireworks.ai/v1/accounts/fireworks/models?pageSize=1")
}

func verifyCerebras(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.cerebras.ai/v1/models")
}

func verifyBaseten(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.baseten.co/v1/models", "Authorization", "Api-Key ")
}

func verifyOpenRouter(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://openrouter.ai/api/v1/auth/key")
}

func invalidCredentialResult() VerificationResult {
	return VerificationResult{Status: VerificationUnverified, ErrorCategory: "invalid_credentials", Message: "provider rejected credential"}
}

func unknownVerificationResult(category, message string) VerificationResult {
	return VerificationResult{Status: VerificationUnknown, ErrorCategory: category, Message: message}
}

func classifyGraphQLIdentity(field string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var payload map[string]any
		if json.Unmarshal(body, &payload) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if findJSONField(payload["data"], field) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("authorization", "GraphQL response did not contain authenticated identity"), true
	}
}

func findJSONField(value any, field string) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if key == field && child != nil && child != "" {
				return true
			}
			if findJSONField(child, field) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if findJSONField(child, field) {
				return true
			}
		}
	}
	return false
}
