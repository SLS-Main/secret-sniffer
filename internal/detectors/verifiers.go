package detectors

import (
	"bytes"
	"context"
	"encoding/base64"
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
