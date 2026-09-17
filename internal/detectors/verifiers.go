package detectors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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

func verifyJSONIdentityRequest(ctx context.Context, req *http.Request, fields ...string) VerificationResult {
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		switch {
		case statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, fields...):
			return VerificationResult{Status: VerificationVerified}, true
		case statusCode >= 200 && statusCode < 300:
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		case statusCode == http.StatusUnauthorized:
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden:
			return unknownVerificationResult("authorization", "provider could not authorize verification"), true
		case statusCode == http.StatusTooManyRequests:
			return unknownVerificationResult("rate_limited", "provider rate limited verification"), true
		case statusCode >= 500:
			return unknownVerificationResult("provider", "provider unavailable"), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
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
	if strings.HasPrefix(secret, "xoxr-") || strings.HasPrefix(secret, "xoxs-") {
		return VerificationResult{Status: VerificationUnsupported, Message: "Slack refresh and session tokens are not standalone Web API credentials"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/auth.test", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests {
			return unknownVerificationResult("rate_limited", "provider rate limited verification"), true
		}
		if statusCode >= 500 {
			return unknownVerificationResult("provider", "provider unavailable"), true
		}
		if statusCode != http.StatusOK {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		var response struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if response.OK {
			return VerificationResult{Status: VerificationVerified}, true
		}
		switch response.Error {
		case "account_inactive", "token_expired", "token_revoked":
			return invalidCredentialResult(), true
		case "ratelimited":
			return unknownVerificationResult("rate_limited", "provider rate limited verification"), true
		case "accesslimited", "invalid_auth", "missing_scope", "no_permission", "not_allowed_token_type", "org_login_required", "team_access_not_granted", "team_added_to_org":
			return unknownVerificationResult("authorization", "provider could not authorize verification"), true
		case "fatal_error", "internal_error", "request_timeout", "service_unavailable":
			return unknownVerificationResult("provider", "provider unavailable"), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
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

func verifyTwilio(ctx context.Context, candidate Candidate) VerificationResult {
	sid := candidate.SecretParts["account_sid"]
	token := candidate.SecretParts["auth_token"]
	if sid == "" || token == "" {
		return invalidCredentialResult()
	}
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + url.PathEscape(sid) + ".json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.SetBasicAuth(sid, token)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		switch {
		case statusCode >= 200 && statusCode < 300:
			return VerificationResult{Status: VerificationVerified}, true
		case statusCode == http.StatusUnauthorized:
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden:
			return unknownVerificationResult("authorization", "provider denied account access"), true
		case statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500:
			return VerificationResult{}, false
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
}

func verifyLarkSuiteCredentials(ctx context.Context, candidate Candidate) VerificationResult {
	appID := candidate.SecretParts["app_id"]
	appSecret := candidate.SecretParts["app_secret"]
	if appID == "" || appSecret == "" {
		return invalidCredentialResult()
	}
	payload, _ := json.Marshal(map[string]string{"app_id": appID, "app_secret": appSecret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode != http.StatusOK {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		var response struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if response.Code == 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider rejected the credential with an ambiguous error"), true
	})
	result.Response = ""
	return result
}

func verifyAzureEntraCredentials(ctx context.Context, candidate Candidate) VerificationResult {
	tenantID := candidate.SecretParts["tenant_id"]
	clientID := candidate.SecretParts["client_id"]
	clientSecret := candidate.SecretParts["client_secret"]
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return invalidCredentialResult()
	}
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	endpoint := "https://login.microsoftonline.com/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			AccessToken      string `json:"access_token"`
			ErrorDescription string `json:"error_description"`
			ErrorCodes       []int  `json:"error_codes"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if statusCode >= 200 && statusCode < 300 {
			if response.AccessToken != "" {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if azureErrorCode(response.ErrorCodes, response.ErrorDescription, 7000215, 7000222) {
			return invalidCredentialResult(), true
		}
		if azureErrorCode(response.ErrorCodes, response.ErrorDescription, 53003) {
			return unknownVerificationResult("authorization", "provider blocked token issuance by policy"), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous authentication response"), true
	})
	result.Response = ""
	return result
}

func azureErrorCode(codes []int, description string, expected ...int) bool {
	for _, code := range codes {
		for _, candidate := range expected {
			if code == candidate {
				return true
			}
		}
	}
	for _, candidate := range expected {
		if strings.Contains(description, fmt.Sprintf("AADSTS%d", candidate)) {
			return true
		}
	}
	return false
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
	return verifyEndpoints(ctx, datadogAPIEndpoints("/api/v1/validate"), func(endpoint string) VerificationResult {
		result := verifyHeaderGET(ctx, secret, endpoint, "DD-API-KEY", "")
		if result.Status == VerificationVerified && !strings.Contains(result.Response, `"valid":true`) {
			result.Status = VerificationUnknown
			result.ErrorCategory = "provider_response"
			result.Message = "provider returned an unexpected verification response"
		}
		return result
	})
}

func verifyDatadogCredentials(ctx context.Context, candidate Candidate) VerificationResult {
	apiKey := candidate.SecretParts["api_key"]
	appKey := candidate.SecretParts["app_key"]
	if apiKey == "" || appKey == "" {
		return invalidCredentialResult()
	}
	result := verifyEndpoints(ctx, datadogAPIEndpoints("/api/v2/validate_keys"), func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("DD-API-KEY", apiKey)
		req.Header.Set("DD-APPLICATION-KEY", appKey)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
			switch {
			case statusCode >= 200 && statusCode < 300:
				return VerificationResult{Status: VerificationVerified}, true
			case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
				return invalidCredentialResult(), true
			case statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500:
				return VerificationResult{}, false
			default:
				return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
			}
		})
	})
	result.Response = ""
	return result
}

func datadogAPIEndpoints(path string) []string {
	hosts := []string{
		"api.datadoghq.com",
		"api.us3.datadoghq.com",
		"api.us5.datadoghq.com",
		"api.datadoghq.eu",
		"api.ap1.datadoghq.com",
		"api.ap2.datadoghq.com",
		"api.uk1.datadoghq.com",
		"api.ddog-gov.com",
		"api.us2.ddog-gov.com",
	}
	endpoints := make([]string, 0, len(hosts))
	for _, host := range hosts {
		endpoints = append(endpoints, "https://"+host+path)
	}
	return endpoints
}

func verifyCensysCredentials(ctx context.Context, candidate Candidate) VerificationResult {
	apiID := candidate.SecretParts["api_id"]
	apiSecret := candidate.SecretParts["api_secret"]
	if apiID == "" || apiSecret == "" {
		return invalidCredentialResult()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://search.censys.io/api/v1/account", nil)
	req.SetBasicAuth(apiID, apiSecret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		switch {
		case statusCode >= 200 && statusCode < 300:
			return VerificationResult{Status: VerificationVerified}, true
		case statusCode == http.StatusUnauthorized:
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden:
			return unknownVerificationResult("authorization", "provider denied account access"), true
		case statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500:
			return VerificationResult{}, false
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pulumi.com/api/user", nil)
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.pulumi+8")
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusOK {
			if jsonHasAnyField(body, "id", "githubLogin") {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "credential may require token exchange"), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyTailscale(ctx context.Context, secret string) VerificationResult {
	body := "key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/secret-scanning/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		switch statusCode {
		case http.StatusNoContent:
			return VerificationResult{Status: VerificationVerified}, true
		case http.StatusUnauthorized:
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://circleci.com/api/v2/me", nil)
	req.Header.Set("Circle-Token", secret)
	return verifyJSONIdentityRequest(ctx, req, "id")
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.vercel.com/v2/user", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		switch {
		case statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "id"):
			return VerificationResult{Status: VerificationVerified}, true
		case statusCode >= 200 && statusCode < 300:
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		case statusCode == http.StatusUnauthorized:
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden:
			var response struct {
				Error struct {
					InvalidToken bool `json:"invalidToken"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &response) == nil && response.Error.InvalidToken {
				return invalidCredentialResult(), true
			}
			return unknownVerificationResult("authorization", "provider could not authorize verification"), true
		case statusCode == http.StatusTooManyRequests:
			return unknownVerificationResult("rate_limited", "provider rate limited verification"), true
		case statusCode >= 500:
			return unknownVerificationResult("provider", "provider unavailable"), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
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

func verifyDropbox(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.dropboxapi.com/2/users/get_current_account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			return VerificationResult{}, false
		}
		response := strings.ToLower(string(body))
		switch {
		case strings.Contains(response, "missing_scope"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		case strings.Contains(response, "invalid_access_token"), strings.Contains(response, "expired_access_token"):
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
	})
}

func verifyFigma(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.figma.com/v1/me", nil)
	req.Header.Set("X-Figma-Token", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusForbidden {
			return VerificationResult{}, false
		}
		response := strings.ToLower(string(body))
		switch {
		case strings.Contains(response, "invalid scope"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		case strings.Contains(response, "invalid token"):
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
	})
}

func verifyNeon(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://console.neon.tech/api/v2/auth")
}

func verifyRender(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.render.com/v1/users")
}

func verifyResend(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.resend.com/api-keys?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := strings.ToLower(string(body))
		switch {
		case statusCode == http.StatusUnauthorized && strings.Contains(response, "restricted_api_key"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted key"}, true
		case statusCode == http.StatusBadRequest && strings.Contains(response, "validation_error"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden && strings.Contains(response, "restricted_api_key"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		default:
			return VerificationResult{}, false
		}
	})
}

func verifyShortcut(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.app.shortcut.com/api/v3/member", "Shortcut-Token", "")
}

func verifyTodoist(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.todoist.com/api/v1/user")
}

func verifyFastly(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.fastly.com/tokens/self", "Fastly-Key", "")
}

func verifyBitly(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api-ssl.bitly.com/v4/user", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(body)), "token") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyReadMe(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.readme.com/v2/projects/me")
}

func verifyGoCardless(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.gocardless.com/creditors?limit=1"
	if strings.HasPrefix(strings.ToLower(secret), "sandbox_") {
		endpoint = "https://api-sandbox.gocardless.com/creditors?limit=1"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("GoCardless-Version", "2015-07-06")
	return verifyHTTPRequest(ctx, req)
}

func verifyPipedrive(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.pipedrive.com/v1/users/me?api_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyHelpScout(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://docsapi.helpscout.net/v1/collections", nil)
	req.SetBasicAuth(secret, "X")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifySegment(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://platform.segmentapis.com/v1beta/workspaces")
}

func verifyFullStory(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.fullstory.com/me", "Authorization", "Basic ")
}

func verifySecurityTrails(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.securitytrails.com/v1/ping", nil)
	req.Header.Set("APIKEY", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			var response struct {
				Success bool `json:"success"`
			}
			if json.Unmarshal(body, &response) != nil || !response.Success {
				return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
			}
		}
		return VerificationResult{}, false
	})
}

func verifyWebflow(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.webflow.com/v2/token/authorized_by", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		}
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "invalid_credentials", "invalid credential") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyWorkOS(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.workos.com/organizations?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyDeepgram(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deepgram.com/v1/projects", nil)
	req.Header.Set("Authorization", "Token "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden {
			return VerificationResult{}, false
		}
		response := string(body)
		switch {
		case containsAnyFold(response, "INSUFFICIENT_PERMISSIONS"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		case containsAnyFold(response, "INVALID_AUTH", "Invalid credentials"):
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
	})
}

func verifyContentful(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.contentful.com/spaces?limit=1", "https://api.eu.contentful.com/spaces?limit=1"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/vnd.contentful.management.v1+json")
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			response := string(body)
			switch {
			case statusCode == http.StatusForbidden && containsAnyFold(response, "AccessDenied"):
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
			case statusCode == http.StatusUnauthorized && !containsAnyFold(response, "AccessTokenInvalid"):
				return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
			default:
				return VerificationResult{}, false
			}
		})
	})
}

func verifySupabaseManagement(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.supabase.com/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyCloseCRM(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.close.com/api/v1/me/", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired || statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted account"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyBrevo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.brevo.com/v3/account", nil)
	req.Header.Set("api-key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusBadRequest && !containsAnyFold(string(body), "api-key not found", "authentication failed", "unauthorized") {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		return VerificationResult{}, false
	})
}

func verifyDeepSeek(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deepseek.com/models", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with insufficient balance"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyShodan(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.shodan.io/api-info?key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			if jsonHasAnyField(body, "plan", "query_credits", "scan_credits") {
				return VerificationResult{}, false
			}
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if containsAnyFold(string(body), "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyApify(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.apify.com/v2/users/me")
}

func verifyCloudsmith(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudsmith.io/v1/user/self/", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			var response struct {
				Authenticated bool `json:"authenticated"`
			}
			if json.Unmarshal(body, &response) == nil && response.Authenticated {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		}
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyClockify(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.clockify.me/api/v1/user", "X-Api-Key", "")
}

func verifySmartsheet(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.smartsheet.com/2.0/users/me", "https://api.smartsheet.eu/2.0/users/me", "https://api.smartsheet.au/2.0/users/me"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyYNAB(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.ynab.com/v1/plans")
}

func verifyGrafanaCloud(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://grafana.com/api/v1/tokens?region=us&pageSize=1",
		"https://grafana.com/api/v1/tokens?region=eu&pageSize=1",
		"https://grafana.com/api/v1/tokens?region=au&pageSize=1",
	}
	result := verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden {
				return VerificationResult{}, false
			}
			response := string(body)
			switch {
			case containsAnyFold(response, "invalid permission", "required scope"):
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
			case containsAnyFold(response, "InvalidCredentials", "could not be parsed"):
				return invalidCredentialResult(), true
			default:
				return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
			}
		})
	})
	result.Response = ""
	return result
}

func verifyLokalise(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.lokalise.com/api2/projects?limit=1", nil)
	req.Header.Set("X-Api-Token", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusBadRequest {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "Invalid `X-Api-Token` header") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyShippo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.goshippo.com/addresses/?results=1", nil)
	req.Header.Set("Authorization", "ShippoToken "+secret)
	req.Header.Set("Shippo-API-Version", "2018-02-08")
	return verifyHTTPRequest(ctx, req)
}

func verifyTaxJar(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.taxjar.com/v2/categories", "https://api.sandbox.taxjar.com/v2/categories"}, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyTogglTrack(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.track.toggl.com/api/v9/me", nil)
	req.SetBasicAuth(secret, "api_token")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusForbidden {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "incorrect username and/or password") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
	})
}

func verifyTicketmaster(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://app.ticketmaster.com/discovery/v2/events.json?size=1&apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "oauth.v2.InvalidApiKey") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyDynalist(ctx context.Context, secret string) VerificationResult {
	body, _ := json.Marshal(map[string]string{"token": secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://dynalist.io/api/v1/file/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 || statusCode >= 300 && statusCode < 400 {
			return VerificationResult{}, false
		}
		var response struct {
			Code string `json:"_code"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch response.Code {
		case "OK":
			return VerificationResult{Status: VerificationVerified}, true
		case "InvalidToken":
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyGyazo(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.gyazo.com/api/users/me")
}

func verifyLunchMoney(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.lunchmoney.dev/v2/me")
}

func verifyMeraki(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.meraki.com/api/v1/organizations")
}

func verifyMiro(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.miro.com/v1/oauth-token")
}

func verifyRevAI(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.rev.ai/speechtotext/v1/account")
}

func verifyTwist(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twist.com/api/v3/users/get_session_user", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := string(body)
		if statusCode == http.StatusForbidden && containsAnyFold(response, "invalid token") && containsAnyFold(response, `"code":200`, `"code": 200`) {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyYousign(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.yousign.app/v3/users?limit=1", "https://api-sandbox.yousign.app/v3/users?limit=1"}, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyRootly(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.rootly.com/v1/users?page[number]=1&page[size]=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.api+json")
	return verifyHTTPRequest(ctx, req)
}

func verifyIncidentIO(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.incident.io/v1/identity")
}

func verifyFireHydrant(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.firehydrant.io/v1/ping")
}

func verifySocketDev(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.socket.dev/v0/organizations")
}

func verifySemgrep(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://semgrep.dev/api/v1/deployments", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "token may lack Web API access"), true
		}
		return VerificationResult{}, false
	})
}

func verifyThousandEyes(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.thousandeyes.com/v7/account-groups", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyVultr(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.vultr.com/v2/account")
}

func verifyAssemblyAI(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.assemblyai.com/v2/transcript?limit=1", "https://api.eu.assemblyai.com/v2/transcript?limit=1"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "Authorization", "")
	})
}

func verifyLiveblocks(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.liveblocks.io/v2/rooms?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "MISSING_SECRET_KEY", "WRONG_KEY_USED", "INVALID_SECRET_KEY", "INVALID_PUBLIC_KEY") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
	})
}

func verifyClerk(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.clerk.com/v1/clients?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "clerk_key_invalid") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyUptimeRobot(ctx context.Context, secret string) VerificationResult {
	body := "api_key=" + url.QueryEscape(secret) + "&format=json&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.uptimerobot.com/v2/getMonitors", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Stat  string `json:"stat"`
			Error struct {
				ParameterName string `json:"parameter_name"`
				Message       string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch {
		case response.Stat == "ok":
			return VerificationResult{Status: VerificationVerified}, true
		case response.Stat == "fail" && response.Error.ParameterName == "api_key" && containsAnyFold(response.Error.Message, "invalid"):
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyApollo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apollo.io/api/v1/auth/health", nil)
	req.Header.Set("x-api-key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Healthy    bool `json:"healthy"`
			IsLoggedIn bool `json:"is_logged_in"`
		}
		if json.Unmarshal(body, &response) != nil || !response.Healthy {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if response.IsLoggedIn {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return invalidCredentialResult(), true
	})
}

func verifySonarCloud(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://sonarcloud.io/api/authentication/validate", "https://sonarqube.us/api/authentication/validate"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode < 200 || statusCode >= 300 {
				return VerificationResult{}, false
			}
			var response struct {
				Valid *bool `json:"valid"`
			}
			if json.Unmarshal(body, &response) != nil || response.Valid == nil {
				return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
			}
			if *response.Valid {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return invalidCredentialResult(), true
		})
	})
}

func verifyAlienVaultOTX(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://otx.alienvault.com/api/v1/user/me", nil)
	req.Header.Set("X-OTX-API-KEY", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "authentication required") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyLemlist(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.lemlist.com/api/team", nil)
	req.SetBasicAuth("", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusNotFound && containsAnyFold(string(body), "no user found") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusNotFound {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		return VerificationResult{}, false
	})
}

func verifyZeroTier(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.zerotier.com/api/v1/network", nil)
	req.Header.Set("Authorization", "token "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "access denied") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyTwitch(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://id.twitch.tv/oauth2/validate", nil)
	req.Header.Set("Authorization", "OAuth "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "invalid access token") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyPushbullet(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pushbullet.com/v2/users/me", nil)
	req.Header.Set("Access-Token", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "invalid_access_token") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyZeplin(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.zeplin.dev/v1/users/me")
}

func verifyAdafruitIO(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://io.adafruit.com/api/v2/user", "X-AIO-Key", "")
}

func verifyAtera(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://app.atera.com/api/v3/agents?page=1&itemsInPage=1", "X-API-KEY", "")
}

func verifyBorgBase(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.borgbase.com/graphql", strings.NewReader(`{"query":"{ repoList { id } }"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Data struct {
				RepoList []any `json:"repoList"`
			} `json:"data"`
			Errors []struct {
				Extensions struct {
					Code string `json:"code"`
				} `json:"extensions"`
			} `json:"errors"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Data.RepoList != nil {
			return VerificationResult{Status: VerificationVerified}, true
		}
		for _, providerErr := range response.Errors {
			if providerErr.Extensions.Code == "UNAUTHENTICATED" {
				return invalidCredentialResult(), true
			}
		}
		return unknownVerificationResult("authorization", "GraphQL response did not authenticate the credential"), true
	})
}

func verifyEverhour(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.everhour.com/users/me", nil)
	req.Header.Set("X-Api-Key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			var response struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if json.Unmarshal(body, &response) == nil && response.Code == 403 && strings.EqualFold(response.Message, "Access denied") {
				return invalidCredentialResult(), true
			}
		}
		return VerificationResult{}, false
	})
}

func verifyFrameIO(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.frame.io/v2/me")
}

func verifyLoyverse(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.loyverse.com/v1.0/merchant/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		switch {
		case statusCode == http.StatusPaymentRequired:
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token for an inactive subscription"}, true
		case statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "access token is not valid", "UNAUTHORIZED"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusUnauthorized:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		default:
			return VerificationResult{}, false
		}
	})
}

func verifyMailsac(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://mailsac.com/api/me", nil)
	req.Header.Set("Mailsac-Key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			var response map[string]any
			if strings.TrimSpace(string(body)) == "null" {
				return invalidCredentialResult(), true
			}
			if json.Unmarshal(body, &response) != nil || response == nil {
				return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
			}
		}
		return VerificationResult{}, false
	})
}

func verifyMeisterTask(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://www.meistertask.com/api/persons/me")
}

func verifyProtocolsIO(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.protocols.io/api/v3/session/profile", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			StatusCode int            `json:"status_code"`
			User       map[string]any `json:"user"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch response.StatusCode {
		case 0:
			if len(response.User) > 0 {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider response did not contain an authenticated user"), true
		case 1218, 1219:
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyTravisCI(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.travis-ci.com/user", "https://api.travis-ci.org/user"}
	result := verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "token "+secret)
		req.Header.Set("Travis-API-Version", "3")
		req.Header.Set("User-Agent", "secret-sniffer")
		result := verifyJSONIdentityRequest(ctx, req, "id", "login")
		if result.Status == VerificationUnverified {
			result = unknownVerificationResult("endpoint_context", "token may belong to a Travis CI Enterprise installation")
		}
		return result
	})
	result.Response = ""
	return result
}

func verifyMandrill(ctx context.Context, secret string) VerificationResult {
	body, _ := json.Marshal(map[string]string{"key": secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://mandrillapp.com/api/1.0/users/info.json", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "Invalid_Key", "Invalid API key") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyCodacy(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.codacy.com/api/v3/user", nil)
	req.Header.Set("api-token", secret)
	result := verifyHTTPRequest(ctx, req)
	if result.Status == VerificationUnverified {
		result.Status = VerificationUnknown
		result.ErrorCategory = "credential_type"
		result.Message = "credential may be a repository-scoped Codacy token"
	}
	return result
}

func verifyWrike(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://www.wrike.com/api/v4/contacts?me=true",
		"https://app-eu.wrike.com/api/v4/contacts?me=true",
		"https://app-us2.wrike.com/api/v4/contacts?me=true",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusForbidden && containsAnyFold(string(body), "access_forbidden") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyPrefect(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.prefect.cloud/api/me/workspaces")
}

func verifyPolar(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.polar.sh/v1/organizations/?page=1&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "organizations:read", "insufficient scope") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		}
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "invalid_token") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyPaystack(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.paystack.co/balance", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "invalid key", "invalid_Key") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyFlutterwave(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.flutterwave.com/v3/balances", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "invalid authorization key") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyVirusTotal(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://www.virustotal.com/api/v3/files/" + strings.Repeat("0", 64)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("x-apikey", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := string(body)
		switch {
		case statusCode == http.StatusNotFound && containsAnyFold(response, "NotFoundError"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated the sentinel lookup"}, true
		case statusCode == http.StatusUnauthorized && containsAnyFold(response, "WrongCredentialsError"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusUnauthorized || statusCode == http.StatusNotFound:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		default:
			return VerificationResult{}, false
		}
	})
}

func verifyStatuspage(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.statuspage.io/v1/pages", "Authorization", "OAuth ")
}

func verifyStatusCake(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.statuscake.com/v1/uptime?limit=1&nouptime=true")
}

func verifyWeightsAndBiases(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.wandb.ai/graphql", strings.NewReader(`{"query":"query { viewer { id } }"}`))
	req.SetBasicAuth("api", secret)
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Data struct {
				Viewer *struct {
					ID string `json:"id"`
				} `json:"viewer"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Data.Viewer == nil {
			return invalidCredentialResult(), true
		}
		if response.Data.Viewer.ID == "" {
			return unknownVerificationResult("provider_response", "provider response did not contain an authenticated identity"), true
		}
		return VerificationResult{Status: VerificationVerified}, true
	})
}

func verifyPipedream(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.pipedream.com/v1/users/me")
}

func verifyCrowdin(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.crowdin.com/api/v2/user")
}

func verifyEventbrite(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://www.eventbriteapi.com/v3/users/me/")
}

func verifyLINEMessaging(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.line.me/v2/bot/info", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted channel token"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyMessageBird(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://rest.messagebird.com/balance", nil)
	req.Header.Set("Authorization", "AccessKey "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), `"code":2`, "incorrect access_key") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyTelnyx(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.telnyx.com/v2/balance", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), `"10009"`, "authentication failed") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyFlyIO(ctx context.Context, secret string) VerificationResult {
	body, _ := json.Marshal(map[string]string{"header": secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.machines.dev/v1/tokens/authenticate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusBadRequest && containsAnyFold(string(body), "invalid token", "no tokens found") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusBadRequest {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		return VerificationResult{}, false
	})
}

func verifyPhrase(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.phrase.com/v2/user", "https://api.us.app.phrase.com/v2/user"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "token "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusForbidden && containsAnyFold(string(body), "scope", "permission") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyLemonSqueezy(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.lemonsqueezy.com/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Content-Type", "application/vnd.api+json")
	return verifyHTTPRequest(ctx, req)
}

func verifyRecharge(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.rechargeapps.com/store", nil)
	req.Header.Set("X-Recharge-Access-Token", secret)
	req.Header.Set("X-Recharge-Version", "2021-11")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "permission", "scope") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		}
		return VerificationResult{}, false
	})
}

func verifySquare(ctx context.Context, secret string) VerificationResult {
	if strings.HasPrefix(secret, "sq0csp-") {
		return VerificationResult{Status: VerificationUnsupported, Message: "Square application secrets are not bearer access tokens"}
	}
	endpoints := []string{"https://connect.squareup.com/v2/merchants", "https://connect.squareupsandbox.com/v2/merchants"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Square-Version", "2026-08-19")
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusForbidden && containsAnyFold(string(body), "INSUFFICIENT_SCOPES") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
			}
			if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "AUTHENTICATION_ERROR", "UNAUTHORIZED") {
				return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyAttio(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.attio.com/v2/self", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Active *bool `json:"active"`
		}
		if json.Unmarshal(body, &response) != nil || response.Active == nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if *response.Active {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return invalidCredentialResult(), true
	})
}

func verifyOnfleet(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://onfleet.com/api/v2/auth/test", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyPodio(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.podio.com/user/status")
}

func verifyGumroad(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.gumroad.com/v2/user")
}

func verifyPDFShift(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pdfshift.io/v3/credits/usage", nil)
	req.SetBasicAuth("api", secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyTurso(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.turso.tech/v1/organizations")
}

func verifyDenoDeploy(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.deno.com/v1/organizations")
}

func verifyCoinlayer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.coinlayer.com/api/list?access_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success *bool `json:"success"`
			Error   struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil || response.Success == nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if *response.Success {
			return VerificationResult{Status: VerificationVerified}, true
		}
		switch response.Error.Code {
		case 101, 102:
			return invalidCredentialResult(), true
		case 104, 105:
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted or exhausted key"}, true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyEasyPost(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.easypost.com/v2/metadata/carriers?carriers=usps&types=service_levels", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyLob(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.lob.com/v1/addresses?limit=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyMapbox(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.mapbox.com/tokens/v2?access_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(body, &response) != nil || response.Code == "" {
			if statusCode >= 200 && statusCode < 300 {
				return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
			}
			return VerificationResult{}, false
		}
		switch response.Code {
		case "TokenValid":
			return VerificationResult{Status: VerificationVerified}, true
		case "TokenMalformed", "TokenInvalid", "TokenExpired", "TokenRevoked":
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous token status"), true
		}
	})
}

func verifyQase(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.qase.io/v1/project?limit=1&offset=0", "Token", "")
}

func verifyProductboard(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.productboard.com/v2/members", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "auth.invalid") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifySanity(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.sanity.io/v2021-10-21/users/me")
}

func verifyStoryblokPersonal(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{
		"https://mapi.storyblok.com/v1/spaces?per_page=1",
		"https://api-us.storyblok.com/v1/spaces?per_page=1",
		"https://api-ca.storyblok.com/v1/spaces?per_page=1",
		"https://api-ap.storyblok.com/v1/spaces?per_page=1",
		"https://app.storyblokchina.cn/v1/spaces?per_page=1",
	}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "Authorization", "")
	})
}

func verifyStoryblokAccess(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"api.storyblok.com", "api-us.storyblok.com", "api-ca.storyblok.com", "api-ap.storyblok.com", "app.storyblokchina.cn"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		endpoint := "https://" + host + "/v2/cdn/spaces/me?token=" + url.QueryEscape(secret)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		return verifyHTTPRequest(ctx, req)
	})
}

func verifyOANDA(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api-fxpractice.oanda.com/v3/accounts", "https://api-fxtrade.oanda.com/v3/accounts"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyGreenhouse(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://harvest.greenhouse.io/v1/users?per_page=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyPivotalTracker(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.pivotaltracker.com/services/v5/me", nil)
	req.Header.Set("X-TrackerToken", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "invalid authentication credentials") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyCloudConvert(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudconvert.com/v2/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "user.read", "scope") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyBannerbear(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bannerbear.com/v2/account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with exhausted quota"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyAPIFlash(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.apiflash.com/v1/urltoimage/quota?access_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with exhausted quota"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyIPInfo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipinfo.io/lite/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "unknown token") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyBaremetrics(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.baremetrics.com/v1/account")
}

func verifyScrapingBee(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://app.scrapingbee.com/api/v1/usage?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyVoyageAI(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.voyageai.com/v1/files?limit=1")
}

func verifyPerplexity(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.perplexity.ai/router/v1/models")
}

func verifyAI21(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.ai21.com/studio/v1/library/files?offset=0&limit=1")
}

func verifyNovita(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.novita.ai/openai/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode != http.StatusForbidden {
			return VerificationResult{}, false
		}
		response := string(body)
		switch {
		case containsAnyFold(response, "INVALID_API_KEY"):
			return invalidCredentialResult(), true
		case containsAnyFold(response, "NOT_ENOUGH_BALANCE", "ACCESS_DENY"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted or exhausted key"}, true
		default:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
	})
}

func verifyZilliz(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloud.zilliz.com/v2/projects", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Code int `json:"code"`
		}
		if json.Unmarshal(body, &response) != nil {
			if statusCode >= 200 && statusCode < 300 {
				return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
			}
			return VerificationResult{}, false
		}
		switch response.Code {
		case 0:
			return VerificationResult{Status: VerificationVerified}, true
		case 80001, 80002, 21119:
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyDatoCMS(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://site-api.datocms.com/site", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Api-Version", "3")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := string(body)
		switch {
		case containsAnyFold(response, "INSUFFICIENT_PERMISSIONS"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		case statusCode == http.StatusUnauthorized && containsAnyFold(response, "INVALID_AUTHORIZATION_HEADER"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusUnauthorized:
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		default:
			return VerificationResult{}, false
		}
	})
}

func verifyLocationIQ(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"us1.locationiq.com", "eu1.locationiq.com"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		endpoint := "https://" + host + "/v1/balance?key=" + url.QueryEscape(secret) + "&format=json"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		return verifyHTTPRequest(ctx, req)
	})
}

func verifyXata(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.xata.tech/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "invalid api key", "invalid token") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyVagrantCloud(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.vagrantup.com/api/v2/authenticate")
}

func verifyPaperform(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.paperform.co/v1/forms?limit=1")
}

func verifyDaily(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.daily.co/v1/rooms?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "forbidden-error") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with insufficient permission"}, true
		}
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "authentication-error") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyAffinity(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.affinity.co/auth/whoami")
}

func verifyWise(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.wise.com/2026Q3/me", "https://api.wise-sandbox.com/2026Q3/me"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyWistia(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.wistia.com/v1/account.json")
}

func verifyFlickr(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://www.flickr.com/services/rest/?method=flickr.test.echo&api_key=" + url.QueryEscape(secret) + "&format=json&nojsoncallback=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Stat string `json:"stat"`
			Code int    `json:"code"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Stat == "ok" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Stat == "fail" && response.Code == 100 {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyHelloSign(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.hellosign.com/v3/account", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyParseHub(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://www.parsehub.com/api/v2/projects?api_key=" + url.QueryEscape(secret) + "&offset=0&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyPackagecloud(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://packagecloud.io/api/v1/repos.json?per_page=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyOnfido(ctx context.Context, secret string) VerificationResult {
	host := "api.eu.onfido.com"
	low := strings.ToLower(secret)
	if strings.HasPrefix(low, "api_live_us.") || strings.HasPrefix(low, "api_sandbox_us.") {
		host = "api.us.onfido.com"
	} else if strings.HasPrefix(low, "api_live_ca.") || strings.HasPrefix(low, "api_sandbox_ca.") {
		host = "api.ca.onfido.com"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v3.6/applicants?page=1&per_page=1", nil)
	req.Header.Set("Authorization", "Token token="+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "authorization_error", "expired_token") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyNylas(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.us.nylas.com/v3/grants?limit=1&offset=0", "https://api.eu.nylas.com/v3/grants?limit=1&offset=0"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		result := verifyBearerGET(ctx, secret, endpoint)
		if result.Status == VerificationUnverified {
			result.Status = VerificationUnknown
			result.ErrorCategory = "credential_type"
			result.Message = "credential may be a Nylas OAuth client secret"
		}
		return result
	})
}

func verifyCapsuleCRM(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.capsulecrm.com/api/v2/users/current", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, _ []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
		}
		return VerificationResult{}, false
	})
}

func verifyPandaDoc(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.pandadoc.com/public/v1/members/current", "Authorization", "API-Key ")
}

func verifySparkPost(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.sparkpost.com/api/v1/account", "https://api.eu.sparkpost.com/api/v1/account"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusForbidden && containsAnyFold(string(body), "permission", "scope") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with insufficient permission"}, true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyAirbyte(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.airbyte.com/v1/workspaces?limit=1")
}

func verifyShipEngine(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.shipengine.com/v1/account/settings", "https://api.eu.shipengine.com/v1/account/settings"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyHeaderGET(ctx, secret, endpoint, "API-Key", "")
	})
}

func verifyGetResponse(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.getresponse.com/v3/accounts", "X-Auth-Token", "api-key ")
}

func verifyMailerLite(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://connect.mailerlite.com/api/timezones")
}

func verifyKoyeb(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.koyeb.com/v1/account/profile")
}

func verifyRebrandly(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.rebrandly.com/v1/account", "apikey", "")
}

func verifyCoinAPI(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://rest.coinapi.io/v1/limits", "X-CoinAPI-Key", "")
}

func verifyPinata(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pinata.cloud/data/testAuthentication", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode >= 200 && statusCode < 300 {
			var response struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(body, &response) != nil || response.Message != "Congratulations! You are communicating with the Pinata API!" {
				return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
			}
		}
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "INVALID_CREDENTIALS") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyTheOddsAPI(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.the-odds-api.com/v4/sports/?apiKey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "INVALID_KEY") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		if statusCode >= 200 && statusCode < 300 && !jsonArray(body) {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		return VerificationResult{}, false
	})
}

func verifyJotform(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"api.jotform.com", "eu-api.jotform.com", "hipaa-api.jotform.com"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		return verifyHeaderGET(ctx, secret, "https://"+host+"/user", "APIKEY", "")
	})
}

func verifyBraintree(ctx context.Context, secret string) VerificationResult {
	host := "payments.braintree-api.com"
	if strings.HasPrefix(secret, "access_token$sandbox$") {
		host = "payments.sandbox.braintree-api.com"
	} else if !strings.HasPrefix(secret, "access_token$production$") {
		return VerificationResult{Status: VerificationUnsupported, Message: "Braintree token environment is not recognized"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/graphql", strings.NewReader(`{"query":"query { ping }"}`))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Braintree-Version", "2019-01-01")
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Data struct {
				Ping string `json:"ping"`
			} `json:"data"`
			Errors []struct {
				Extensions struct {
					ErrorClass string `json:"errorClass"`
				} `json:"extensions"`
			} `json:"errors"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Data.Ping == "pong" && len(response.Errors) == 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		for _, providerErr := range response.Errors {
			if providerErr.Extensions.ErrorClass == "AUTHENTICATION" {
				return invalidCredentialResult(), true
			}
		}
		return unknownVerificationResult("authorization", "provider returned an ambiguous GraphQL response"), true
	})
}

func verifyImageKit(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.imagekit.io/v1/files?limit=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) && containsAnyFold(string(body), "your account cannot be authenticated") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyAirbrakeUser(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.airbrake.io/api/v4/projects?limit=1&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyBitGo(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://app.bitgo.com/api/v2/user/me", "https://app.bitgo-test.com/api/v2/user/me"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyPercy(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://percy.io/api/v1/projects", nil)
	req.Header.Set("Authorization", "Token "+secret)
	req.Header.Set("Accept", "application/vnd.percy+json; version=3")
	return verifyHTTPRequest(ctx, req)
}

func verifyNGC(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.ngc.nvidia.com/v2/users/me")
}

func verifyWitAI(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.wit.ai/apps?offset=1&limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if (statusCode == http.StatusBadRequest || statusCode == http.StatusUnauthorized) && containsAnyFold(string(body), "no-auth", "bad auth") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusBadRequest || statusCode == http.StatusUnauthorized {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyRailway(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://backboard.railway.com/graphql/v2"
	queries := []struct {
		header string
		body   string
		field  string
	}{
		{header: "Authorization", body: `{"query":"query { me { name email } }"}`, field: "email"},
		{header: "Project-Access-Token", body: `{"query":"query { projectToken { projectId environmentId } }"}`, field: "projectId"},
	}
	result := verifyEndpoints(ctx, []string{"account", "project"}, func(kind string) VerificationResult {
		query := queries[0]
		if kind == "project" {
			query = queries[1]
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(query.body))
		value := secret
		if query.header == "Authorization" {
			value = "Bearer " + secret
		}
		req.Header.Set(query.header, value)
		req.Header.Set("Content-Type", "application/json")
		return verifyHTTPRequestWithClassifier(ctx, req, classifyGraphQLIdentity(query.field))
	})
	result.Response = ""
	return result
}

func verifyTwelveData(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.twelvedata.com/api_usage?apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyAPIlayerKey)
}

func verifyExchangeRateAPI(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://v6.exchangerate-api.com/v6/" + url.PathEscape(secret) + "/quota"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Result    string `json:"result"`
			ErrorType string `json:"error-type"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Result == "success" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		switch response.ErrorType {
		case "invalid-key", "inactive-account":
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyGuardian(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://content.guardianapis.com/search?page-size=1&api-key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyNewsAPI(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://newsapi.org/v2/top-headlines?country=us&pageSize=1", nil)
	req.Header.Set("X-Api-Key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status string `json:"status"`
			Code   string `json:"code"`
		}
		if json.Unmarshal(body, &response) != nil {
			if statusCode >= 200 && statusCode < 300 {
				return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
			}
			return VerificationResult{}, false
		}
		if response.Status == "ok" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		switch response.Code {
		case "apiKeyInvalid", "apiKeyDisabled":
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func classifyAPIlayerKey(statusCode int, body []byte) (VerificationResult, bool) {
	if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
		return VerificationResult{}, false
	}
	var response struct {
		Status       string   `json:"status"`
		Code         int      `json:"code"`
		CurrentUsage *float64 `json:"current_usage"`
		PlanLimit    *float64 `json:"plan_limit"`
	}
	if json.Unmarshal(body, &response) != nil {
		if statusCode >= 200 && statusCode < 300 {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		return VerificationResult{}, false
	}
	if response.Status != "error" && response.CurrentUsage != nil && response.PlanLimit != nil {
		return VerificationResult{Status: VerificationVerified}, true
	}
	if response.Code == http.StatusUnauthorized {
		return invalidCredentialResult(), true
	}
	return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
}

func jsonArray(body []byte) bool {
	var value []any
	return json.Unmarshal(body, &value) == nil
}

func jsonObject(body []byte) bool {
	var value map[string]any
	return json.Unmarshal(body, &value) == nil && len(value) > 0
}

func verifyElasticEmail(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.elasticemail.com/v4/security/apikeys", nil)
	req.Header.Set("X-ElasticEmail-ApiKey", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusBadRequest && containsAnyFold(string(body), "apikey expired", "invalid api key") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusBadRequest {
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
		return VerificationResult{}, false
	})
}

func verifyImgix(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.imgix.com/api/v1/sources?page[limit]=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequest(ctx, req)
	if result.Status == VerificationUnverified {
		result.Status = VerificationUnknown
		result.ErrorCategory = "credential_type"
		result.Message = "credential may be an imgix secure URL token"
	}
	return result
}

func verifyKeyCDN(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.keycdn.com/zones.json", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyHarvest(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://id.getharvest.com/api/v2/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("User-Agent", "secret-sniffer")
	return verifyHTTPRequest(ctx, req)
}

func verifyCockroachCloud(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://cockroachlabs.cloud/api/v1/clusters?pagination.limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Cc-Version", "2024-09-16")
	result := verifyHTTPRequest(ctx, req)
	if result.Status == VerificationUnverified {
		result.Status = VerificationUnknown
		result.ErrorCategory = "credential_type"
		result.Message = "credential subtype could not be confirmed"
	}
	return result
}

func verifySingleStore(ctx context.Context, secret string) VerificationResult {
	if len(secret) != 64 || !isHex(secret) {
		return VerificationResult{Status: VerificationUnsupported, Message: "credential is not a documented SingleStore management API key"}
	}
	return verifyBearerGET(ctx, secret, "https://api.singlestore.com/v2/organizations/current")
}

func verifyPagarMe(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pagar.me/core/v5/orders?page=1&size=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyCodemagic(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.codemagic.io/apps", "x-auth-token", "")
}

func verifyStreak(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.streak.com/api/v1/users/me", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyQovery(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.qovery.com/me")
}

func verifyFulcrum(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.fulcrumapp.com/api/v2/users.json?page=1&per_page=1", "X-ApiToken", "")
}

func verifyMavenlink(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.mavenlink.com/api/v1/users.json?limit=1&offset=0")
}

func verifyAshby(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.ashbyhq.com/user.list", strings.NewReader(`{"limit":1}`))
	req.SetBasicAuth(secret, "")
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode < 200 || statusCode >= 300 {
			return VerificationResult{}, false
		}
		var response struct {
			Success *bool `json:"success"`
		}
		if json.Unmarshal(body, &response) != nil || response.Success == nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if *response.Success {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifySmartRecruiters(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"smart-token", "bearer"}, func(kind string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.smartrecruiters.com/users/me", nil)
		if kind == "smart-token" {
			req.Header.Set("X-SmartToken", secret)
		} else {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		return verifyHTTPRequest(ctx, req)
	})
}

func verifyJumpCloud(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"console.jumpcloud.com", "console.eu.jumpcloud.com", "console.in.jumpcloud.com"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		return verifyHeaderGET(ctx, secret, "https://"+host+"/api/systemusers?limit=1&skip=0", "x-api-key", "")
	})
}

func isHex(value string) bool {
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f' || char >= 'A' && char <= 'F') {
			return false
		}
	}
	return value != ""
}

func verifyHarness(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://app.harness.io/ng/api/user/currentUser", "x-api-key", "")
}

func verifySourcegraphCloud(ctx context.Context, secret string) VerificationResult {
	if strings.HasPrefix(secret, "sgp_local_") {
		return VerificationResult{Status: VerificationUnsupported, Message: "self-hosted Sourcegraph token requires instance context"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://sourcegraph.com/.api/graphql", strings.NewReader(`{"query":"query { currentUser { username } }"}`))
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyGraphQLIdentity("username"))
}

func verifySemaphore(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.semaphore.co/api/v4/account?apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyHunter(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.hunter.io/v2/account", "X-API-KEY", "")
}

func verifyRocketReach(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.rocketreach.co/api/v2/account/", "Api-Key", "")
}

func verifyZeroBounce(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.zerobounce.net/v2/getcredits?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response map[string]any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&response) != nil {
			return VerificationResult{}, false
		}
		var credits int64
		var err error
		switch value := response["Credits"].(type) {
		case json.Number:
			credits, err = value.Int64()
		case string:
			credits, err = strconv.ParseInt(value, 10, 64)
		default:
			err = errors.New("missing credits")
		}
		if err != nil {
			return unknownVerificationResult("provider_response", "provider returned an unexpected response"), true
		}
		if credits >= 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if credits == -1 {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyDetectify(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.detectify.com/rest/v3/ips?limit=1", "Authorization", "")
}

func verifyMixmax(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.mixmax.com/v1/users/me", "X-API-Token", "")
}

func verifyBunny(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bunny.net/user", nil)
	req.Header.Set("AccessKey", secret)
	result := verifyHTTPRequest(ctx, req)
	if result.Status == VerificationUnverified {
		result.Status = VerificationUnknown
		result.ErrorCategory = "credential_type"
		result.Message = "credential may be a Bunny storage password"
	}
	return result
}

func verifyUbidots(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://industrial.api.ubidots.com/api/v1.6/users/me/", "X-Auth-Token", "")
}

func verifyZohoCRM(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"www.zohoapis.com", "www.zohoapis.eu", "www.zohoapis.in", "www.zohoapis.com.au", "www.zohoapis.jp", "www.zohoapis.ca", "www.zohoapis.sa"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/crm/v8/users?type=CurrentUser", nil)
		req.Header.Set("Authorization", "Zoho-oauthtoken "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if containsAnyFold(string(body), "OAUTH_SCOPE_MISMATCH") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient scope"}, true
			}
			if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "INVALID_TOKEN") {
				return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyTatum(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tatum.io/v3/tatum/version", nil)
	req.Header.Set("x-api-key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && !containsAnyFold(string(body), "subscription.invalid", "subscription.not.active") {
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		return VerificationResult{}, false
	})
}

func verifyDialpad(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://dialpad.com/api/v2/company", "https://sandbox.dialpad.com/api/v2/company"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
}

func verifyCryptoCompare(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://min-api.cryptocompare.com/data/blockchain/latest?fsym=BTC", nil)
	req.Header.Set("Authorization", "Apikey "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Response string `json:"Response"`
			Message  string `json:"Message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Response == "Success" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Response == "Error" && containsAnyFold(response.Message, "valid auth key", "valid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyCloudinary(ctx context.Context, secret string) VerificationResult {
	parsed, err := url.Parse(secret)
	if err != nil || parsed.Scheme != "cloudinary" || parsed.User == nil || parsed.Host == "" {
		return VerificationResult{Status: VerificationUnsupported, Message: "Cloudinary URL could not be parsed safely"}
	}
	apiSecret, ok := parsed.User.Password()
	if !ok || parsed.User.Username() == "" {
		return VerificationResult{Status: VerificationUnsupported, Message: "Cloudinary URL is missing credentials"}
	}
	cloudName := parsed.Host
	if strings.ContainsAny(cloudName, ".:/\\") {
		return VerificationResult{Status: VerificationUnsupported, Message: "Cloudinary cloud name is invalid"}
	}
	hosts := []string{"api.cloudinary.com", "api-eu.cloudinary.com", "api-ap.cloudinary.com"}
	return verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		endpoint := "https://" + host + "/v1_1/" + url.PathEscape(cloudName) + "/config"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.SetBasicAuth(parsed.User.Username(), apiSecret)
		return verifyHTTPRequest(ctx, req)
	})
}

func verifyChartMogul(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.chartmogul.com/v1/account", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyIntrinio(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api-v2.intrinio.com/account/current_usage")
}

func verifyOmnisend(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.omnisend.com/api/brands/current", nil)
	req.Header.Set("Authorization", "Omnisend-API-Key "+secret)
	req.Header.Set("Omnisend-Version", "2026-03-15")
	return verifyHTTPRequest(ctx, req)
}

func verifyEasyship(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://public-api.easyship.com/2024-09/account")
}

func verifyTemporalCloud(ctx context.Context, secret string) VerificationResult {
	return positiveOnlyVerification(verifyBearerGET(ctx, secret, "https://saas-api.tmprl.cloud/cloud/current-identity"), "credential may be a Temporal client secret")
}

func verifyCircle(ctx context.Context, secret string) VerificationResult {
	return positiveOnlyVerification(verifyBearerGET(ctx, secret, "https://api.circle.com/v1/configuration"), "credential may be a Circle webhook secret")
}

func verifyHightouch(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.hightouch.com/api/v1/workspaces")
}

func verifyPendo(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://app.pendo.io/api/v1/metadata/schema/account", "x-pendo-integration-key", "")
}

func verifyNorthflank(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.northflank.com/v1/projects")
}

func verifyFlagsmith(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://edge.api.flagsmith.com/api/v1/flags/", nil)
	req.Header.Set("X-Environment-Key", secret)
	return positiveOnlyVerification(verifyHTTPRequest(ctx, req), "credential subtype could not be confirmed")
}

func verifyConfigCat(ctx context.Context, secret string) VerificationResult {
	parts := strings.Split(secret, "/")
	for i := range parts {
		if parts[i] == "" {
			return VerificationResult{Status: VerificationUnsupported, Message: "ConfigCat SDK key path is invalid"}
		}
		parts[i] = url.PathEscape(parts[i])
	}
	endpoint := "https://cdn-global.configcat.com/configuration-files/" + strings.Join(parts, "/") + "/config_v6.json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyAfterShip(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.aftership.com/tracking/2026-07/couriers", nil)
	req.Header.Set("as-api-key", secret)
	return verifyHTTPRequest(ctx, req)
}

func verifyGrowthBook(ctx context.Context, secret string) VerificationResult {
	if !strings.HasPrefix(secret, "secret_") {
		return VerificationResult{Status: VerificationUnsupported, Message: "GrowthBook client and SDK keys are not secret API keys"}
	}
	return verifyBearerGET(ctx, secret, "https://api.growthbook.io/api/v1/projects?limit=1")
}

func verifyPersona(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.withpersona.com/api/v1/inquiries?page%5Bsize%5D=1&fields%5Binquiry%5D=status"
	return positiveOnlyVerification(verifyBearerGET(ctx, secret, endpoint), "credential may be a Persona webhook secret")
}

func verifyIncrease(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.increase.com/programs?limit=1", "https://sandbox.increase.com/programs?limit=1"}
	result := verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		return verifyBearerGET(ctx, secret, endpoint)
	})
	return positiveOnlyVerification(result, "credential may be an Increase webhook or OAuth client secret")
}

func verifyAPISports(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://v3.football.api-sports.io/status", nil)
	req.Header.Set("x-apisports-key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Results int             `json:"results"`
			Errors  json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		errorsText := strings.TrimSpace(string(response.Errors))
		if response.Results == 1 && (errorsText == "[]" || errorsText == "{}") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if containsAnyFold(errorsText, "missing application key", "token") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyOpenCage(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.opencagedata.com/geocode/v1/json?q=0%2C0&no_annotations=1&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequest(ctx, req)
}

func verifyMediastack(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.mediastack.com/v1/news?access_key=" + url.QueryEscape(secret) + "&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyAPIlayerAccessKey)
}

func verifyMailboxlayer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://apilayer.net/api/check?access_key=" + url.QueryEscape(secret) + "&email=noreply%40example.com&smtp=0"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyAPIlayerAccessKey)
}

func verifyPhotoRoom(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://image-api.photoroom.com/v1/account", nil)
	req.Header.Set("x-api-key", secret)
	return positiveOnlyVerification(verifyHTTPRequest(ctx, req), "credential format could not be confirmed as a PhotoRoom secret key")
}

func positiveOnlyVerification(result VerificationResult, message string) VerificationResult {
	if result.Status == VerificationUnverified {
		result.Status = VerificationUnknown
		result.ErrorCategory = "credential_type"
		result.Message = message
	}
	return result
}

func classifyAPIlayerAccessKey(statusCode int, body []byte) (VerificationResult, bool) {
	if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
		return VerificationResult{}, false
	}
	var response struct {
		Success *bool `json:"success"`
		Error   struct {
			Code any    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		if statusCode >= 200 && statusCode < 300 {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		return VerificationResult{}, false
	}
	if response.Success != nil && !*response.Success {
		if containsAnyFold(fmt.Sprint(response.Error.Code), "101") || containsAnyFold(response.Error.Type, "invalid_access_key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	}
	return VerificationResult{}, false
}

func verifySaladCloud(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.salad.com/api/public", "Salad-Api-Key", "")
}

func verifyAyrshare(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ayrshare.com/api/user", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), `"code":102`, "api key not valid") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyBitBar(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloud.bitbar.com/api/me", nil)
	req.SetBasicAuth(secret, "")
	return verifyHTTPRequest(ctx, req)
}

func verifyRestpack(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://restpack.io/api/html2pdf/usage", "X-Access-Token", "")
}

func verifyTMetric(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.tmetric.com/api/v3/user")
}

func verifyFlat(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.flat.io/v2/me")
}

func verifySupernotes(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.supernotes.app/v1/user/token", "Api-Key", "")
}

func verifyStormboard(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.stormboard.com/users/profile", nil)
	req.Header.Set("X-API-Key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "invalid api key") {
			return invalidCredentialResult(), true
		}
		return VerificationResult{}, false
	})
}

func verifyCloudplan(ctx context.Context, secret string) VerificationResult {
	return verifyHeaderGET(ctx, secret, "https://api.cloudplan.biz/api/user/me", "session_id", "")
}

func verifyClustdoc(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://app.clustdoc.com/api/users")
}

func verifyCheckly(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.checklyhq.com/v1/accounts")
}

func verifyKustomer(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://api.kustomerapp.com/v1/users/current")
}

func verifySalesloft(ctx context.Context, secret string) VerificationResult {
	return positiveOnlyVerification(verifyBearerGET(ctx, secret, "https://api.salesloft.com/v2/me"), "credential subtype could not be confirmed as a bearer token")
}

func verifyTiingo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tiingo.com/api/test", nil)
	req.Header.Set("Authorization", "Token "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch response.Message {
		case "You successfully sent a request":
			return VerificationResult{Status: VerificationVerified}, true
		case "Auth Token was not correct":
			return invalidCredentialResult(), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyWorkable(ctx context.Context, secret string) VerificationResult {
	return verifyBearerGET(ctx, secret, "https://workable.com/spi/v3/accounts")
}

func verifySalesforce(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://login.salesforce.com/services/oauth2/userinfo", "https://test.salesforce.com/services/oauth2/userinfo"}
	return verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusForbidden && strings.TrimSpace(string(body)) == "Bad_OAuth_Token" {
				return invalidCredentialResult(), true
			}
			return VerificationResult{}, false
		})
	})
}

func verifyGusto(ctx context.Context, secret string) VerificationResult {
	endpoints := []string{"https://api.gusto.com/v1/token_info", "https://api.gusto-demo.com/v1/token_info"}
	result := verifyEndpoints(ctx, endpoints, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("X-Gusto-API-Version", "2026-06-15")
		return verifyHTTPRequest(ctx, req)
	})
	return positiveOnlyVerification(result, "credential may be a Gusto OAuth client secret")
}

func verifyIBMCloud(ctx context.Context, secret string) VerificationResult {
	body := "grant_type=" + url.QueryEscape("urn:ibm:params:oauth:grant-type:apikey") + "&apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://iam.cloud.ibm.com/identity/token", strings.NewReader(body))
	req.SetBasicAuth("bx", "bx")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyTokenExchange("BXNIM0415E"))
	result.Response = ""
	return result
}

func verifyPlatformSH(ctx context.Context, secret string) VerificationResult {
	body := "grant_type=api_token&api_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.api.platform.sh/oauth2/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyTokenExchange("invalid_grant", "invalid_token"))
	result.Response = ""
	return result
}

func verifyEtherscan(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.etherscan.io/v2/api?chainid=1&module=account&action=balance&address=0x0000000000000000000000000000000000000000&tag=latest&apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Result  string `json:"result"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Status == "1" && response.Message == "OK" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Status == "0" && containsAnyFold(response.Result, "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyOpenWeather(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.openweathermap.org/data/2.5/weather?q=London&appid="+url.QueryEscape(secret), []string{"weather", "main"}, "invalid api key")
}

func verifyTomorrowIO(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.tomorrow.io/v4/weather/realtime?location=0%2C0&apikey="+url.QueryEscape(secret), []string{"data", "location"}, "invalid auth", "invalid api key")
}

func verifyHERE(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://geocode.search.hereapi.com/v1/geocode?q=Berlin&limit=1&apiKey="+url.QueryEscape(secret), []string{"items"}, "apikey invalid", "apikey not found")
}

func verifyPolygon(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.polygon.io/v3/reference/tickers?limit=1&apiKey="+url.QueryEscape(secret), []string{"request_id", "results"}, "unknown api key")
}

func verifyAbuseIPDB(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.abuseipdb.com/api/v2/check?ipAddress=192.0.2.1&maxAgeInDays=1", nil)
	req.Header.Set("Key", secret)
	req.Header.Set("Accept", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"ipAddress", "abuseConfidenceScore"}, "authentication failed. your api key is either missing, incorrect, or revoked"))
}

func verifyIPStack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.ipstack.com/192.0.2.1?access_key="+url.QueryEscape(secret), []string{"ip"}, "invalid_access_key")
}

func verifyIPGeolocation(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.ipgeolocation.io/v3/ipgeo?ip=192.0.2.1&fields=ip&apiKey="+url.QueryEscape(secret), []string{"ip"}, "provided api key is not valid")
}

func verifyWeatherstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.weatherstack.com/current?query=London&access_key="+url.QueryEscape(secret), []string{"request", "location", "current"}, "invalid_access_key")
}

func verifyAccuWeather(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://dataservice.accuweather.com/locations/v1/cities/search?q=London&apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized {
			var response struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			}
			if json.Unmarshal(body, &response) == nil && strings.EqualFold(response.Code, "Unauthorized") && containsAnyFold(response.Message, "API authorization failed") {
				return invalidCredentialResult(), true
			}
			return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonArray(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyMapQuest(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://www.mapquestapi.com/geocoding/v1/address?location=Washington%2CDC&thumbMaps=false&maxResults=1&key="+url.QueryEscape(secret), []string{"info", "results"}, "the appkey submitted with this request is invalid")
}

func verifyFixer(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://data.fixer.io/api/symbols?access_key="+url.QueryEscape(secret), []string{"success", "symbols"}, "invalid_access_key")
}

func verifyCurrencyLayer(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.currencylayer.com/list?access_key="+url.QueryEscape(secret), []string{"success", "currencies"}, "invalid_access_key")
}

func verifyExchangeRatesAPI(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.exchangeratesapi.io/v1/symbols?access_key="+url.QueryEscape(secret), []string{"success", "symbols"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyMarketstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.marketstack.com/v2/tickers?limit=1&access_key="+url.QueryEscape(secret), []string{"pagination", "data"}, "invalid_access_key")
}

func verifyPositionstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.positionstack.com/v1/forward?query=Berlin&limit=1&access_key="+url.QueryEscape(secret), []string{"data"}, "invalid_access_key")
}

func verifyFinnhub(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://finnhub.io/api/v1/quote?symbol=AAPL&token="+url.QueryEscape(secret), []string{"c", "t"}, "invalid api key")
}

func verifyTradier(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tradier.com/v1/user/profile", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"profile"}, "invalid access token", "keymanagement.service.invalid_access_token"))
}

func verifyGeocodio(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.geocod.io/v2/geocode?q=Washington%2CDC&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"results"}, "invalid api key"))
}

func verifyWorldWeather(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.worldweatheronline.com/premium/v1/weather.ashx?q=London&num_of_days=0&format=json&key="+url.QueryEscape(secret), []string{"request", "current_condition"}, "api key is invalid")
}

func verifyFinancialModelingPrep(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://financialmodelingprep.com/stable/available-exchanges?apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "invalid api key") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonArray(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyCurrencyFreaks(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.currencyfreaks.com/v2.0/rates/latest?symbols=EUR&apikey="+url.QueryEscape(secret), []string{"date", "base", "rates"}, "provided api key is invalid")
}

func verifyCurrencyScoop(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.currencybeacon.com/v1/currencies?api_key="+url.QueryEscape(secret), []string{"meta", "response"}, "missing or invalid api credentials")
}

func verifyFastForex(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.fastforex.io/fetch-one?from=USD&to=EUR&api_key="+url.QueryEscape(secret), []string{"base", "result", "updated"}, "api key not valid")
}

func verifyVATLayer(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://apilayer.net/api/rate?country_code=GB&access_key="+url.QueryEscape(secret), []string{"success", "country_code", "standard_rate"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyAviationstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.aviationstack.com/v1/flights?limit=1&access_key="+url.QueryEscape(secret), []string{"pagination", "data"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyCalendarific(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://calendarific.com/api/v2/countries?api_key="+url.QueryEscape(secret), []string{"meta", "response", "countries"}, "missing or invalid api credentials")
}

func verifyEthplorer(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.ethplorer.io/getLastBlock?apiKey="+url.QueryEscape(secret), []string{"lastBlock"}, "invalid api key")
}

func verifyWeatherbit(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.weatherbit.io/v2.0/current?lat=0&lon=0&key="+url.QueryEscape(secret), []string{"count", "data"}, "api key not valid, or not yet activated")
}

func verifyVPNAPI(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://vpnapi.io/api/8.8.8.8?key="+url.QueryEscape(secret), []string{"ip", "security", "location", "network"}, "invalid api key")
}

func verifyIPQualityScore(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://www.ipqualityscore.com/api/json/ip/" + url.PathEscape(secret) + "/8.8.8.8"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch {
		case response.Success:
			return VerificationResult{Status: VerificationVerified}, true
		case containsAnyFold(response.Message, "invalid or unauthorized key"):
			return invalidCredentialResult(), true
		case containsAnyFold(response.Message, "insufficient credits"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with insufficient credits"}, true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyNumverify(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://apilayer.net/api/validate?number=14155552671&access_key="+url.QueryEscape(secret), []string{"valid", "number", "country_code"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyGeoapify(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.geoapify.com/v1/geocode/search?text=Berlin&limit=1&apiKey="+url.QueryEscape(secret), []string{"type", "features"}, "invalid apikey")
}

func verifyGraphHopper(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://graphhopper.com/api/1/geocode?q=Berlin&limit=1&key="+url.QueryEscape(secret), []string{"hits"}, "wrong credentials")
}

func verifyKickbox(ctx context.Context, secret string) VerificationResult {
	return verifyEndpoints(ctx, []string{"https://api.kickbox.com", "https://api.eu.kickbox.com"}, func(baseURL string) VerificationResult {
		endpoint := baseURL + "/v2/verify?email=deliverable%40example.com&apikey=" + url.QueryEscape(secret)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
				return VerificationResult{}, false
			}
			response := string(body)
			switch {
			case containsAnyFold(response, "invalid api key"):
				return invalidCredentialResult(), true
			case containsAnyFold(response, "insufficient balance"):
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with insufficient balance"}, true
			case statusCode >= 200 && statusCode < 300 && jsonHasAllFields(body, "success", "result", "email"):
				return VerificationResult{Status: VerificationVerified}, true
			default:
				return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
			}
		})
	})
}

func verifyOpenUV(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.openuv.io/api/v1/uv?lat=0&lng=0", nil)
	req.Header.Set("x-access-token", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"result", "uv", "uv_time"}, "user with api key not found"))
}

func verifyPandaScore(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pandascore.co/videogames?per_page=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("invalid credentials"))
}

func verifyCountryLayer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.countrylayer.com/v2/all?access_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("invalid_access_key", "not supplied a valid api access key"))
}

func verifyCommoditiesAPI(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://commodities-api.com/api/symbols?access_key="+url.QueryEscape(secret), []string{"success", "symbols"}, "invalid_access_key", "invalid api key was specified")
}

func verifyWalkScore(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.walkscore.com/score?format=json&address=1%20Main%20St&lat=47.6&lon=-122.3&wsapikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status int `json:"status"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch response.Status {
		case 1, 2:
			return VerificationResult{Status: VerificationVerified}, true
		case 40:
			return invalidCredentialResult(), true
		case 41:
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key with exhausted quota"}, true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
}

func verifyVeriphone(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.veriphone.io/v2/credits", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"email", "counter", "active"}, "invalid api key"))
}

func verifyRAWG(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.rawg.io/api/platforms?page_size=1&key="+url.QueryEscape(secret), []string{"count", "results"}, "api key is not found")
}

func verifyMailmodo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mailmodo.com/api/v1/campaigns?type=CONTACT_LIST", nil)
	req.Header.Set("mmApiKey", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data"}, "wrong api key", "unauthorized login"))
	result.Response = ""
	return result
}

func verifySalesblink(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://run.salesblink.io/api/public/lists", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("unauthorized api key"))
	result.Response = ""
	return result
}

func verifyRoute4Me(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.route4me.com/api.v4/address_book.php?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("invalid api key"))
	result.Response = ""
	return result
}

func verifyButterCMS(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.buttercms.com/v2/posts/?page_size=1&auth_token="+url.QueryEscape(secret), []string{"data", "meta"}, "invalid token")
	result.Response = ""
	return result
}

func verifyLanguageLayer(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.languagelayer.com/languages?access_key="+url.QueryEscape(secret), []string{"results"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyIPAPI(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.ipapi.com/8.8.8.8?access_key="+url.QueryEscape(secret), []string{"ip", "continent_code"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyTomTom(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.tomtom.com/map/1/tile/basic/main/0/0/0.png?view=Unified&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "missing valid authentication credentials") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyVisualCrossing(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/LA/today?include=current&contentType=json&key=" + url.QueryEscape(secret)
	return verifyQueryAPI(ctx, endpoint, []string{"resolvedAddress", "timezone"}, "no account found with api key")
}

func verifyPixabay(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://pixabay.com/api/?q=test&per_page=3&safesearch=true&key="+url.QueryEscape(secret), []string{"total", "totalHits", "hits"}, "invalid or missing api key")
}

func verifySpoonacular(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.spoonacular.com/recipes/complexSearch?query=pasta&number=1&apiKey=" + url.QueryEscape(secret)
	return verifyQueryAPI(ctx, endpoint, []string{"offset", "number", "results", "totalResults"}, "you are not authorized")
}

func verifyUnsplash(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.unsplash.com/photos?per_page=1", nil)
	req.Header.Set("Authorization", "Client-ID "+secret)
	req.Header.Set("Accept-Version", "v1")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("access token is invalid", "invalid access key"))
}

func verifyDataGov(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.ers.usda.gov/data/arms/state?api_key=" + url.QueryEscape(secret)
	return verifyQueryAPI(ctx, endpoint, []string{"data"}, "api_key_invalid", "invalid api_key was supplied")
}

func verifyAbstractAPI(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://exchange-rates.abstractapi.com/v1/live/?base=USD&api_key="+url.QueryEscape(secret), []string{"base", "exchange_rates"}, "invalid api key provided")
}

func verifyAPILayer(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apilayer.com/number_verification/countries", nil)
	req.Header.Set("apikey", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"country_code", "country_name"}, "invalid authentication credentials"))
}

func verifyInfura(ctx context.Context, secret string) VerificationResult {
	body := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	endpoint := "https://mainnet.infura.io/v3/" + url.PathEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyJSONRPC("invalid project id"))
}

func verifyMoralis(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://deep-index.moralis.io/api/v2/0xd8da6bf26964af9d7eed9e03e53415d37aa96045/nft?chain=eth&format=decimal&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("X-API-Key", secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"result"}, "api key is not valid"))
}

func verifyDiffbot(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.diffbot.com/v4/account?days=1&token="+url.QueryEscape(secret), []string{"token", "status", "planCredits"}, "not authorized api token")
	result.Response = ""
	return result
}

func verifyRestpackScreenshot(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://restpack.io/api/screenshot/usage", nil)
	req.Header.Set("X-Access-Token", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "invalidaccesstoken", "access token is invalid") {
			return unknownVerificationResult("authorization", "token validity and subscription status could not be distinguished"), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "usage", "limit", "remaining") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyBrowshot(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.browshot.com/api/v1/account/info?key=" + url.QueryEscape(secret)
	return verifyQueryAPI(ctx, endpoint, []string{"balance"}, "wrong or missing api key")
}

func verifyTwitterBearer(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/tweets/20", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "unauthorized") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAllFields(body, "data", "id") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
	})
}

func verifyAlchemy(ctx context.Context, secret string) VerificationResult {
	body := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	endpoint := "https://eth-mainnet.g.alchemy.com/v2/" + url.PathEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return verifyHTTPRequestWithClassifier(ctx, req, classifyJSONRPC("must be authenticated"))
}

func verifyDetectLanguage(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ws.detectlanguage.com/v3/account/status", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"status", "requests", "daily_requests_limit"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyKlipfolio(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.klipfolio.com/api/1.0/users?limit=1", nil)
	req.Header.Set("kf-api-key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"meta", "success"}, "auth_fail", "credentials you provided are invalid"))
	result.Response = ""
	return result
}

func verifyWhoxy(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.whoxy.com/?account=balance&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status       int    `json:"status"`
			StatusReason string `json:"status_reason"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Status == 1 && jsonHasAnyField(body, "balance", "credits") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Status == 0 && containsAnyFold(response.StatusReason, "incorrect api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyUserstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.userstack.com/detect?ua=Mozilla%2F5.0&access_key="+url.QueryEscape(secret), []string{"ua", "type"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyIP2Location(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.ip2location.io/?ip=8.8.8.8&key="+url.QueryEscape(secret), []string{"ip", "country_code"}, "invalid api key")
}

func verifyIPInfoDB(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.ipinfodb.com/v3/ip-country/?ip=8.8.8.8&format=json&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			StatusCode string `json:"statusCode"`
			Message    string `json:"message"`
			IPAddress  string `json:"ipAddress"`
			Country    string `json:"countryCode"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.StatusCode == "OK" && response.IPAddress == "8.8.8.8" && response.Country != "" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.StatusCode == "ERROR" && containsAnyFold(response.Message, "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func verifyGeckoboard(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.geckoboard.com/", nil)
	req.SetBasicAuth(secret, "")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "api key you provided is invalid") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyYelp(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.yelp.com/v3/businesses/search?term=delis&latitude=37.786882&longitude=-122.399972&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"total", "businesses"}, "unauthorized_access_token", "access token provided is not currently able"))
}

func verifyLinkPreview(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.linkpreview.net/?q=https%3A%2F%2Fexample.com&key="+url.QueryEscape(secret), []string{"url", "title", "description"}, "invalid or blank api access key")
}

func verifyScraperAPI(ctx context.Context, secret string) VerificationResult {
	result := verifyFetchedExample(ctx, "https://api.scraperapi.com?url=https%3A%2F%2Fexample.com&api_key="+url.QueryEscape(secret), "unauthorized request", "api key is valid")
	result.Response = ""
	return result
}

func verifyScrapestack(ctx context.Context, secret string) VerificationResult {
	result := verifyFetchedExample(ctx, "https://api.scrapestack.com/scrape?url=https%3A%2F%2Fexample.com&access_key="+url.QueryEscape(secret), "invalid_access_key", "usage limit", "subscription plan does not support")
	result.Response = ""
	return result
}

func verifySerpstack(ctx context.Context, secret string) VerificationResult {
	return verifyQueryAPI(ctx, "https://api.serpstack.com/search?query=test&access_key="+url.QueryEscape(secret), []string{"request", "search_url"}, "invalid_access_key", "not supplied a valid api access key")
}

func verifyMoosend(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.moosend.com/v3/lists.json?format=json&PageSize=1&apikey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Code  int             `json:"Code"`
			Error string          `json:"Error"`
			Data  json.RawMessage `json:"Context"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Code == 0 && len(response.Data) > 0 && string(response.Data) != "null" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Code == 100 && response.Error == "USER_NOT_FOUND" {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyCanny(ctx context.Context, secret string) VerificationResult {
	body, _ := json.Marshal(map[string]any{"apiKey": secret, "limit": 1})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://canny.io/api/v1/boards/list", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"boards"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyProxyCrawl(ctx context.Context, secret string) VerificationResult {
	result := verifyFetchedExample(ctx, "https://api.crawlbase.com/?url=https%3A%2F%2Fexample.com&token="+url.QueryEscape(secret), "token is invalid", "api token is valid")
	result.Response = ""
	return result
}

func verifyCodequiry(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://codequiry.com/api/v1/checks", nil)
	req.Header.Set("apikey", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("unauthorized", "api key is valid"))
	result.Response = ""
	return result
}

func verifyDyspatch(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.dyspatch.io/templates", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.dyspatch.2020.11+json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if containsAnyFold(string(body), "limited_usage") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted key"}, true
		}
		return classifyReadOnlyAPI([]string{"data"}, "no valid authorization credentials")(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifySignUpGenius(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.signupgenius.com/v2/k/user/profile/?user_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "authentication failed") {
			return invalidCredentialResult(), true
		}
		var response struct {
			Success bool `json:"success"`
			Data    struct {
				MemberID int `json:"memberid"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &response) == nil && statusCode >= 200 && statusCode < 300 && response.Success && response.Data.MemberID > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifySportsMonk(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sportmonks.com/v3/football/leagues?per_page=1", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data", "rate_limit", "requested_entity"}, "invalid token provided"))
	result.Response = ""
	return result
}

func verifyStockData(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.stockdata.org/v1/data/quote?symbols=AAPL&api_token="+url.QueryEscape(secret), []string{"meta", "requested", "returned", "data"}, "invalid_api_token", "invalid api token was supplied")
	result.Response = ""
	return result
}

func verifyUPCDatabase(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.upcdatabase.org/account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success bool `json:"success"`
			Error   struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Success && jsonHasAllFields(body, "api_subscription", "api_limits", "api_remain") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if !response.Success && containsAnyFold(response.Error.Message, "api key is invalid") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifySimFin(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://backend.simfin.com/api/v3/companies/list?api-key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("full authentication is required"))
	result.Response = ""
	return result
}

func verifyTravelpayouts(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.travelpayouts.com/aviasales/v3/prices_for_dates?origin=MAD&destination=BCN&one_way=true&limit=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("X-Access-Token", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "unauthorized") {
			return invalidCredentialResult(), true
		}
		var response struct {
			Success bool            `json:"success"`
			Data    json.RawMessage `json:"data"`
		}
		if json.Unmarshal(body, &response) == nil && statusCode >= 200 && statusCode < 300 && response.Success && len(response.Data) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyAmbee(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ambeedata.com/latest/by-lat-lng?lat=12&lng=77", nil)
	req.Header.Set("x-api-key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "invalid authentication key") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "stations", "data", "airQuality", "weather") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyNewsCatcher(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://v3-api.newscatcherapi.com/api/subscription", nil)
	req.Header.Set("x-api-token", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"plan", "plan_calls", "remaining_calls", "concurrent_calls", "historical_days"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyStormGlass(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.stormglass.io/v2/weather/point?lat=58.7984&lng=17.8081&params=windSpeed", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"hours", "meta"}, "api key is invalid"))
	result.Response = ""
	return result
}

func verifyPeopleDataLabs(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.peopledatalabs.com/v5/person/enrich", nil)
	req.Header.Set("X-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		response := string(body)
		switch {
		case statusCode == http.StatusUnauthorized && containsAnyFold(response, "invalid api key", "authentication_error"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusBadRequest && containsAnyFold(response, "invalid_request_error", "minimum inputs", "missing"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated the key before validating input"}, true
		case statusCode == http.StatusPaymentRequired:
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated an exhausted key"}, true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
}

func verifyAirVisual(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.airvisual.com/v2/countries?key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status string          `json:"status"`
			Data   json.RawMessage `json:"data"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Status == "success" && len(response.Data) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusForbidden && response.Status == "fail" && containsAnyFold(string(response.Data), "forbidden") {
			return unknownVerificationResult("authorization", "provider did not distinguish invalid credentials from plan restrictions"), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyHolidayAPI(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://holidayapi.com/v1/countries?country=US&key="+url.QueryEscape(secret), []string{"status", "requests", "countries"}, "invalid api key")
	result.Response = ""
	return result
}

func verifyWorldCoinIndex(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://www.worldcoinindex.com/apiservice/ticker?label=ethbtc&fiat=btc&key="+url.QueryEscape(secret), []string{"Markets", "Label", "Price", "Timestamp"}, "use a right key")
	result.Response = ""
	return result
}

func verifyCraftMyPDF(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.craftmypdf.com/v1/get-account-info", nil)
	req.Header.Set("X-API-KEY", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"status", "data"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyGlassnode(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.glassnode.com/v1/metadata/metrics?a=BTC", nil)
	req.Header.Set("X-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("authorization required", "invalid api key"))
	result.Response = ""
	return result
}

func verifyFlightAPI(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.flightapi.io/iata/" + url.PathEscape(secret) + "?name=london&type=airport"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("unauthorized request"))
	result.Response = ""
	return result
}

func verifyMockaroo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mockaroo.com/api/types", nil)
	req.Header.Set("X-API-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"types", "name"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyBeamer(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.getbeamer.com/v0/url", nil)
	req.Header.Set("Beamer-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "api key is invalid") {
			return invalidCredentialResult(), true
		}
		var configuredURL string
		_ = json.Unmarshal(body, &configuredURL)
		if configuredURL == "" {
			var response struct {
				URL string `json:"url"`
			}
			if json.Unmarshal(body, &response) == nil {
				configuredURL = response.URL
			}
		}
		if statusCode >= 200 && statusCode < 300 {
			parsed, err := url.Parse(configuredURL)
			if err == nil && parsed.Scheme == "https" && parsed.Host != "" {
				return VerificationResult{Status: VerificationVerified}, true
			}
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyCurrentsAPI(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.currentsapi.services/v1/latest-news", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"status", "news"}, "invalid token"))
	result.Response = ""
	return result
}

func verifyUClassify(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.uclassify.com/v1/uClassify/Sentiment", nil)
	req.Header.Set("Authorization", "Token "+secret)
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("doesn't exist", "invalid api key"))
	result.Response = ""
	return result
}

func verifyShotstack(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.shotstack.io/edit/stage/templates", "https://api.shotstack.io/edit/v1/templates"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("x-api-key", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"success", "response", "templates"}, "invalid or disabled api key"))
	})
	result.Response = ""
	return result
}

func verifyUpLead(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.uplead.com/v2/credits", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"credits"}, "api key is invalid"))
	result.Response = ""
	return result
}

func verifyConvertAPI(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://v2.convertapi.com/user?auth=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), "invalid or missing api credentials") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "Id", "id", "SecondsLeft", "seconds_left", "ConversionsTotal") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyBestTime(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://besttime.app/api/v1/keys/" + url.PathEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status  string `json:"status"`
			Valid   bool   `json:"valid"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Status == "OK" && response.Valid {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if !response.Valid && containsAnyFold(response.Message, "invalid api_key_private") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyAPITemplate(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apitemplate.io/v1/list-templates", nil)
	req.Header.Set("X-API-KEY", secret)
	return verifyPrivateCollection(ctx, req, "invalid api key")
}

func verifyAutoklose(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.autoklose.com/api/me/?api_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Accept", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"email"}, "api key is invalid"))
	result.Response = ""
	return result
}

func verifyTicketTailor(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tickettailor.com/v1/orders?limit=1", nil)
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")
	return verifyPrivateCollection(ctx, req)
}

func verifyNightfall(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.nightfall.ai/v3/detection-rules", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, `"code":40101`, "unauthorized")
}

func verifyReplyIO(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.reply.io/v1/people?limit=1", nil)
	req.Header.Set("X-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyPartnerStack(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.partnerstack.com/api/v2/partnerships", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "token invalid or archived")
}

func verifyPepipost(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pepipost.com/v5.1/domain/getDomains?domain=pepisandbox.com", nil)
	req.Header.Set("api_key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data"}, "invalid api_key"))
	result.Response = ""
	return result
}

func verifySignable(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.signable.co.uk/v1/templates?offset=0&limit=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyPrivateCollection(ctx, req, "authentication failed", `"code":10002`)
}

func verifySnipcart(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.snipcart.com/api/orders?limit=1", nil)
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")
	return verifyPrivateCollection(ctx, req)
}

func verifySimpleSat(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.simplesat.io/api/answers/?page_size=1", nil)
	req.Header.Set("X-Simplesat-Token", secret)
	return verifyPrivateCollection(ctx, req, "invalid token")
}

func verifySendbirdOrganization(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://gate.sendbird.com/api/v2/applications", nil)
	req.Header.Set("SENDBIRDORGANIZATIONAPITOKEN", secret)
	return verifyPrivateCollection(ctx, req, "authentication information invalid")
}

func verifyShipday(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.shipday.com/carriers", nil)
	req.Header.Set("Authorization", "Basic "+secret)
	return verifyPrivateCollection(ctx, req)
}

func verifySignaturit(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.signaturit.com/v3/signatures.json?limit=1", "https://api.sandbox.signaturit.com/v3/signatures.json?limit=1"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("invalid_grant", "access token provided is invalid"))
	})
	result.Response = ""
	return result
}

func verifyIconfinder(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.iconfinder.com/v4/iconsets?count=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "provided api key is invalid")
}

func verifyHappyScribe(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.happyscribe.com/api/v1/transcriptions", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "invalid api key")
}

func verifyNimble(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.nimble.com/api/v1/myself", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "access token is invalid or expired"))
	result.Response = ""
	return result
}

func verifyZenkit(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://base.zenkit.com/api/v1/users/me", nil)
	req.Header.Set("Zenkit-API-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "unauthenticated"))
	result.Response = ""
	return result
}

func verifyPrivateCollection(ctx context.Context, req *http.Request, invalidMarkers ...string) VerificationResult {
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse(invalidMarkers...))
	result.Response = ""
	return result
}

func verifySpectralOps(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://get.spectralops.io/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyVoicegain(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.voicegain.ai/v1/sa/config", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "unauthorized") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("authorization", "provider authentication response was ambiguous"), true
	})
	result.Response = ""
	return result
}

func verifyGetGeoAPI(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.getgeoapi.com/v2/currency/list?api_key="+url.QueryEscape(secret), []string{"status", "currencies"}, "invalid api key")
	result.Response = ""
	return result
}

func verifyGeocodify(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.geocodify.com/v2/geocode?api_key="+url.QueryEscape(secret), []string{"meta", "response"}, "missing or invalid api credentials")
	result.Response = ""
	return result
}

func verifyClearbit(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://person.clearbit.com/v1/people/email/alex@alexmaccaw.com", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id", "name"}, "invalid_api_key", "invalid api key provided"))
	result.Response = ""
	return result
}

func verifyPDFLayer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.pdflayer.com/api/convert?document_url=https%3A%2F%2Fexample.com&access_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyBinaryResponse([][]byte{[]byte("%PDF-")}, "invalid_access_key", "not supplied a valid api access key"))
	result.Response = ""
	return result
}

func verifyScreenshotLayer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.screenshotlayer.com/api/capture?url=https%3A%2F%2Fexample.com&access_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyBinaryResponse([][]byte{[]byte("\x89PNG\r\n\x1a\n"), {0xff, 0xd8, 0xff}}, "invalid_access_key", "not supplied a valid api access key"))
	result.Response = ""
	return result
}

func verifyScrapfly(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.scrapfly.io/scrape?url=https%3A%2F%2Fhttpbin.org%2Fstatus%2F200&key=" + url.QueryEscape(secret)
	result := verifyQueryAPI(ctx, endpoint, []string{"result", "status_code"}, "invalid api key")
	result.Response = ""
	return result
}

func verifyDeepAI(ctx context.Context, secret string) VerificationResult {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("text", "test")
	_ = writer.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.deepai.org/api/text-tagging", &body)
	req.Header.Set("Api-Key", secret)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id", "output"}, "pass a valid api-key"))
	result.Response = ""
	return result
}

func verifyHTML2PDF(ctx context.Context, secret string) VerificationResult {
	body, _ := json.Marshal(map[string]string{"html": "test", "apiKey": secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.html2pdf.app/v1/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyBinaryResponse([][]byte{[]byte("%PDF-")}, `"errorCode":6`, "unauthorized"))
	result.Response = ""
	return result
}

func verifyCarbonInterface(ctx context.Context, secret string) VerificationResult {
	body := `{"type":"flight","passengers":1,"legs":[{"departure_airport":"SFO","destination_airport":"LAX"}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.carboninterface.com/api/v1/estimates", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data", "type", "attributes", "carbon_kg"}, "http token: access denied"))
	result.Response = ""
	return result
}

func verifyDeBounce(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.debounce.io/v1/?email=noreply%40example.com&api=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success  string `json:"success"`
			DeBounce struct {
				Error string `json:"error"`
				Code  string `json:"code"`
			} `json:"debounce"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Success == "1" && response.DeBounce.Error == "" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Success == "0" && response.DeBounce.Code == "0" && containsAnyFold(response.DeBounce.Error, "wrong api") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyTimeCamp(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.timecamp.com/third_party/api/user?format=json", nil)
	req.Header.Set("Authorization", secret)
	req.Header.Set("Accept", "application/vnd.timecamp+json; version=3")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"user_id"}, "api token not found", `"code":"logout"`))
	result.Response = ""
	return result
}

func verifyGoodDay(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.goodday.work/2.0/users", nil)
	req.Header.Set("gd-api-token", secret)
	return verifyPrivateCollection(ctx, req, "auth failed")
}

func verifyParseur(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.parseur.com/", nil)
	req.Header.Set("Authorization", "Token "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "authentication failed") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyRiteKit(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.ritekit.com/v1/stats/multiple-hashtags?tags=hello&client_id=" + url.QueryEscape(secret)
	result := verifyQueryAPI(ctx, endpoint, []string{"result", "stats"}, "verification failed")
	result.Response = ""
	return result
}

func verifyFloat(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.float.com/v3/people?per-page=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("User-Agent", "secret-sniffer credential verifier")
	return verifyPrivateCollection(ctx, req, "invalid credentials")
}

func verifyHumanity(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://www.humanity.com/api/v2/me?access_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status int             `json:"status"`
			Data   json.RawMessage `json:"data"`
			Error  string          `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Status == 1 && len(response.Data) > 0 && string(response.Data) != "null" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.Status == 3 && containsAnyFold(response.Error+" "+string(response.Data), "invalid token", "not found in system") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyQubole(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://us.qubole.com/api/v1.2/account", nil)
	req.Header.Set("X-AUTH-TOKEN", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "invalid token"))
	result.Response = ""
	return result
}

func verifyProdPad(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.prodpad.com/v1/tags", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "api key is not valid", "not a valid one")
}

func classifyBinaryResponse(magics [][]byte, invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 {
			for _, magic := range magics {
				if bytes.HasPrefix(body, magic) {
					return VerificationResult{Status: VerificationVerified}, true
				}
			}
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous binary response"), true
	}
}

func verifyScaleway(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.scaleway.com/account/v3/projects?per_page=1", nil)
	req.Header.Set("X-Auth-Token", secret)
	return verifyPrivateCollection(ctx, req, "denied_authentication", "authentication is denied")
}

func verifyPayMongo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.paymongo.com/v1/webhooks?limit=1", nil)
	req.SetBasicAuth(secret, "")
	return verifyPrivateCollection(ctx, req, "authentication_invalid", "authentication is invalid")
}

func verifyUnit(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.unit.co/accounts?page%5Blimit%5D=1", "https://api.s.unit.sh/accounts?page%5Blimit%5D=1"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("bearer token is invalid or expired"))
	})
	result.Response = ""
	return result
}

func verifyLithic(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.lithic.com/v1/account_holders?limit=1", "https://sandbox.lithic.com/v1/account_holders?limit=1"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data", "has_more"}, "could not find the provided api key"))
	})
	result.Response = ""
	return result
}

func verifyFalAI(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.fal.ai/v1/models", nil)
	req.Header.Set("Authorization", "Key "+secret)
	return verifyPrivateCollection(ctx, req, "authorization_error", "invalid api key")
}

func verifyChromaCloud(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.trychroma.com/api/v2/auth/identity", "https://europe-west1.gcp.trychroma.com/api/v2/auth/identity"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("X-Chroma-Token", secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"user_id"}, "permission denied"))
	})
	result.Response = ""
	return result
}

func verifyTrulioo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.trulioo.com/v3/connection/testauthentication", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "not authorized") {
			return invalidCredentialResult(), true
		}
		var message string
		if json.Unmarshal(body, &message) == nil && statusCode >= 200 && statusCode < 300 && strings.HasPrefix(message, "Hello ") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyOpticOdds(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.opticodds.com/api/v3/sports", nil)
	req.Header.Set("X-Api-Key", secret)
	return verifyPrivateCollection(ctx, req, "invalid or inactive api key")
}

func verifyTriggerDev(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.trigger.dev/api/v1/runs?page%5Bsize%5D=10", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data", "pagination"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyTrayIO(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tray.io/core/v1/connectors", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"elements"}, "request is unauthorized"))
	result.Response = ""
	return result
}

func verifyMotherDuck(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.motherduck.com/v1/active_accounts", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		response := string(body)
		if containsAnyFold(response, "authentication_error", "invalid authentication token") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusForbidden && containsAnyFold(response, "forbidden") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a non-admin token"}, true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "accounts") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyPlanhat(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.planhat.com/users?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "invalid token")
}

func verifySlackWebhook(ctx context.Context, secret string) VerificationResult {
	if !strings.HasPrefix(secret, "https://hooks.slack.com/") {
		return VerificationResult{Status: VerificationUnsupported, Message: "unexpected Slack webhook host"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, secret, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		response := strings.TrimSpace(string(body))
		switch {
		case statusCode == http.StatusBadRequest && containsAnyFold(response, "no_text", "invalid_payload"):
			return VerificationResult{Status: VerificationVerified, Message: "provider recognized the webhook but rejected an empty payload"}, true
		case containsAnyFold(response, "no_team", "no_service", "invalid_token"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusTooManyRequests || statusCode >= 500:
			return VerificationResult{}, false
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous webhook response"), true
		}
	})
	result.Response = ""
	return result
}

func verifyConvertKit(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.convertkit.com/v3/account?api_secret=" + url.QueryEscape(secret)
	result := verifyQueryAPI(ctx, endpoint, []string{"id"}, "authorization failed", "api key not valid")
	result.Response = ""
	return result
}

func verifyScrutinizer(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://scrutinizer-ci.com/api/user/repositories?access_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("invalid_grant", "access token provided is invalid"))
	result.Response = ""
	return result
}

func verifyInstantly(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.instantly.ai/api/v2/workspaces/current", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired && containsAnyFold(string(body), "active paid plan") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a workspace without an active paid plan"}, true
		}
		return classifyReadOnlyAPI([]string{"id", "name", "owner"}, "invalid api key")(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifySmartlead(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://server.smartlead.ai/api/v1/campaigns/?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyJSONArrayAPI("invalid api key"))
	result.Response = ""
	return result
}

func verifyDeel(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.letsdeel.com/rest/contracts?limit=1", "https://api-staging.letsdeel.com/rest/contracts?limit=1"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("invalid_token", "unauthorized call: invalid token"))
	})
	result.Response = ""
	return result
}

func verifySalesflare(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.salesflare.com/me/contacts", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "missing authentication") {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyIlert(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ilert.com/api/users/current", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "provided credentials are invalid", "key_error"))
	result.Response = ""
	return result
}

func verifyAbyssale(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.abyssale.com/auth", nil)
	req.Header.Set("x-api-key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Company string `json:"company"`
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Company != "" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusUnauthorized && response.ID == "api_access_denied" {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a key without API plan access"}, true
		}
		if statusCode == http.StatusUnauthorized && response.ID == "unauthorized" && containsAnyFold(response.Message, "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyHelpCrunch(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.helpcrunch.com/v1/departments", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "invalid_token", "invalid token")
}

func verifyAvaza(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.avaza.com/api/Account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"AccountId"}, "request was unauthorized"))
	result.Response = ""
	return result
}

func verifyAlconost(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.nitrotranslate.com/api/v1/account", nil)
	req.SetBasicAuth(secret, "")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyReadOnlyAPI([]string{"id"})(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyAxonaut(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://axonaut.com/api/v2/companies?type=all&sort=id", nil)
	req.Header.Set("userApiKey", secret)
	return verifyPrivateCollection(ctx, req, "provided api key is invalid")
}

func verifyBuddyNS(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.buddyns.com/api/v2/user/", nil)
	req.Header.Set("Authorization", "Token "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"email"}, "invalid token"))
	result.Response = ""
	return result
}

func verifyDiggernaut(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.diggernaut.com/api/projects", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token "+secret)
	return verifyPrivateCollection(ctx, req, "invalid token")
}

func verifyGrooveHQ(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.groovehq.com/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyReadOnlyAPI([]string{"id"})(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyLoadmill(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.loadmill.com/api/v1/labels?filter=CI_enable", nil)
	req.Header.Set("Accept", "application/vnd.loadmill+json; version=3")
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "unauthorized")
}

func verifyNozbeTeams(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api4.nozbe.com/v1/api/users", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", secret)
	return verifyPrivateCollection(ctx, req, "authenticate yourself", `"errno":104`)
}

func verifyOverloop(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.overloop.com/public/v1/users?page%5Bsize%5D=1", nil)
	req.Header.Set("Authorization", secret)
	return verifyPrivateCollection(ctx, req, "api key is wrong")
}

func verifySkrapp(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.skrapp.io/api/v2/account", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Access-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"credits"}, "not authorized"))
	result.Response = ""
	return result
}

func verifyStitchData(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.stitchdata.com/v4/sources", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	return verifyPrivateCollection(ctx, req, "not authorized")
}

func verifyTeletype(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.teletype.app/public/api/v1/messages", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success bool            `json:"success"`
			Data    json.RawMessage `json:"data"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Success && len(response.Data) > 0 && string(response.Data) != "null" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if len(response.Errors) > 0 && response.Errors[0].Code == http.StatusUnauthorized && containsAnyFold(response.Errors[0].Message, "invalid credentials") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyUpwave(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.upwave.io/workspaces/", nil)
	req.Header.Set("Authorization", "Token "+secret)
	return verifyPrivateCollection(ctx, req, "invalid token")
}

func verifyWorksnaps(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.worksnaps.com/api/projects.xml", nil)
	req.SetBasicAuth(secret, "ignored")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && containsAnyFold(string(body), "<projects", "<project") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous XML response"), true
	})
	result.Response = ""
	return result
}

func verifyAPIMatic(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.apimatic.io/code-generations", nil)
	req.Header.Set("Authorization", "X-Auth-Key "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "authorization has been denied") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && (jsonArray(body) || jsonObject(body) || containsAnyFold(string(body), "<CodeGeneration", "<code-generation")) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyAppointedd(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.appointedd.com/v1/availability/slots", nil)
	req.Header.Set("X-API-KEY", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"total", "slots"}, `"message":"forbidden"`))
	result.Response = ""
	return result
}

func verifyBugHerd(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.bugherd.com/api_v2/projects.json", nil)
	req.SetBasicAuth(secret, "x")
	return verifyPrivateCollection(ctx, req, "invalid api key")
}

func verifyLivestorm(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.livestorm.co/v1/ping", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "not authorized", `"code":"401"`) {
			return invalidCredentialResult(), true
		}
		var response map[string]any
		if json.Unmarshal(body, &response) == nil && statusCode >= 200 && statusCode < 300 && len(response) > 0 && response["errors"] == nil {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyMadKudu(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.madkudu.com/v1/ping", nil)
	req.SetBasicAuth(secret, "")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Status == "ok" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(response.Message, "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyAPIMetrics(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://client.apimetrics.io/api/2/calls/?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"meta", "results"}, `"error_msg":"forbidden"`))
	result.Response = ""
	return result
}

func verifyChatBot(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.chatbot.com/v2/stories", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "403 forbidden") {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyFeedier(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.feedier.com/v1/carriers", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	return verifyPrivateCollection(ctx, req, "api key provided does not exist")
}

func verifyFlexport(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://logistics-api.flexport.com/logistics/api/2024-04/webhooks", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, `"code":401`, `"message":"unauthorized"`)
}

func verifyJuro(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.juro.com/v3/templates", nil)
	req.Header.Set("x-api-key", secret)
	return verifyPrivateCollection(ctx, req, `"message":"forbidden"`)
}

func verifyMindMeister(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.mindmeister.com/services/rest/oauth2?method=mm.maps.getList", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			RSP struct {
				Stat string `json:"stat"`
				Err  struct {
					Code string `json:"code"`
					Msg  string `json:"msg"`
				} `json:"err"`
			} `json:"rsp"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.RSP.Stat == "ok" {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if response.RSP.Stat == "fail" && response.RSP.Err.Code == "1010" && containsAnyFold(response.RSP.Err.Msg, "oauth credentials are invalid") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyMoonClerk(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.moonclerk.com/forms", nil)
	req.Header.Set("Authorization", "Token token="+secret)
	req.Header.Set("Accept", "application/vnd.moonclerk+json;version=1")
	return verifyPrivateCollection(ctx, req, "http token: access denied")
}

func verifyPrivacy(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.privacy.com/v1/card?page=1&page_size=1", nil)
	req.Header.Set("Authorization", "api-key "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data"}, `"message":"unauthorized"`))
	result.Response = ""
	return result
}

func verifyReachMail(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://services.reachmail.net/administration/users/current", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyReadOnlyAPI([]string{"id"})(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifySurveySparrow(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.surveysparrow.com/v1/contacts?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "bad_token")
}

func verifySurvicate(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://data-api.survicate.com/v1/surveys", nil)
	req.Header.Set("Authorization", "Basic "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyVyte(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.vyte.in/v2/events", nil)
	req.Header.Set("Authorization", secret)
	req.Header.Set("Accept", "application/vnd.vyte+json; version=3")
	return verifyPrivateCollection(ctx, req, "unauthorized")
}

func verifyStorecove(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.storecove.com/api/v2/discovery/identifiers", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyCourier(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.courier.com/preferences", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"sections"}, "authentication failed", "invalid or missing authentication credentials"))
	result.Response = ""
	return result
}

func verifyComplyAdvantage(ctx context.Context, secret string) VerificationResult {
	result := verifyEndpoints(ctx, []string{"https://api.complyadvantage.com/users", "https://api.us.complyadvantage.com/users", "https://api.ap.complyadvantage.com/users"}, func(endpoint string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		req.Header.Set("Authorization", "Token "+secret)
		return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"status", "content"}, "api key is invalid or was not provided"))
	})
	result.Response = ""
	return result
}

func verifyCronitor(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://cronitor.io/api/monitors", nil)
	req.SetBasicAuth(secret, "")
	req.Header.Set("Cronitor-Version", "2025-11-28")
	return verifyPrivateCollection(ctx, req, "invalid api key")
}

func verifySSLMate(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://sslmate.com/api/v2/certs/example.com", nil)
	req.SetBasicAuth(secret, "")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"exists"}, "bad_credentials", "not recognized"))
	result.Response = ""
	return result
}

func verifyBlazeMeter(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.runscope.com/account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"data"}, "provide a valid authorization header"))
	result.Response = ""
	return result
}

func verifyCloudflareCA(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/certificates?per_page=5", nil)
	req.Header.Set("X-Auth-User-Service-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Success && len(response.Result) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if !response.Success && len(response.Errors) > 0 && response.Errors[0].Code == 9106 {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyGTmetrix(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://gtmetrix.com/api/2.0/status", nil)
	req.SetBasicAuth(secret, "")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		response := string(body)
		if statusCode == http.StatusUnauthorized && containsAnyFold(response, "e40100", "invalid api key") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusForbidden && containsAnyFold(response, "e40300", "e40301") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted account"}, true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAllFields(body, "data", "type") && containsAnyFold(response, `"type":"status"`) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyHybiscus(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.hybiscus.dev/api/v1/get-remaining-quota", nil)
	req.Header.Set("X-API-KEY", secret)
	req.Header.Set("Accept", "application/vnd.hybiscus+json; version=3")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusForbidden && containsAnyFold(string(body), "api key supplied is invalid") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) && !jsonHasAnyField(body, "error", "detail") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return VerificationResult{}, false
	})
	result.Response = ""
	return result
}

func verifyMailjetSMS(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mailjet.com/v4/sms", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.mailjetsms+json; version=3")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "api key authentication/authorization failure") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return VerificationResult{}, false
	})
	result.Response = ""
	return result
}

func verifyCalorieNinjas(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.calorieninjas.com/v1/nutrition?query=", nil)
	req.Header.Set("X-Api-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"items"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyAletheia(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.aletheiaapi.com/StockData?symbol=msft&summary=true", nil)
	req.Header.Set("Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "api key invalid") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) && !jsonHasAnyField(body, "error") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return VerificationResult{}, false
	})
	result.Response = ""
	return result
}

func verifyAllSports(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://apiv2.allsportsapi.com/football/?met=Countries&APIkey=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Error  string `json:"error"`
			Result []struct {
				Code int    `json:"cod"`
				Msg  string `json:"msg"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if response.Error == "1" && len(response.Result) > 0 && response.Result[0].Code == 1004 && containsAnyFold(response.Result[0].Msg, "wrong login credentials") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Error != "1" && len(response.Result) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyFinage(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.finage.co.uk/symbol-list/crypto?apikey="+url.QueryEscape(secret), []string{"symbols"}, "do not have permission to make a request")
	result.Response = ""
	return result
}

func verifyDandelion(ctx context.Context, secret string) VerificationResult {
	result := verifyQueryAPI(ctx, "https://api.dandelion.eu/datatxt/li/v1/?text=Smart&token="+url.QueryEscape(secret), []string{"annotations"}, "no such token")
	result.Response = ""
	return result
}

func verifyApacta(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.apacta.com/api/v1/time_entries", nil)
	req.Header.Set("Authorization", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "not authenticated", "set `authorization` http header") {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyLeadfeeder(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.leadfeeder.com/accounts", nil)
	req.Header.Set("Authorization", "Token token="+secret)
	return verifyPrivateCollection(ctx, req, "invalid access token")
}

func verifyKnapsackPro(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.knapsackpro.com/v1/builds?page=1", nil)
	req.Header.Set("KNAPSACK-PRO-TEST-SUITE-TOKEN", secret)
	return verifyPrivateCollection(ctx, req, "invalid test suite token")
}

func verifyTLY(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.t.ly/api/v1/link/list", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	return verifyPrivateCollection(ctx, req, "unauthenticated")
}

func verifyWebScraper(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.webscraper.io/api/v1/sitemaps?api_token=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("invalid api_token", "unauthorized"))
	result.Response = ""
	return result
}

func verifyEnvoy(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.envoy.com/v1/locations", nil)
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Accept", "application/vnd.envoy+json; version=3")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "unauthenticated", "status code 401") {
			return invalidCredentialResult(), true
		}
		return classifyCollectionResponse()(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyDocparser(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.docparser.com/v1/parsers?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyCollectionResponse("api key not valid"))
	result.Response = ""
	return result
}

func verifyInterseller(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://interseller.io/api/campaigns/list", nil)
	req.Header.Set("X-API-Key", secret)
	req.Header.Set("Accept", "application/json")
	return verifyPrivateCollection(ctx, req, "unauthorizederror", `"message":"unauthorized"`)
}

func verifySquarespace(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.squarespace.com/1.0/authorization/website", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("User-Agent", "secret-sniffer credential verifier")
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id", "siteId"}, "authorization_error", "not authorized to do that"))
	result.Response = ""
	return result
}

func verifyAppFollow(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.appfollow.io/api/v2/account/users", nil)
	req.Header.Set("X-AppFollow-API-Token", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusPaymentRequired && containsAnyFold(string(body), "not enough credits") {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated an account without credits"}, true
		}
		return classifyCollectionResponse("invalid api token")(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyOptimizely(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.optimizely.com/v2/projects", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "invalid_credentials", "malformed or invalid authorization header")
}

func verifyCliengo(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.cliengo.com/1.0/account?api_key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "invalid credentials"))
	result.Response = ""
	return result
}

func verifyTeamwork(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.teamwork.com/launchpad/v1/userinfo.json", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"sub", "user_id", "installation_id", "url"}, "unauthorized"))
	result.Response = ""
	return result
}

func verifyTeachable(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://developers.teachable.com/v1/courses", nil)
	req.Header.Set("apiKey", secret)
	return verifyPrivateCollection(ctx, req, "invalid authentication credentials")
}

func verifyBrandfetch(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.brandfetch.io/v2/brands/google.com", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"name", "domain"}, "invalid api key"))
	result.Response = ""
	return result
}

func verifyBombBomb(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.bombbomb.com/v2/user/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		return classifyReadOnlyAPI([]string{"id"})(statusCode, body)
	})
	result.Response = ""
	return result
}

func verifyCaflou(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.caflou.com/api/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	return verifyPrivateCollection(ctx, req, "signature verification failed")
}

func verifyAutopilot(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api2.autopilothq.com/v1/account", nil)
	req.Header.Set("autopilotapikey", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "autopilotapikey not valid"))
	result.Response = ""
	return result
}

func verifyBeebole(ctx context.Context, secret string) VerificationResult {
	body := `{"service":"custom_field.list"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://beebole-apps.com/api/v2", strings.NewReader(body))
	req.SetBasicAuth(secret, "x")
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, responseBody []byte) (VerificationResult, bool) {
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && (jsonArray(responseBody) || jsonHasAnyField(responseBody, "result", "data", "custom_fields")) && !jsonHasAnyField(responseBody, "error") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyRingover(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://public-api.ringover.com/v2/users", nil)
	req.Header.Set("Authorization", secret)
	return verifyPrivateCollection(ctx, req, "invalid user")
}

func verifyCloverly(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloverly.com/2019-03-beta/account", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "incorrect api key given"))
	result.Response = ""
	return result
}

func verifyVBOUT(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://api.vbout.com/1/app/me.json?key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Response struct {
				Header struct {
					Status string `json:"status"`
				} `json:"header"`
				Data json.RawMessage `json:"data"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Response.Header.Status == "success" && len(response.Response.Data) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusUnauthorized && response.Response.Header.Status == "error" {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyAPI2Cart(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.api2cart.com/v1.1/account.cart.list.json", nil)
	req.Header.Set("x-api-key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			ReturnCode    int    `json:"return_code"`
			ReturnMessage string `json:"return_message"`
			Result        struct {
				CartsCount int             `json:"carts_count"`
				Carts      json.RawMessage `json:"carts"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		switch response.ReturnCode {
		case 0:
			if len(response.Result.Carts) > 0 {
				return VerificationResult{Status: VerificationVerified}, true
			}
		case 2, 6:
			return invalidCredentialResult(), true
		case 5, 7, 10:
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted or exhausted key"}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyKylas(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.kylas.io/v1/contacts?page=0&size=1", nil)
	req.Header.Set("api-key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Code          string          `json:"code"`
			Message       string          `json:"message"`
			Content       json.RawMessage `json:"content"`
			TotalElements *int            `json:"totalElements"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.TotalElements != nil && len(response.Content) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusBadRequest && response.Code == "001079" && containsAnyFold(response.Message, "invalid api key") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyInsightly(ctx context.Context, secret string) VerificationResult {
	hosts := []string{"api.insightly.com", "api.na1.insightly.com", "api.eu1.insightly.com", "api.au1.insightly.com"}
	result := verifyEndpoints(ctx, hosts, func(host string) VerificationResult {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v3.1/Contacts?top=1", nil)
		req.SetBasicAuth(secret, "")
		return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
			if statusCode == http.StatusTooManyRequests {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a rate-limited key"}, true
			}
			if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "authorization has been denied") {
				return invalidCredentialResult(), true
			}
			if statusCode >= 200 && statusCode < 300 && jsonArray(body) {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		})
	})
	result.Response = ""
	return result
}

func verifyOOPSpam(ctx context.Context, secret string) VerificationResult {
	body := `{"content":"This is a deterministic credential verification probe.","checkForLength":true,"logIt":false}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.oopspam.com/v1/spamdetection", strings.NewReader(body))
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			Score   *float64        `json:"Score"`
			Details json.RawMessage `json:"Details"`
			Error   struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.Score != nil && *response.Score >= 0 && *response.Score <= 6 && len(response.Details) > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusForbidden && response.Error.Code == "API_KEY_INVALID" {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyTinyPNG(ctx context.Context, secret string) VerificationResult {
	png, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zc1sAAAAASUVORK5CYII=")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tinify.com/shrink", bytes.NewReader(png))
	req.SetBasicAuth("api", secret)
	req.Header.Set("Content-Type", "image/png")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "credentials are invalid") {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusCreated && jsonHasAnyField(body, "input", "output") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyCaptainData(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.captaindata.com/v1/quotas", nil)
	req.Header.Set("X-API-Key", secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"quotas"}, "not authorized to access this resource"))
	result.Response = ""
	return result
}

func verifyColumn(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.column.com/entities?limit=1", nil)
	req.SetBasicAuth("", secret)
	return verifyPrivateCollection(ctx, req, "no valid api key", "invalid api key")
}

func verifyNVAPI(ctx context.Context, secret string) VerificationResult {
	body := "credentials=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.ngc.nvidia.com/v3/keys/get-caller-info", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "unauthorized", "invalid api key") {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonObject(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyPaymo(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.paymoapp.com/api/me", nil)
	req.SetBasicAuth(secret, "X")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI([]string{"id"}, "not authenticated"))
	result.Response = ""
	return result
}

func verifySelectPDF(ctx context.Context, secret string) VerificationResult {
	endpoint := "https://selectpdf.com/api2/usage/?get_history=False&key=" + url.QueryEscape(secret)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode == http.StatusUnauthorized && containsAnyFold(string(body), "license key not valid") {
			return invalidCredentialResult(), true
		}
		var response struct {
			Status    string `json:"status"`
			Limit     *int   `json:"limit"`
			Used      *int   `json:"used"`
			Available *int   `json:"available"`
		}
		if json.Unmarshal(body, &response) == nil && statusCode >= 200 && statusCode < 300 && response.Status != "" && response.Limit != nil && response.Used != nil && response.Available != nil {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyGCPAuthorizedUser(ctx context.Context, secret string) VerificationResult {
	var credential struct {
		Type         string `json:"type"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal([]byte(secret), &credential) != nil || (credential.Type != "" && credential.Type != "authorized_user") || credential.ClientID == "" || credential.ClientSecret == "" || credential.RefreshToken == "" {
		return invalidCredentialResult()
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {credential.ClientID},
		"client_secret": {credential.ClientSecret},
		"refresh_token": {credential.RefreshToken},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyGoogleTokenExchange(false))
	result.Response = ""
	return result
}

func verifyGCPServiceAccount(ctx context.Context, secret string) VerificationResult {
	var credential struct {
		Type         string `json:"type"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
	}
	if json.Unmarshal([]byte(secret), &credential) != nil || credential.Type != "service_account" || credential.PrivateKey == "" || credential.ClientEmail == "" {
		return invalidCredentialResult()
	}
	key, err := parseRSAPrivateKey([]byte(credential.PrivateKey))
	if err != nil {
		return invalidCredentialResult()
	}
	assertion, err := signGoogleServiceAccountJWT(key, credential.ClientEmail, credential.PrivateKeyID, time.Now().UTC())
	if err != nil {
		return unknownVerificationResult("provider", "failed to sign service account assertion")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyGoogleTokenExchange(true))
	result.Response = ""
	return result
}

func classifyGoogleTokenExchange(serviceAccount bool) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			AccessToken      string `json:"access_token"`
			TokenType        string `json:"token_type"`
			ExpiresIn        int    `json:"expires_in"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.AccessToken != "" && strings.EqualFold(response.TokenType, "Bearer") && response.ExpiresIn > 0 {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if serviceAccount && response.Error == "invalid_grant" && containsAnyFold(response.ErrorDescription, "iat", "exp", "clock", "timeframe") {
			return unknownVerificationResult("clock", "provider rejected assertion timing"), true
		}
		switch response.Error {
		case "invalid_grant", "invalid_client", "deleted_client", "disabled_client":
			return invalidCredentialResult(), true
		case "temporarily_unavailable", "server_error":
			return unknownVerificationResult("provider", "provider temporarily unavailable"), true
		case "invalid_scope", "unauthorized_client":
			return unknownVerificationResult("authorization", "provider rejected credential authorization"), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous token response"), true
		}
	}
}

func parseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func signGoogleServiceAccountJWT(key *rsa.PrivateKey, email, keyID string, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if keyID != "" {
		header["kid"] = keyID
	}
	claims := map[string]any{
		"iss":   email,
		"scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyAzureAppConfiguration(ctx context.Context, secret string) VerificationResult {
	parts := parseConnectionString(secret)
	endpoint, err := url.Parse(parts["Endpoint"])
	key, keyErr := base64.StdEncoding.DecodeString(parts["Secret"])
	if err != nil || keyErr != nil || endpoint.Scheme != "https" || endpoint.User != nil || !strings.HasSuffix(endpoint.Hostname(), ".azconfig.io") || parts["Id"] == "" {
		return invalidCredentialResult()
	}
	endpoint.Path = "/kv"
	endpoint.RawQuery = "api-version=1.0"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	date := time.Now().UTC().Format(http.TimeFormat)
	emptyHash := sha256.Sum256(nil)
	contentHash := base64.StdEncoding.EncodeToString(emptyHash[:])
	stringToSign := req.Method + "\n" + req.URL.RequestURI() + "\n" + date + ";" + req.URL.Host + ";" + contentHash
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-content-sha256", contentHash)
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+parts["Id"]+"&SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature="+signature)
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyAzureSignedRequest)
	result.Response = ""
	return result
}

func verifyAzureStorageConnectionString(ctx context.Context, secret string) VerificationResult {
	parts := parseConnectionString(secret)
	account := parts["AccountName"]
	key, err := base64.StdEncoding.DecodeString(parts["AccountKey"])
	if err != nil || parts["DefaultEndpointsProtocol"] != "https" || parts["EndpointSuffix"] != "core.windows.net" || account == "" {
		return invalidCredentialResult()
	}
	endpoint := "https://" + account + ".blob.core.windows.net/?comp=list&maxresults=1"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	date := time.Now().UTC().Format(http.TimeFormat)
	version := "2023-11-03"
	canonicalHeaders := "x-ms-date:" + date + "\n" + "x-ms-version:" + version + "\n"
	canonicalResource := "/" + account + "/\ncomp:list\nmaxresults:1"
	fields := []string{http.MethodGet, "", "", "", "", "", "", "", "", "", "", "", canonicalHeaders + canonicalResource}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strings.Join(fields, "\n")))
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-version", version)
	req.Header.Set("Authorization", "SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyAzureSignedRequest)
	result.Response = ""
	return result
}

func parseConnectionString(value string) map[string]string {
	parts := map[string]string{}
	for _, field := range strings.Split(value, ";") {
		key, item, ok := strings.Cut(field, "=")
		if ok {
			parts[key] = item
		}
	}
	return parts
}

func classifyAzureSignedRequest(statusCode int, body []byte) (VerificationResult, bool) {
	if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500 {
		return VerificationResult{}, false
	}
	if statusCode >= 200 && statusCode < 300 {
		return VerificationResult{Status: VerificationVerified}, true
	}
	response := string(body)
	if containsAnyFold(response, "date header", "request date", "clock skew", "request time") {
		return unknownVerificationResult("clock", "provider rejected request timing"), true
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		if containsAnyFold(response, "signature did not match", "invalid signature", "invalid credential", "authenticationfailed", "invalidauthenticationinfo") {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("authorization", "provider authorization response was ambiguous"), true
	}
	if statusCode == http.StatusNotFound {
		return unknownVerificationResult("endpoint_context", "provider endpoint was not found"), true
	}
	return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
}

func verifyMailjetBasicAuth(ctx context.Context, secret string) VerificationResult {
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || strings.Count(string(decoded), ":") != 1 {
		return invalidCredentialResult()
	}
	username, password, _ := strings.Cut(string(decoded), ":")
	if username == "" || password == "" {
		return invalidCredentialResult()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mailjet.com/v3/REST/message?Limit=1", nil)
	req.Header.Set("Authorization", "Basic "+secret)
	req.Header.Set("Accept", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAnyField(body, "Data", "Count", "Total") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		if statusCode == http.StatusUnauthorized {
			return invalidCredentialResult(), true
		}
		if statusCode == http.StatusForbidden {
			return unknownVerificationResult("authorization", "provider authenticated response was permission denied"), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
	result.Response = ""
	return result
}

func verifyFetchedExample(ctx context.Context, endpoint string, invalidMarker string, authenticatedMarkers ...string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		response := string(body)
		if containsAnyFold(response, invalidMarker) {
			return invalidCredentialResult(), true
		}
		if containsAnyFold(response, authenticatedMarkers...) {
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a restricted or exhausted key"}, true
		}
		if statusCode >= 200 && statusCode < 300 && containsAnyFold(response, "<title>Example Domain</title>", "<h1>Example Domain</h1>") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	})
}

func classifyCollectionResponse(invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && (jsonArray(body) || jsonHasAnyField(body,
			"data", "results", "lists", "addresses", "templates", "orders", "answers", "applications",
			"partnerships", "transcriptions", "iconsets", "carriers", "checks", "people", "detectionRules", "signatures",
			"projects", "models", "sports", "repositories", "contracts", "contacts", "webhooks", "account_holders", "connectors",
			"departments", "companies", "labels", "users", "sources", "workspaces", "slots", "stories", "forms", "cards",
			"surveys", "events", "identifiers", "monitors", "calls", "preferences", "sections", "time_entries", "accounts",
			"builds", "links", "sitemaps", "locations", "parsers", "campaigns", "entities")) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	}
}

func classifyJSONRPC(invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		var response struct {
			JSONRPC string `json:"jsonrpc"`
			Result  string `json:"result"`
			ID      int    `json:"id"`
		}
		if json.Unmarshal(body, &response) == nil && statusCode >= 200 && statusCode < 300 && response.JSONRPC == "2.0" && response.ID == 1 && strings.HasPrefix(response.Result, "0x") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous JSON-RPC response"), true
	}
}

func classifyJSONArrayAPI(invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonArray(body) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	}
}

func verifyQueryAPI(ctx context.Context, endpoint string, validFields []string, invalidMarkers ...string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	return verifyHTTPRequestWithClassifier(ctx, req, classifyReadOnlyAPI(validFields, invalidMarkers...))
}

func classifyReadOnlyAPI(validFields []string, invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		if containsAnyFold(string(body), invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		if statusCode >= 200 && statusCode < 300 && jsonHasAllFields(body, validFields...) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
	}
}

func classifyTokenExchange(invalidMarkers ...string) verificationResponseClassifier {
	return func(statusCode int, body []byte) (VerificationResult, bool) {
		if statusCode == http.StatusTooManyRequests || statusCode >= 500 {
			return VerificationResult{}, false
		}
		var response struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			Error        string `json:"error"`
			ErrorCode    string `json:"errorCode"`
			ErrorMessage string `json:"errorMessage"`
		}
		if json.Unmarshal(body, &response) != nil {
			return unknownVerificationResult("provider_response", "provider returned malformed JSON"), true
		}
		if statusCode >= 200 && statusCode < 300 && response.AccessToken != "" && strings.EqualFold(response.TokenType, "Bearer") {
			return VerificationResult{Status: VerificationVerified}, true
		}
		combined := response.Error + " " + response.ErrorCode + " " + response.ErrorMessage
		if containsAnyFold(combined, invalidMarkers...) {
			return invalidCredentialResult(), true
		}
		return unknownVerificationResult("provider_response", "provider returned an ambiguous token exchange response"), true
	}
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.linear.app/graphql", strings.NewReader(`{"query":"{ viewer { id name } }"}`))
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, classifyGraphQLIdentity("id"))
	result.Response = ""
	return result
}

func verifyNotion(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.notion.com/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Notion-Version", "2022-06-28")
	return verifyJSONIdentityRequest(ctx, req, "id")
}

func verifyPostman(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.getpostman.com/me", nil)
	req.Header.Set("X-Api-Key", secret)
	return verifyJSONIdentityRequest(ctx, req, "id")
}

func verifySentry(ctx context.Context, secret string) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://sentry.io/api/0/auth/validate/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	result := verifyHTTPRequestWithClassifier(ctx, req, func(statusCode int, body []byte) (VerificationResult, bool) {
		switch {
		case statusCode >= 200 && statusCode < 300:
			return VerificationResult{Status: VerificationVerified}, true
		case statusCode == http.StatusUnauthorized:
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden && containsAnyFold(string(body), "Invalid token"):
			return invalidCredentialResult(), true
		case statusCode == http.StatusForbidden && strings.HasPrefix(secret, "sntryu_") && containsAnyFold(string(body), "You do not have permission to perform this action"):
			return VerificationResult{Status: VerificationVerified, Message: "provider authenticated a token with insufficient permission"}, true
		case statusCode == http.StatusForbidden:
			return unknownVerificationResult("authorization", "provider could not authorize verification"), true
		case statusCode == http.StatusTooManyRequests:
			return unknownVerificationResult("rate_limited", "provider rate limited verification"), true
		case statusCode >= 500:
			return unknownVerificationResult("provider", "provider unavailable"), true
		default:
			return unknownVerificationResult("provider_response", "provider returned an ambiguous response"), true
		}
	})
	result.Response = ""
	return result
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

func containsAnyFold(value string, candidates ...string) bool {
	value = strings.ToLower(value)
	for _, candidate := range candidates {
		if strings.Contains(value, strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func jsonHasAnyField(body []byte, fields ...string) bool {
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	for _, field := range fields {
		if findJSONField(payload, field) {
			return true
		}
	}
	return false
}

func jsonHasAllFields(body []byte, fields ...string) bool {
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	for _, field := range fields {
		if !findJSONField(payload, field) {
			return false
		}
	}
	return true
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
