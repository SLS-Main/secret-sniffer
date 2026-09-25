package detectors

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type identityPayload map[string]json.RawMessage

// Identity probes accept only the documented success status and structure.
// Permission, region and credential-subtype failures are not proof of invalidity.
func verifyIdentityRequest(ctx context.Context, req *http.Request, valid func(identityPayload) bool) VerificationResult {
	req.Header.Set("Accept", "application/json")
	result := verifyHTTPRequestWithClassifier(ctx, req, func(status int, body []byte) (VerificationResult, bool) {
		var payload identityPayload
		if status == http.StatusOK && json.Unmarshal(body, &payload) == nil && payload != nil && !identityHasErrors(payload) && valid(payload) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return verifyJSONReadClassification(status, body)
	})
	result.Response = ""
	return result
}

func identityHasErrors(p identityPayload) bool {
	for _, key := range []string{"error", "error_code"} {
		if _, ok := p[key]; ok {
			return true
		}
	}
	if raw, ok := p["errors"]; ok {
		var errors []json.RawMessage
		if json.Unmarshal(raw, &errors) != nil || len(errors) != 0 {
			return true
		}
	}
	return false
}

func identityObject(p identityPayload, path ...string) identityPayload {
	for _, key := range path {
		var child identityPayload
		if json.Unmarshal(p[key], &child) != nil || child == nil {
			return nil
		}
		p = child
	}
	return p
}

func identityStrings(p identityPayload, fields ...string) bool {
	for _, field := range fields {
		var value string
		if json.Unmarshal(p[field], &value) != nil || strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func identityID(raw json.RawMessage) bool {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text) != ""
	}
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func verifyIdentityGET(ctx context.Context, secret, endpoint, header, prefix string, valid func(identityPayload) bool) VerificationResult {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set(header, prefix+secret)
	return verifyIdentityRequest(ctx, req, valid)
}

// Only an authorization ambiguity justifies trying the next known deployment.
// Do not multiply requests after throttling, redirects, malformed success,
// cancellation, network errors, or provider outages.
func verifyIdentityEndpoints(ctx context.Context, endpoints []string, verify func(string) VerificationResult) VerificationResult {
	result := unknownVerificationResult("authorization", "provider deployment could not be determined")
	for _, endpoint := range endpoints {
		if ctx.Err() == context.DeadlineExceeded {
			return unknownVerificationResult("timeout", "verification context expired")
		}
		if ctx.Err() != nil {
			return unknownVerificationResult("cancelled", "verification context ended")
		}
		result = verify(endpoint)
		if result.Status != VerificationUnknown || result.ErrorCategory != "authorization" {
			return result
		}
	}
	return result
}

func validAtlassianOrganizations(p identityPayload) bool {
	var organizations []identityPayload
	if json.Unmarshal(p["data"], &organizations) != nil || organizations == nil {
		return false
	}
	for _, org := range organizations {
		var kind string
		if !identityStrings(org, "id") || json.Unmarshal(org["type"], &kind) != nil || kind != "orgs" {
			return false
		}
	}
	return true
}

func validPaystackBalance(p identityPayload) bool {
	var status bool
	var balances []struct {
		Currency string `json:"currency"`
		Balance  *int64 `json:"balance"`
	}
	if json.Unmarshal(p["status"], &status) != nil || !status || json.Unmarshal(p["data"], &balances) != nil || balances == nil {
		return false
	}
	for _, balance := range balances {
		if len(balance.Currency) != 3 || balance.Balance == nil {
			return false
		}
		for _, c := range balance.Currency {
			if c < 'A' || c > 'Z' {
				return false
			}
		}
	}
	return true
}
