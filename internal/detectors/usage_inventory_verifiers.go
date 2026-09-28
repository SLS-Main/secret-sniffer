package detectors

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"time"
)

func verifyInventoryArray(ctx context.Context, req *http.Request, valid func(identityPayload) bool) VerificationResult {
	result := verifyHTTPRequestWithClassifier(ctx, req, func(status int, body []byte) (VerificationResult, bool) {
		if status == http.StatusOK && validIdentityCollection(identityPayload{"items": body}, "items", valid) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		return verifyJSONReadClassification(status, body)
	})
	result.Response = ""
	return result
}

var (
	pagarMeLegacyLiveKey = regexp.MustCompile(`^ak_live_[A-Za-z0-9]{30}$`)
	detectifyV2Key       = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)
	detectifyV3Key       = regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`)
)

func validEtherscanUsage(p identityPayload) bool {
	usage := identityObject(p, "result")
	if !identityStringEquals(p, "status", "1") || !identityStringEquals(p, "message", "OK") || identityHasErrors(usage) || !identityStrings(usage, "limitInterval", "intervalExpiryTimespan") {
		return false
	}
	for _, field := range []string{"creditsUsed", "creditsAvailable", "creditLimit"} {
		var value *float64
		if json.Unmarshal(usage[field], &value) != nil || value == nil {
			return false
		}
	}
	return true
}

func validMassiveMarketStatus(p identityPayload) bool {
	if raw, ok := p["status"]; ok && !identityStringEquals(identityPayload{"status": raw}, "status", "OK") {
		return false
	}
	if !identityStrings(p, "market", "serverTime") {
		return false
	}
	var timestamp string
	if json.Unmarshal(p["serverTime"], &timestamp) != nil {
		return false
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		return false
	}
	for _, field := range []string{"afterHours", "earlyHours"} {
		var flag *bool
		if json.Unmarshal(p[field], &flag) != nil || flag == nil {
			return false
		}
	}
	return true
}

func validDetectifyAssets(p identityPayload) bool {
	// V2 explicitly documents an empty object for a team without assets.
	if len(p) == 0 {
		return true
	}
	for _, field := range []string{"code", "status", "detail"} {
		if _, ok := p[field]; ok {
			return false
		}
	}
	var more *bool
	return json.Unmarshal(p["has_more"], &more) == nil && more != nil && validIdentityCollection(p, "assets", func(asset identityPayload) bool {
		return !identityHasErrors(asset) && identityStrings(asset, "token", "name", "status")
	})
}

func validDetectifyIPs(p identityPayload) bool {
	// RFC 7807 problem envelopes are not successful inventory responses.
	for _, field := range []string{"type", "title", "status", "detail"} {
		if _, ok := p[field]; ok {
			return false
		}
	}
	return validIdentityCollection(p, "items", func(ip identityPayload) bool {
		var address string
		return !identityHasErrors(ip) && identityStrings(ip, "id", "asset_id", "team_id") && json.Unmarshal(ip["ip_address"], &address) == nil && net.ParseIP(address) != nil
	})
}
