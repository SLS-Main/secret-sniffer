package detectors

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

var (
	ngcLegacyCredential = regexp.MustCompile(`^[A-Za-z0-9._-]{32,256}$`)
	ngcScopedCredential = regexp.MustCompile(`^nvapi-[A-Za-z0-9_-]{32,256}$`)
)

func finalPositiveInteger(raw json.RawMessage) bool {
	var n *int64
	return json.Unmarshal(raw, &n) == nil && n != nil && *n > 0
}

func finalStringList(raw json.RawMessage) bool {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil {
		return false
	}
	for _, item := range items {
		if !identityStrings(identityPayload{"value": item}, "value") {
			return false
		}
	}
	return true
}

func validComplyUsers(p identityPayload) bool {
	content := identityObject(p, "content")
	return identityStringEquals(p, "status", "success") && !identityHasErrors(content) &&
		validIdentityCollection(content, "data", func(user identityPayload) bool {
			return !identityHasErrors(user) && finalPositiveInteger(user["id"]) && identityStrings(user, "email", "name")
		})
}

func validCodyLimits(p identityPayload) bool {
	// The official client returns a feature -> LimitStatus map, possibly empty.
	for feature, raw := range p {
		var limit identityPayload
		if strings.TrimSpace(feature) == "" || json.Unmarshal(raw, &limit) != nil || limit == nil || identityHasErrors(limit) || !identityStrings(limit, "interval") {
			return false
		}
		for _, field := range []string{"limit", "usage"} {
			var value *int64
			if json.Unmarshal(limit[field], &value) != nil || value == nil {
				return false
			}
		}
		if expiry, present := limit["expiry"]; present && string(expiry) != "null" {
			var value time.Time
			if json.Unmarshal(expiry, &value) != nil {
				return false
			}
		}
	}
	return true
}

func validXCredits(p identityPayload) bool {
	data := identityObject(p, "data")
	if data == nil || identityHasErrors(data) {
		return false
	}
	for _, field := range []string{"total_balance", "prepaid_balance", "free_balance"} {
		var balance *float64
		if json.Unmarshal(data[field], &balance) != nil || balance == nil || (field != "prepaid_balance" && *balance < 0) {
			return false
		}
	}
	return validIdentityCollection(data, "free_grants", func(grant identityPayload) bool {
		var amount *float64
		// Expiry may be omitted or unknown. It is not authentication evidence.
		return !identityHasErrors(grant) && json.Unmarshal(grant["amount"], &amount) == nil && amount != nil && *amount >= 0
	})
}

func validNGCLegacyToken(p identityPayload) bool {
	if !identityStrings(p, "token") {
		return false
	}
	if expiry, present := p["expires_in"]; present {
		return finalPositiveInteger(expiry)
	}
	return true
}

func validNGCScopedCaller(p identityPayload) bool {
	status := identityObject(p, "requestStatus")
	if identityHasErrors(status) || !identityStringEquals(status, "statusCode", "SUCCESS") ||
		!identityStrings(p, "orgName") || !finalStringList(p["products"]) {
		return false
	}
	if identityStringEquals(p, "type", "SERVICE_KEY") {
		return true
	}
	// Personal keys can legitimately have no roles, or no expanded user object.
	return identityStringEquals(p, "type", "PERSONAL_KEY") && identityStrings(p, "userId") && !identityHasErrors(identityObject(p, "user"))
}

func validBombBombSession(p identityPayload) bool {
	info := identityObject(p, "info")
	if !identityStringEquals(p, "status", "success") || info == nil || identityHasErrors(info) {
		return false
	}
	return (identityID(info["userId"]) && identityID(info["clientId"])) ||
		(identityID(info["user_id"]) && identityID(info["client_id"]))
}
