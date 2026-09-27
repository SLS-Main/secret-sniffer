package detectors

import (
	"encoding/json"
	"math"
	"strconv"
)

func validPagerDutyAbilities(p identityPayload) bool {
	var abilities []string
	if json.Unmarshal(p["abilities"], &abilities) != nil || abilities == nil {
		return false
	}
	// Decode each element separately: null must not become a zero-value string.
	var raw []json.RawMessage
	if json.Unmarshal(p["abilities"], &raw) != nil {
		return false
	}
	for _, ability := range raw {
		if !identityStrings(identityPayload{"ability": ability}, "ability") {
			return false
		}
	}
	return true
}

func validHoneycombAuth(p identityPayload) bool {
	team, env, access := identityObject(p, "team"), identityObject(p, "environment"), identityObject(p, "api_key_access")
	if !identityStrings(p, "id") || !(identityStringEquals(p, "type", "configuration") || identityStringEquals(p, "type", "ingest")) ||
		identityHasErrors(team) || !identityStrings(team, "name", "slug") || env == nil || identityHasErrors(env) || access == nil || identityHasErrors(access) {
		return false
	}
	// Classic keys have empty environment strings; restricted keys may have no permissions.
	for _, field := range []string{"name", "slug"} {
		var value *string
		if json.Unmarshal(env[field], &value) != nil || value == nil {
			return false
		}
	}
	for _, raw := range access {
		var value *bool
		if json.Unmarshal(raw, &value) != nil || value == nil {
			return false
		}
	}
	return true
}

func validKeyCDNBalance(p identityPayload) bool {
	data := identityObject(p, "data")
	var amount string
	if !identityStringEquals(p, "status", "success") || identityHasErrors(data) || json.Unmarshal(data["amount"], &amount) != nil {
		return false
	}
	value, err := strconv.ParseFloat(amount, 64)
	return err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validWebScraperSitemaps(p identityPayload) bool {
	var success bool
	return json.Unmarshal(p["success"], &success) == nil && success &&
		identityNonnegativeIntegers(p, "current_page", "last_page", "total", "per_page") &&
		validIdentityCollection(p, "data", func(sitemap identityPayload) bool {
			return !identityHasErrors(sitemap) && collectionPositiveInteger(sitemap["id"]) && identityStrings(sitemap, "name")
		})
}

func validPostmarkStats(p identityPayload) bool {
	_, hasError := p["ErrorCode"]
	return !hasError && identityNonnegativeIntegers(p, "Sent", "Bounced", "SMTPApiErrors")
}

func validPostmarkSenders(p identityPayload) bool {
	_, hasError := p["ErrorCode"]
	return !hasError && identityNonnegativeIntegers(p, "TotalCount") && validIdentityCollection(p, "SenderSignatures", func(sender identityPayload) bool {
		var confirmed *bool
		return !identityHasErrors(sender) && collectionPositiveInteger(sender["ID"]) && identityStrings(sender, "EmailAddress") && json.Unmarshal(sender["Confirmed"], &confirmed) == nil && confirmed != nil
	})
}
