package detectors

import "encoding/json"

func validQuoOrganization(p identityPayload) bool {
	org := identityObject(p, "data")
	return !identityHasErrors(org) && identityStrings(org, "id", "createdAt", "updatedAt") &&
		(identityStringEquals(org, "subscriptionStatus", "active") || identityStringEquals(org, "subscriptionStatus", "expired"))
}

func validKlaviyoAccount(p identityPayload) bool {
	var accounts []identityPayload
	if json.Unmarshal(p["data"], &accounts) != nil || len(accounts) != 1 {
		return false
	}
	account := accounts[0]
	attributes := identityObject(account, "attributes")
	return !identityHasErrors(account) && identityStringEquals(account, "type", "account") && identityStrings(account, "id") && !identityHasErrors(attributes) && identityStrings(attributes, "timezone")
}

func validSocketOrganizations(p identityPayload) bool {
	organizations := identityObject(p, "organizations")
	if organizations == nil {
		return false
	}
	for _, raw := range organizations {
		var org identityPayload
		if json.Unmarshal(raw, &org) != nil || identityHasErrors(org) || !identityStrings(org, "id", "slug", "plan") {
			return false
		}
	}
	return true
}

func validYousignUsers(p identityPayload) bool {
	meta := identityObject(p, "meta")
	var cursor *string
	if identityHasErrors(meta) || json.Unmarshal(meta["next_cursor"], &cursor) != nil {
		return false
	}
	return validIdentityCollection(p, "data", func(user identityPayload) bool {
		return !identityHasErrors(user) && identityStrings(user, "id", "email")
	})
}

func validCraftMyPDFAccount(p identityPayload) bool {
	if !identityStringEquals(p, "status", "success") || !identityStrings(p, "username", "created_at") {
		return false
	}
	for _, field := range []string{"quota_counter", "quota_max"} {
		var value *float64
		if json.Unmarshal(p[field], &value) != nil || value == nil || *value < 0 {
			return false
		}
	}
	return true
}

func validFastForexUsage(p identityPayload) bool {
	period := identityObject(p, "current_period")
	usage := identityObject(p, "usage")
	if !identityNonnegativeIntegers(p, "monthly_quota") || identityHasErrors(period) || !identityStrings(period, "start", "end") || !identityNonnegativeIntegers(period, "remaining_quota", "usage") || len(usage) == 0 {
		return false
	}
	for date := range usage {
		if !identityNonnegativeIntegers(usage, date) {
			return false
		}
	}
	return true
}
