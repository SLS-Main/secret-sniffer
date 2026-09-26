package detectors

import (
	"encoding/json"
	"net/http"
)

func validSnykPrincipal(p identityPayload) bool {
	principal := identityObject(p, "data")
	attributes := identityObject(principal, "attributes")
	if identityHasErrors(principal) || identityHasErrors(attributes) || !identityStrings(principal, "id") {
		return false
	}
	if identityStringEquals(principal, "type", "user") {
		return identityStrings(attributes, "email")
	}
	return (identityStringEquals(principal, "type", "service_account") || identityStringEquals(principal, "type", "app_instance")) && identityStrings(attributes, "name")
}

func validShotstackTemplates(p identityPayload) bool {
	response := identityObject(p, "response")
	return string(p["success"]) == "true" && !identityHasErrors(response) && identityStrings(response, "owner") && validIdentityCollection(response, "templates", func(template identityPayload) bool {
		return !identityHasErrors(template) && identityStrings(template, "id", "name")
	})
}

func validProductboardMembers(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(member identityPayload) bool {
		return !identityHasErrors(member) && identityStrings(member, "id") && identityStringEquals(member, "type", "member") && !identityHasErrors(identityObject(member, "fields")) && identityStrings(identityObject(member, "fields"), "role")
	})
}

func validNorthflankAuth(p identityPayload) bool {
	auth := identityObject(p, "data")
	return !identityHasErrors(auth) && identityStrings(auth, "id", "entityId", "entityUid", "createdAt") &&
		(identityStringEquals(auth, "tokenKind", "api") || identityStringEquals(auth, "tokenKind", "session")) &&
		(identityStringEquals(auth, "entityType", "team") || identityStringEquals(auth, "entityType", "org"))
}

func validWistiaToken(p identityPayload) bool {
	if _, present := p["code"]; present {
		return false
	}
	if !identityStringEquals(p, "type", "permanent") && !identityStringEquals(p, "type", "expiring") && !identityStringEquals(p, "type", "oauth") {
		return false
	}
	if !principalStringList(p["scopes"]) {
		return false
	}
	var name *string
	if json.Unmarshal(p["name"], &name) != nil {
		return false
	}
	if identityStringEquals(p, "type", "oauth") {
		app := identityObject(p, "application")
		return !identityHasErrors(app) && identityStrings(app, "name") && principalStringList(app["scopes"])
	}
	return string(p["application"]) == "null"
}

func principalStringList(raw json.RawMessage) bool {
	var values []json.RawMessage
	if json.Unmarshal(raw, &values) != nil || values == nil {
		return false
	}
	for _, raw := range values {
		var value string
		if string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
			return false
		}
	}
	return true
}

func validTwelveDataUsage(p identityPayload) bool {
	if _, present := p["code"]; present {
		return false
	}
	if _, present := p["status"]; present && !identityStringEquals(p, "status", "ok") {
		return false
	}
	for _, field := range []string{"daily_usage", "plan_daily_limit"} {
		if _, present := p[field]; present && !identityNonnegativeIntegers(p, field) {
			return false
		}
	}
	return identityStrings(p, "timestamp", "plan_category") && identityNonnegativeIntegers(p, "current_usage", "plan_limit")
}

func validGuardianSearch(p identityPayload) bool {
	response := identityObject(p, "response")
	return !identityHasErrors(response) && identityStringEquals(response, "status", "ok") && identityStrings(response, "userTier") && identityNonnegativeIntegers(response, "total") && validIdentityCollection(response, "results", func(article identityPayload) bool {
		return !identityHasErrors(article) && identityStrings(article, "id", "type", "webUrl")
	})
}

func classifyNewsAPIHeadlines(status int, body []byte) (VerificationResult, bool) {
	var p identityPayload
	if json.Unmarshal(body, &p) == nil && p != nil && !identityHasErrors(p) {
		_, hasCode := p["code"]
		if status == http.StatusOK && !hasCode && identityStringEquals(p, "status", "ok") && identityNonnegativeIntegers(p, "totalResults") && validIdentityCollection(p, "articles", func(article identityPayload) bool {
			return !identityHasErrors(article) && identityStrings(article, "url", "publishedAt")
		}) {
			return VerificationResult{Status: VerificationVerified}, true
		}
		_, hasArticles := p["articles"]
		_, hasTotal := p["totalResults"]
		if status == http.StatusUnauthorized && !hasArticles && !hasTotal && identityStringEquals(p, "status", "error") && (identityStringEquals(p, "code", "apiKeyInvalid") || identityStringEquals(p, "code", "apiKeyDisabled")) {
			return invalidCredentialResult(), true
		}
	}
	return verifyJSONReadClassification(status, body)
}
