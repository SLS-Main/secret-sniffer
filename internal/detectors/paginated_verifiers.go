package detectors

import "encoding/json"

// Require the JSON integer form rather than accepting numeric strings as IDs.
func collectionPositiveInteger(raw json.RawMessage) bool {
	return len(raw) > 0 && raw[0] >= '1' && raw[0] <= '9' && identityID(raw)
}

func validBetterStackMembers(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(member identityPayload) bool {
		attributes := identityObject(member, "attributes")
		return !identityHasErrors(member) && !identityHasErrors(attributes) && identityStrings(member, "id") && identityStrings(attributes, "email", "role") &&
			(identityStringEquals(member, "type", "team_member") || identityStringEquals(member, "type", "team_member_invitation"))
	})
}

func validMavenlinkSelf(p identityPayload) bool {
	var results []identityPayload
	if json.Unmarshal(p["results"], &results) != nil || len(results) != 1 || string(p["count"]) != "1" {
		return false
	}
	result := results[0]
	if identityHasErrors(result) || !identityStringEquals(result, "key", "users") || !identityStrings(result, "id") {
		return false
	}
	var id string
	if json.Unmarshal(result["id"], &id) != nil {
		return false
	}
	user := identityObject(p, "users", id)
	return !identityHasErrors(user) && identityStringEquals(user, "id", id) && identityStrings(user, "email_address")
}

func validIntrinioUsage(p identityPayload) bool {
	account := identityObject(p, "account")
	return !identityHasErrors(account) && identityStrings(account, "email") && validIdentityCollection(p, "usage", func(usage identityPayload) bool {
		// Counters are documented as strings; do not assume numeric quota limits.
		return !identityHasErrors(usage) && identityStrings(usage, "access_code", "count", "limit")
	})
}

func validSnipcartOrders(p identityPayload) bool {
	return identityNonnegativeIntegers(p, "totalItems", "offset", "limit") && validIdentityCollection(p, "items", func(order identityPayload) bool {
		return !identityHasErrors(order) && identityStrings(order, "token", "status")
	})
}

func validScrutinizerRepositories(p identityPayload) bool {
	embedded := identityObject(p, "_embedded")
	return identityNonnegativeIntegers(p, "page", "limit") && !identityHasErrors(embedded) && validIdentityCollection(embedded, "repositories", func(repo identityPayload) bool {
		links := identityObject(repo, "_links", "self")
		return !identityHasErrors(repo) && !identityHasErrors(links) && identityStrings(repo, "type", "created_at") && identityStrings(links, "href")
	})
}

func validSurvicateSurveys(p identityPayload) bool {
	pagination := identityObject(p, "pagination_data")
	if identityHasErrors(pagination) || (string(pagination["has_more"]) != "true" && string(pagination["has_more"]) != "false") {
		return false
	}
	return validIdentityCollection(p, "data", func(survey identityPayload) bool {
		return !identityHasErrors(survey) && identityStrings(survey, "id", "name", "created_at") &&
			(identityStringEquals(survey, "type", "PageSurvey") || identityStringEquals(survey, "type", "WidgetSurvey") || identityStringEquals(survey, "type", "MobileSurvey") || identityStringEquals(survey, "type", "IntercomSurvey"))
	})
}

func validTeachableCourses(p identityPayload) bool {
	meta := identityObject(p, "meta")
	return !identityHasErrors(meta) && identityNonnegativeIntegers(meta, "total", "page", "per_page") && validIdentityCollection(p, "courses", func(course identityPayload) bool {
		return !identityHasErrors(course) && collectionPositiveInteger(course["id"]) && identityStrings(course, "name") && (string(course["is_published"]) == "true" || string(course["is_published"]) == "false")
	})
}
