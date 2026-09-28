package detectors

import "encoding/json"

func contextInteger(raw json.RawMessage) bool {
	var n *int64
	return json.Unmarshal(raw, &n) == nil && n != nil && *n >= 0
}

func contextBoolean(raw json.RawMessage) bool {
	var value *bool
	return json.Unmarshal(raw, &value) == nil && value != nil
}

func validContextCollection(p identityPayload, field string, fields ...string) bool {
	var items []identityPayload
	if json.Unmarshal(p[field], &items) != nil || items == nil {
		return false
	}
	for _, item := range items {
		if identityHasErrors(item) || !identityStrings(item, fields...) {
			return false
		}
	}
	return true
}

func validTrayWorkspaces(p identityPayload) bool {
	page := identityObject(p, "pageInfo")
	if identityHasErrors(page) || !contextBoolean(page["hasNextPage"]) || !contextBoolean(page["hasPreviousPage"]) {
		return false
	}
	// The OpenAPI schema makes elements optional, including for an empty page.
	if _, present := p["elements"]; !present {
		return true
	}
	return validContextCollection(p, "elements", "id", "name", "type")
}

func validPercyProject(p identityPayload) bool {
	project := identityObject(p, "data")
	var kind string
	attributes := identityObject(project, "attributes")
	return !identityHasErrors(project) && !identityHasErrors(attributes) && identityStrings(project, "id") &&
		json.Unmarshal(project["type"], &kind) == nil && kind == "projects" &&
		identityStrings(attributes, "name", "slug", "full-slug") && contextBoolean(attributes["publicly-readable"])
}

func validDataGovStations(p identityPayload) bool {
	var stations []json.RawMessage
	return contextInteger(p["total_results"]) && identityStrings(p, "station_locator_url") &&
		json.Unmarshal(p["fuel_stations"], &stations) == nil && stations != nil && len(stations) == 0
}

func validAPISportsStatus(body []byte) bool {
	var p identityPayload
	if json.Unmarshal(body, &p) != nil || p == nil {
		return false
	}
	var emptyArray []json.RawMessage
	var emptyObject identityPayload
	errors := p["errors"]
	if !(json.Unmarshal(errors, &emptyArray) == nil && emptyArray != nil && len(emptyArray) == 0) &&
		!(json.Unmarshal(errors, &emptyObject) == nil && emptyObject != nil && len(emptyObject) == 0) {
		return false
	}
	delete(p, "errors")
	var results int
	var get string
	response := identityObject(p, "response")
	account := identityObject(response, "account")
	subscription := identityObject(response, "subscription")
	requests := identityObject(response, "requests")
	return !identityHasErrors(p) && !identityHasErrors(response) && !identityHasErrors(account) &&
		!identityHasErrors(subscription) && !identityHasErrors(requests) &&
		json.Unmarshal(p["results"], &results) == nil && results == 1 &&
		json.Unmarshal(p["get"], &get) == nil && get == "status" && identityStrings(account, "email") &&
		identityStrings(subscription, "plan") &&
		contextInteger(requests["current"]) && contextInteger(requests["limit_day"])
}
