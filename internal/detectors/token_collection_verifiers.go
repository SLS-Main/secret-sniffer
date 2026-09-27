package detectors

import "encoding/json"

func validBuildkiteToken(p identityPayload) bool {
	// Reuse the strict string-array check; a token may have no scopes.
	return identityStrings(p, "uuid", "created_at") && validPagerDutyAbilities(identityPayload{"abilities": p["scopes"]})
}

func validIncreasePrograms(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(item identityPayload) bool {
		return !identityHasErrors(item) && identityStringEquals(item, "type", "program") && identityStrings(item, "id", "name")
	})
}

func validPersonaInquiries(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(item identityPayload) bool {
		attrs := identityObject(item, "attributes")
		return !identityHasErrors(item) && !identityHasErrors(attrs) && identityStringEquals(item, "type", "inquiry") && identityStrings(item, "id") && identityStrings(attrs, "status")
	})
}

func validCircleConfiguration(p identityPayload) bool {
	data := identityObject(p, "data")
	payments := identityObject(data, "payments")
	_, hasCode := p["code"]
	return !hasCode && !identityHasErrors(data) && !identityHasErrors(payments) && identityStrings(payments, "masterWalletId")
}

func validCockroachClusters(p identityPayload) bool {
	_, hasCode := p["code"]
	return !hasCode && validIdentityCollection(p, "clusters", func(item identityPayload) bool {
		return !identityHasErrors(item) && identityStrings(item, "id", "name", "state")
	})
}

func validPolarOrganizations(p identityPayload) bool {
	_, hasDetail := p["detail"]
	pagination := identityObject(p, "pagination")
	return !hasDetail && !identityHasErrors(pagination) && identityNonnegativeIntegers(pagination, "total_count", "max_page") && validIdentityCollection(p, "items", func(item identityPayload) bool {
		return !identityHasErrors(item) && identityStrings(item, "id", "name", "slug")
	})
}

func validWrikeContacts(p identityPayload) bool {
	return identityStringEquals(p, "kind", "contacts") && validIdentityCollection(p, "data", func(item identityPayload) bool {
		var me bool
		return !identityHasErrors(item) && identityStrings(item, "id", "type") && json.Unmarshal(item["me"], &me) == nil && me
	})
}

func validMessageBirdBalance(p identityPayload) bool {
	var amount *float64
	return (identityStringEquals(p, "payment", "prepaid") || identityStringEquals(p, "payment", "postpaid")) && identityStrings(p, "type") && json.Unmarshal(p["amount"], &amount) == nil && amount != nil
}

func validImgixSources(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(item identityPayload) bool {
		attrs := identityObject(item, "attributes")
		return !identityHasErrors(item) && !identityHasErrors(attrs) && identityStringEquals(item, "type", "sources") && identityStrings(item, "id") && identityStrings(attrs, "name")
	})
}
