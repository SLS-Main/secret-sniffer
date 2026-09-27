package detectors

import (
	"encoding/json"
	"regexp"
)

var harnessPersonalToken = regexp.MustCompile(`^pat\.[A-Za-z0-9]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20}$`)

func validTemporalIdentity(p identityPayload) bool {
	_, hasCode := p["code"]
	if hasCode {
		return false
	}
	user, service := identityObject(p, "user"), identityObject(p, "serviceAccount")
	// The caller is a user or service account, never both. Optional key metadata
	// is not needed to authenticate the principal and is suppressed with the body.
	if (user == nil) == (service == nil) {
		return false
	}
	principal, field := user, "email"
	if service != nil {
		principal, field = service, "name"
	}
	spec := identityObject(principal, "spec")
	return !identityHasErrors(principal) && !identityHasErrors(spec) && identityStrings(principal, "id") && identityStrings(spec, field)
}

func validBunnyStatistics(p identityPayload) bool {
	_, hasErrorKey := p["ErrorKey"]
	var hitRate *float64
	return !hasErrorKey && identityNonnegativeIntegers(p, "TotalBandwidthUsed", "TotalOriginTraffic", "AverageOriginResponseTime", "TotalRequestsServed") && json.Unmarshal(p["CacheHitRate"], &hitRate) == nil && hitRate != nil && *hitRate >= 0
}

func validPartnerStackPartnerships(p identityPayload) bool {
	var status *int
	data := identityObject(p, "data")
	var more *bool
	return json.Unmarshal(p["status"], &status) == nil && status != nil && *status == 200 && !identityHasErrors(data) && json.Unmarshal(data["has_more"], &more) == nil && more != nil && validIdentityCollection(data, "items", func(partnership identityPayload) bool {
		company := identityObject(partnership, "company")
		return !identityHasErrors(partnership) && !identityHasErrors(company) && identityStrings(partnership, "key") && identityNonnegativeIntegers(company, "id")
	})
}
