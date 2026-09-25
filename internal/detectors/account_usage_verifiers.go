package detectors

import "encoding/json"

func identityNonnegativeIntegers(p identityPayload, fields ...string) bool {
	if identityHasErrors(p) {
		return false
	}
	for _, field := range fields {
		var value *int64
		if json.Unmarshal(p[field], &value) != nil || value == nil || *value < 0 {
			return false
		}
	}
	return true
}

func validRestpackUsage(p identityPayload) bool {
	return identityStrings(p, "from", "to") && identityNonnegativeIntegers(p, "limit", "total") &&
		validIdentityCollection(p, "days", func(day identityPayload) bool {
			return identityStrings(day, "day") && identityNonnegativeIntegers(day, "count")
		})
}

func validMiroTokenContext(p identityPayload) bool {
	user := identityObject(p, "user")
	if !identityStringEquals(p, "type", "oAuthToken") || identityHasErrors(user) || !identityStringEquals(user, "type", "user") || !identityStrings(user, "id") {
		return false
	}
	var scopes []json.RawMessage
	if json.Unmarshal(p["scopes"], &scopes) != nil || scopes == nil {
		return false
	}
	for _, scope := range scopes {
		if !identityStrings(identityPayload{"scope": scope}, "scope") {
			return false
		}
	}
	return true
}
