package detectors

import (
	"bytes"
	"encoding/json"
)

func validZohoCurrentUser(p identityPayload) bool {
	_, hasCode := p["code"]
	return !hasCode && validIdentityCollection(p, "users", func(user identityPayload) bool {
		return !identityHasErrors(user) && identityStrings(user, "id", "email")
	})
}

func validNylasGrants(p identityPayload) bool {
	return validIdentityCollection(p, "data", func(grant identityPayload) bool {
		return !identityHasErrors(grant) && identityStrings(grant, "id", "provider") && identityNonnegativeIntegers(grant, "created_at")
	})
}

func validGustoToken(p identityPayload) bool {
	var scope *string
	if json.Unmarshal(p["scope"], &scope) != nil || scope == nil {
		return false
	}
	// System tokens have no resource owner; tokens can have no resource or scopes.
	for _, field := range []string{"resource", "resource_owner"} {
		raw, ok := p[field]
		if !ok {
			return false
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		resource := identityObject(p, field)
		if identityHasErrors(resource) || !identityStrings(resource, "type", "uuid") {
			return false
		}
	}
	return true
}

func validThousandEyesGroups(p identityPayload) bool {
	_, hasStatus := p["status"]
	_, hasDetail := p["detail"]
	return !hasStatus && !hasDetail && validIdentityCollection(p, "accountGroups", func(group identityPayload) bool {
		return !identityHasErrors(group) && identityStrings(group, "aid", "accountGroupName")
	})
}

func validJumpCloudUsers(p identityPayload) bool {
	_, hasCode := p["code"]
	return !hasCode && identityNonnegativeIntegers(p, "totalCount") && validIdentityCollection(p, "results", func(user identityPayload) bool {
		return !identityHasErrors(user) && identityStrings(user, "_id")
	})
}
