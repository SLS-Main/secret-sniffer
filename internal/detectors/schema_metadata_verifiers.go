package detectors

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func validNitroAccount(p identityPayload) bool {
	// The current API permits either JSON int64 or a decimal string ID.
	var id string
	if json.Unmarshal(p["id"], &id) == nil {
		if _, err := strconv.ParseUint(id, 10, 64); err != nil || id == "" {
			return false
		}
	} else if !identityNonnegativeIntegers(p, "id") {
		return false
	}
	// An account with overdraft enabled can legitimately have a negative balance.
	for _, field := range []string{"balance", "reserved"} {
		var value *float64
		if json.Unmarshal(p[field], &value) != nil || value == nil {
			return false
		}
	}
	return true
}

func validPendoSchema(p identityPayload) bool {
	// Built-in auto metadata distinguishes a schema from an arbitrary JSON object.
	if identityObject(p, "auto") == nil {
		return false
	}
	for group := range p {
		fields := identityObject(p, group)
		if fields == nil {
			return false
		}
		for name := range fields {
			field := identityObject(fields, name)
			var kind *string
			// Uninferred fields legitimately have an empty Type in the official example.
			if field == nil || identityHasErrors(field) || json.Unmarshal(field["Type"], &kind) != nil || kind == nil {
				return false
			}
		}
	}
	return true
}

func validSurveySparrowRoles(p identityPayload) bool {
	var more *bool
	return json.Unmarshal(p["has_next_page"], &more) == nil && more != nil && validIdentityCollection(p, "data", func(role identityPayload) bool {
		return !identityHasErrors(role) && identityNonnegativeIntegers(role, "id") && identityStrings(role, "name")
	})
}

func classifyVirusTotalSentinel(status int, body []byte) (VerificationResult, bool) {
	var p identityPayload
	if json.Unmarshal(body, &p) == nil && p != nil {
		if status == http.StatusOK && !identityHasErrors(p) {
			data := identityObject(p, "data")
			attributes := identityObject(data, "attributes")
			if !identityHasErrors(data) && identityStringEquals(data, "type", "file") && identityStringEquals(data, "id", strings.Repeat("0", 64)) && attributes != nil && !identityHasErrors(attributes) {
				return VerificationResult{Status: VerificationVerified}, true
			}
		}
		// Match only the structured provider code; prose can mention other errors.
		err := identityObject(p, "error")
		if len(p) == 1 && !identityHasErrors(err) {
			if status == http.StatusNotFound && identityStringEquals(err, "code", "NotFoundError") {
				return VerificationResult{Status: VerificationVerified, Message: "provider authenticated the sentinel lookup"}, true
			}
			if status == http.StatusUnauthorized && identityStringEquals(err, "code", "WrongCredentialsError") {
				return invalidCredentialResult(), true
			}
		}
	}
	return verifyJSONReadClassification(status, body)
}
