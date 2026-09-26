package detectors

import (
	"encoding/json"
	"net/http"
)

func validSignaturitSignature(p identityPayload) bool {
	return !identityHasErrors(p) && identityStrings(p, "id", "created_at") && validIdentityCollection(p, "documents", func(document identityPayload) bool {
		// A failed document is still evidence of authenticated collection access.
		return !identityHasErrors(document) && identityStrings(document, "id", "status")
	})
}

func validKlipfolioProfile(p identityPayload) bool {
	if meta, present := p["meta"]; present {
		var m identityPayload
		if json.Unmarshal(meta, &m) != nil || m == nil || identityHasErrors(m) || string(m["success"]) != "true" {
			return false
		}
	}
	user := identityObject(p, "data")
	return !identityHasErrors(user) && identityStrings(user, "id", "email")
}

func validMoosendLists(p identityPayload) bool {
	// Do not let a missing Code default to a successful zero value.
	if string(p["Code"]) != "0" {
		return false
	}
	if raw, present := p["Error"]; present && string(raw) != "null" && string(raw) != `""` {
		return false
	}
	context := identityObject(p, "Context")
	return !identityHasErrors(context) && validIdentityCollection(context, "MailingLists", func(list identityPayload) bool {
		return !identityHasErrors(list) && identityStrings(list, "ID", "Name")
	})
}

func classifyDynalistFiles(status int, body []byte) (VerificationResult, bool) {
	var p identityPayload
	if status == http.StatusOK && json.Unmarshal(body, &p) == nil && p != nil && !identityHasErrors(p) {
		if identityStringEquals(p, "_code", "InvalidToken") {
			// Success-looking fields contradict a credential rejection.
			_, hasFiles := p["files"]
			_, hasRoot := p["root_file_id"]
			if !hasFiles && !hasRoot {
				return invalidCredentialResult(), true
			}
		}
		if identityStringEquals(p, "_code", "TooManyRequests") {
			return unknownVerificationResult("rate_limited", "provider rate limit reached"), true
		}
		if identityStringEquals(p, "_code", "OK") && identityStrings(p, "root_file_id") && validIdentityCollection(p, "files", func(file identityPayload) bool {
			return !identityHasErrors(file) && identityStrings(file, "id") && (identityStringEquals(file, "type", "document") || identityStringEquals(file, "type", "folder"))
		}) {
			return VerificationResult{Status: VerificationVerified}, true
		}
	}
	return verifyJSONReadClassification(status, body)
}
