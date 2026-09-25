package detectors

import "encoding/json"

// A present empty collection is valid; missing, null, and malformed entries are not.
func validIdentityCollection(p identityPayload, field string, valid func(identityPayload) bool) bool {
	var items []identityPayload
	if json.Unmarshal(p[field], &items) != nil || items == nil {
		return false
	}
	for _, item := range items {
		if item == nil || !valid(item) {
			return false
		}
	}
	return true
}

func identityStringEquals(p identityPayload, field, expected string) bool {
	var value string
	return json.Unmarshal(p[field], &value) == nil && value == expected
}

func validContentfulSpaces(p identityPayload) bool {
	return identityStringEquals(identityObject(p, "sys"), "type", "Array") && validIdentityCollection(p, "items", func(space identityPayload) bool {
		sys := identityObject(space, "sys")
		return identityStringEquals(sys, "type", "Space") && identityStrings(sys, "id") && identityStrings(space, "name")
	})
}

func validAssemblyAITranscripts(p identityPayload) bool {
	page := identityObject(p, "page_details")
	var count *int
	if json.Unmarshal(page["result_count"], &count) != nil || count == nil || *count < 0 {
		return false
	}
	if !validIdentityCollection(p, "transcripts", func(transcript identityPayload) bool {
		if !identityStrings(transcript, "id") {
			return false
		}
		for _, status := range []string{"queued", "processing", "completed", "error"} {
			if identityStringEquals(transcript, "status", status) {
				return true
			}
		}
		return false
	}) {
		return false
	}
	var transcripts []json.RawMessage
	return json.Unmarshal(p["transcripts"], &transcripts) == nil && len(transcripts) == *count
}

func validRevAIAccount(p identityPayload) bool {
	if !identityStrings(p, "email") {
		return false
	}
	for _, field := range []string{"free_balance", "purchased_balance", "total_balance"} {
		var value *float64
		if json.Unmarshal(p[field], &value) != nil || value == nil {
			return false
		}
	}
	return true
}
