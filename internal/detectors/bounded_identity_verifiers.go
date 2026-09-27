package detectors

import "encoding/json"

func validTriggerRuns(p identityPayload) bool {
	page := identityObject(p, "pagination")
	if page == nil || identityHasErrors(page) {
		return false
	}
	for _, field := range []string{"next", "previous"} {
		if _, ok := page[field]; ok && !identityStrings(page, field) {
			return false
		}
	}
	return validIdentityCollection(p, "data", func(run identityPayload) bool {
		env := identityObject(run, "env")
		var isTest *bool
		return !identityHasErrors(run) && !identityHasErrors(env) && identityStrings(run, "id", "status", "taskIdentifier", "createdAt", "updatedAt") &&
			identityStrings(env, "id", "name") && json.Unmarshal(run["isTest"], &isTest) == nil && isTest != nil
	})
}

func validLINEBot(p identityPayload) bool {
	return identityStrings(p, "userId", "basicId", "displayName") &&
		(identityStringEquals(p, "chatMode", "chat") || identityStringEquals(p, "chatMode", "bot")) &&
		(identityStringEquals(p, "markAsReadMode", "auto") || identityStringEquals(p, "markAsReadMode", "manual"))
}
