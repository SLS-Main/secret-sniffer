package detectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
)

var nozbeRecordID = regexp.MustCompile(`^[A-Za-z0-9]{16}$`)

// All bases are fixed provider endpoints. Context validation and conflict
// checks run before dispatch here; no deployment or version fallback is used.
func verifyModernMetadataProvider(ctx context.Context, c Candidate) VerificationResult {
	base, path, header, prefix := "", "", "Authorization", ""
	var valid func(identityPayload) bool
	var item func(identityPayload) bool
	switch c.DetectorID {
	case "salesblink-api-key":
		base = contextBase(c.SecretParts["endpoint"], "", "https://run.salesblink.io/api/public/v1.0.0")
		path = "/folders?limit=1&skip=0"
		valid = func(v identityPayload) bool {
			return string(v["success"]) == "true" && validIdentityCollection(v, "data", func(folder identityPayload) bool {
				// General folders omit type; only email-sender folders require it.
				return !identityHasErrors(folder) && identityStrings(folder, "id", "name")
			})
		}
	case "autoklose-api-key":
		base = contextBase(c.SecretParts["endpoint"], "https://api.autoklose.com/api", "https://api.autoklose.com/api")
		// The documented path has no trailing slash. Query authentication is
		// documented by the provider; response and transport errors are suppressed.
		path, header = "/me?api_token="+url.QueryEscape(c.Secret), ""
		valid = func(v identityPayload) bool {
			return finalPositiveInteger(v["id"]) && identityStrings(v, "email", "role")
		}
	case "stormboard-api-key":
		base = contextBase(c.SecretParts["endpoint"], "https://api.stormboard.com", "https://api.stormboard.com")
		path, header = "/users/test", "X-API-Key"
		valid = func(v identityPayload) bool {
			return string(v["status"]) == "200" && identityStringEquals(v, "message", "Connected, w00t")
		}
	case "teletype-api-key":
		base = contextBase(c.SecretParts["endpoint"], "https://api.teletype.app/public/api/v1", "https://api.teletype.app/public/api/v1")
		path, header = "/project/details", "X-Auth-Token"
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			created := identityObject(data, "createdAt")
			var errs []json.RawMessage
			return string(v["success"]) == "true" && string(v["errorsType"]) == "null" &&
				json.Unmarshal(v["errors"], &errs) == nil && errs != nil && len(errs) == 0 &&
				!identityHasErrors(data) && !identityHasErrors(created) &&
				identityStrings(data, "id", "owner_id", "name", "domain", "url") && identityStrings(created, "date", "timezone")
		}
	case "clustdoc-api-key":
		// The provider documents shared V1/V2 tokens but distinct sandbox and
		// production deployments. Require an explicit base rather than guessing.
		base = contextBase(c.SecretParts["endpoint"], "", "https://app.clustdoc.com/api/v2", "https://sandbox.clustdoc.com/api/v2")
		path, prefix = "/tags?per_page=1&page=1", "Bearer "
		valid = func(v identityPayload) bool {
			meta := identityObject(v, "meta")
			if _, failed := v["type"]; failed {
				return false
			}
			return !identityHasErrors(meta) && finalPositiveInteger(meta["current_page"]) && finalPositiveInteger(meta["per_page"]) && identityNonnegativeIntegers(meta, "total") &&
				validIdentityCollection(v, "data", func(tag identityPayload) bool {
					return !identityHasErrors(tag) && finalPositiveInteger(tag["id"]) && identityStrings(tag, "name")
				})
		}
	case "nozbeteams-api-token":
		base = contextBase(c.SecretParts["endpoint"], "https://api4.nozbe.com/v1/api", "https://api4.nozbe.com/v1/api")
		path = "/teams?limit=1&offset=0&fields=id,name"
		item = func(team identityPayload) bool {
			var id string
			return !identityHasErrors(team) && json.Unmarshal(team["id"], &id) == nil && nozbeRecordID.MatchString(id) && identityStrings(team, "name")
		}
	default:
		return missingVerificationContext()
	}
	if base == "" {
		return missingVerificationContext()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return missingVerificationContext()
	}
	req.Header.Set("Accept", "application/json")
	if header != "" {
		req.Header.Set(header, prefix+c.Secret)
	}
	if item != nil {
		return verifyInventoryArray(ctx, req, item)
	}
	return verifyIdentityRequest(ctx, req, valid)
}
