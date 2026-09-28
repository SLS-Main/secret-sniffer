package detectors

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var metadataRecordID = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)

// Context conflict/empty-field checks are performed by verifyContextualProvider.
// Each operation reads metadata only; bodies and response links are suppressed.
func verifyScopedMetadataProvider(ctx context.Context, c Candidate) VerificationResult {
	p := c.SecretParts
	base, path, header, prefix := "", "", "Authorization", "Bearer "
	var valid func(identityPayload) bool
	var item func(identityPayload) bool
	switch c.DetectorID {
	case "mailmodo-api-key":
		base = contextBase(p["endpoint"], "https://api.mailmodo.com/api/v1", "https://api.mailmodo.com/api/v1")
		path, header, prefix = "/getAllContactLists", "mmApiKey", ""
		valid = func(v identityPayload) bool {
			if _, failed := v["Error"]; failed {
				return false
			}
			return validIdentityCollection(v, "listDetails", func(v identityPayload) bool {
				_, hasCount := v["contacts_count"]
				return !identityHasErrors(v) && identityStrings(v, "id", "name", "created_at") && (!hasCount || metadataNumbers(v, "contacts_count"))
			})
		}
	case "beebole-api-token":
		if p["credential_type"] != "graphql" {
			return unknownVerificationResult("credential_type", "verification requires a new-platform Beebole GraphQL API key")
		}
		base = contextBase(p["endpoint"], "", "https://app.beebole.com/graphql")
		header, prefix = "apikey", ""
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			person := identityObject(data, "currentPerson")
			// Beebole can return HTTP 200 with partial data and field-level
			// permission failures. Never let partial success override them.
			permissions, present := v["permissionsErrors"]
			var denied []json.RawMessage
			if present && (json.Unmarshal(permissions, &denied) != nil || denied == nil || len(denied) != 0) {
				return false
			}
			return !identityHasErrors(data) && !identityHasErrors(person) && identityStrings(person, "name", "email")
		}
	case "caflou-api-key":
		if !metadataRecordID.MatchString(p["account_id"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://app.caflou.com/api/v1", "https://app.caflou.com/api/v1")
		path = "/" + p["account_id"] + "/account_users?per=1&page=1"
		item = func(v identityPayload) bool {
			return !identityHasErrors(v) && finalPositiveInteger(v["id"]) && identityStrings(v, "email") && contextBoolean(v["active"])
		}
	case "signable-api-key":
		base = contextBase(p["endpoint"], "https://api.signable.co.uk/v1", "https://api.signable.co.uk/v1")
		path = "/settings"
		valid = func(v identityPayload) bool {
			if _, hasCode := v["code"]; hasCode {
				return false
			}
			return string(v["http"]) == "200" && contextBoolean(v["setting_signature_more_info"]) && identityStrings(v, "setting_signature_format_default", "setting_signature_format_accepted")
		}
	case "simplesat-api-key":
		base = contextBase(p["endpoint"], "https://api.simplesat.io/api/v1", "https://api.simplesat.io/api/v1")
		path, header, prefix = "/questions?page_size=1&page=1", "X-Simplesat-Token", ""
		valid = func(v identityPayload) bool {
			return identityNonnegativeIntegers(v, "count") && validIdentityCollection(v, "questions", func(v identityPayload) bool {
				return !identityHasErrors(v) && finalPositiveInteger(v["id"]) && identityStrings(v, "type") && contextBoolean(v["required"])
			})
		}
	case "goodday-api-key":
		// Enterprise deployments can use a different API version. Do not
		// guess that those credentials are accepted by the cloud 2.0 API.
		base = contextBase(p["endpoint"], "", "https://api.goodday.work/2.0")
		path, header, prefix = "/skills", "gd-api-token", ""
		item = func(v identityPayload) bool {
			if _, failed := v["errorMessage"]; failed {
				return false
			}
			return !identityHasErrors(v) && identityStrings(v, "id", "label")
		}
	case "mixmax-api-key":
		base = contextBase(p["endpoint"], "https://api.mixmax.com/v1", "https://api.mixmax.com/v1")
		path, header, prefix = "/tasks?limit=1", "X-API-Token", ""
		valid = func(v identityPayload) bool {
			return identityNonnegativeIntegers(v, "total") && contextBoolean(v["hasNext"]) && contextBoolean(v["hasPrevious"]) && validIdentityCollection(v, "results", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "_id", "type", "status")
			})
		}
	case "overloop-api-key":
		base = contextBase(p["endpoint"], "https://api.overloop.com/public/v1", "https://api.overloop.com/public/v1")
		path, prefix = "/me", ""
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			attributes := identityObject(data, "attributes")
			return !identityHasErrors(data) && !identityHasErrors(attributes) && identityStringEquals(data, "type", "users") && identityStrings(data, "id") && identityStrings(attributes, "email", "name")
		}
	case "worksnaps-api-key":
		id, err := strconv.ParseInt(p["project_id"], 10, 32)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != p["project_id"] {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://api.worksnaps.com/api", "https://api.worksnaps.com/api")
		path = "/projects/" + p["project_id"] + ".xml"
	case "apacta-api-key":
		if p["credential_type"] != "bearer" {
			return unknownVerificationResult("credential_type", "verification requires Apacta Bearer-token context")
		}
		if !contextUUID.MatchString(p["time_entry_type_id"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://app.apacta.com/api/v1", "https://app.apacta.com/api/v1")
		path = "/time_entry_types/" + p["time_entry_type_id"]
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			return string(v["success"]) == "true" && !identityHasErrors(data) && identityStringEquals(data, "id", p["time_entry_type_id"]) && identityStrings(data, "name")
		}
	default:
		return verifyModernMetadataProvider(ctx, c)
	}
	if base == "" {
		return missingVerificationContext()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return missingVerificationContext()
	}
	if c.DetectorID == "beebole-api-token" {
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base, strings.NewReader(`{"query":"{ currentPerson { name email } }"}`))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(header, prefix+c.Secret)
	if c.DetectorID == "beebole-api-token" || c.DetectorID == "simplesat-api-key" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.DetectorID == "overloop-api-key" {
		req.Header.Set("Accept", "application/vnd.api+json")
		req.Header.Set("Content-Type", "application/vnd.api+json; charset=utf-8")
	}
	if c.DetectorID == "signable-api-key" {
		req.SetBasicAuth(c.Secret, "x")
	}
	if c.DetectorID == "worksnaps-api-key" {
		req.SetBasicAuth(c.Secret, "ignored")
		req.Header.Set("Accept", "application/xml")
		req.Header.Set("Content-Type", "application/xml")
		result := verifyHTTPRequestWithClassifier(ctx, req, func(status int, body []byte) (VerificationResult, bool) {
			if status == http.StatusTooManyRequests || status >= 500 {
				return VerificationResult{}, false
			}
			if status == http.StatusOK && validWorksnapsProject(body, p["project_id"]) {
				return VerificationResult{Status: VerificationVerified}, true
			}
			return unknownVerificationResult("provider_response", "provider returned an unexpected verification response"), true
		})
		result.Response = ""
		return result
	}
	if item != nil {
		return verifyInventoryArray(ctx, req, item)
	}
	return verifyIdentityRequest(ctx, req, valid)
}

// Parse the whole XML document, not a substring or just the first root. Reject
// duplicate identity fields, nested error payloads, directives and extra roots.
// encoding/xml never fetches external entities; directives are rejected anyway.
func validWorksnapsProject(body []byte, id string) bool {
	d := xml.NewDecoder(strings.NewReader(string(body)))
	depth, roots := 0, 0
	fields := map[string]*strings.Builder{}
	current := ""
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		switch token := token.(type) {
		case xml.StartElement:
			if token.Name.Space != "" {
				return false
			}
			switch token.Name.Local {
			case "error", "errors", "error_code", "error_string":
				return false
			}
			if depth == 0 {
				roots++
				if roots != 1 || token.Name.Local != "project" {
					return false
				}
			}
			depth++
			if depth == 2 {
				switch token.Name.Local {
				case "id", "name", "status":
					current = token.Name.Local
					if _, duplicate := fields[current]; duplicate {
						return false
					}
					fields[current] = &strings.Builder{}
				}
			} else if current != "" {
				return false
			}
		case xml.EndElement:
			if depth == 2 {
				current = ""
			}
			depth--
		case xml.CharData:
			if current != "" {
				fields[current].Write(token)
			} else if depth < 2 && strings.TrimSpace(string(token)) != "" {
				return false
			}
		case xml.Directive:
			return false
		case xml.ProcInst:
			if token.Target != "xml" || roots != 0 {
				return false
			}
		}
	}
	value := func(field string) string {
		if fields[field] == nil {
			return ""
		}
		return strings.TrimSpace(fields[field].String())
	}
	return roots == 1 && depth == 0 && value("id") == id && value("name") != "" && (value("status") == "active" || value("status") == "archived")
}
