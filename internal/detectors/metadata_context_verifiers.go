package detectors

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var stitchConnectCredential = regexp.MustCompile(`^ac_[a-z0-9]{32}$`)
var stitchClientID = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
var denoOrganizationCredential = regexp.MustCompile(`^ddo_[A-Za-z0-9_-]{20,256}$`)

// Called after the shared context conflict/empty-field checks. Read-only POSTs
// have explicit bodies; returned credentials and metadata are always suppressed.
func verifyMetadataContextProvider(ctx context.Context, c Candidate) VerificationResult {
	p := c.SecretParts
	base, path, header, prefix := "", "", "Authorization", "Bearer "
	var valid func(identityPayload) bool
	var item func(identityPayload) bool
	switch c.DetectorID {
	case "pandadoc-api-key":
		prefix = "API-Key "
		switch p["credential_type"] {
		case "", "api_key":
		case "bearer":
			prefix = "Bearer "
		default:
			return unknownVerificationResult("credential_type", "verification requires a PandaDoc API key or access token")
		}
		base = contextBase(p["endpoint"], "https://api.pandadoc.com", "https://api.pandadoc.com")
		path = "/public/v1/documents/folders?count=1&page=1"
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "results", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "uuid", "name", "date_created") && contextBoolean(v["has_folders"]) && contextBoolean(v["has_items"])
			})
		}
	case "appointedd-api-key":
		base = contextBase(p["endpoint"], "https://api.appointedd.com/v1", "https://api.appointedd.com/v1")
		path, header, prefix = "/resources/groups?limit=1", "X-API-KEY", ""
		valid = func(v identityPayload) bool {
			return identityNonnegativeIntegers(v, "total") && validIdentityCollection(v, "data", func(v identityPayload) bool { return !identityHasErrors(v) && identityStrings(v, "id", "name") })
		}
	case "flexport-api-key":
		// Fulfillment/logistics keys and OAuth client secrets are not freight
		// access tokens. Never exchange a secret or guess between product APIs.
		if p["credential_type"] != "bearer" || strings.HasPrefix(c.Secret, "shltm_") {
			return unknownVerificationResult("credential_type", "verification requires explicit Flexport freight bearer-token context")
		}
		base = contextBase(p["endpoint"], "", "https://api.flexport.com")
		path = "/network/me/companies"
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			return identityStringEquals(v, "_object", "/api/response") && string(v["version"]) == "2" && !identityHasErrors(data) && identityStringEquals(data, "_object", "/network/company") && identityStrings(data, "id", "name") && contextBoolean(data["editable"])
		}
	case "gyazo-api-token":
		if kind := p["credential_type"]; kind != "" && kind != "bearer" {
			return unknownVerificationResult("credential_type", "verification requires a Gyazo access token")
		}
		base = contextBase(p["endpoint"], "https://api.gyazo.com", "https://api.gyazo.com")
		path = "/api/users/me"
		valid = func(v identityPayload) bool {
			user := identityObject(v, "user")
			return !identityHasErrors(user) && identityStrings(user, "uid", "email")
		}
	case "happyscribe-api-key":
		base = contextBase(p["endpoint"], "https://www.happyscribe.com/api/v1", "https://www.happyscribe.com/api/v1")
		// Organization metadata avoids transcript contents and processing jobs.
		// No server pagination is documented; read one byte-capped response.
		path = "/organizations"
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "organizations", func(v identityPayload) bool {
				return !identityHasErrors(v) && finalPositiveInteger(v["id"]) && identityStrings(v, "name", "role", "createdAt", "updatedAt")
			})
		}
	case "hightouch-api-key":
		base = contextBase(p["endpoint"], "https://api.hightouch.com/api/v1", "https://api.hightouch.com/api/v1")
		path = "/events/domains?limit=1&offset=0"
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "data", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "id", "name") && metadataNumbers(v, "workspaceId")
			})
		}
	case "deno-deploy-token":
		if !denoOrganizationCredential.MatchString(c.Secret) {
			return unknownVerificationResult("credential_type", "verification requires a Deno organization access token")
		}
		base = contextBase(p["endpoint"], "https://api.deno.com", "https://api.deno.com")
		path = "/v2/domains?limit=1"
		item = func(v identityPayload) bool {
			return !identityHasErrors(v) && identityStrings(v, "id", "organization_id", "domain") && contextBoolean(v["is_validated"])
		}
	case "ngrok-token":
		if p["credential_type"] != "api" {
			return unknownVerificationResult("credential_type", "verification requires explicit ngrok API-key context")
		}
		base = contextBase(p["endpoint"], "https://api.ngrok.com", "https://api.ngrok.com")
		path = "/agent_ingresses?limit=1"
		valid = func(v identityPayload) bool {
			return identityStrings(v, "uri") && validIdentityCollection(v, "ingresses", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "id", "domain", "created_at")
			})
		}
	case "convertapi-secret":
		if p["credential_type"] != "master" {
			return unknownVerificationResult("credential_type", "verification requires explicit ConvertAPI Master Token context")
		}
		base = contextBase(p["endpoint"], "https://v2.convertapi.com", "https://v2.convertapi.com")
		path = "/user"
		valid = func(v identityPayload) bool {
			return contextBoolean(v["Active"]) && identityStrings(v, "Email") && identityNonnegativeIntegers(v, "ConversionsTotal", "ConversionsConsumed")
		}
	case "voicegain-api-key":
		if !contextUUID.MatchString(p["config_id"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "", "https://api.voicegain.ai/v1")
		path = "/sa/config/" + p["config_id"]
		valid = func(v identityPayload) bool {
			return identityStringEquals(v, "saConfId", p["config_id"]) && identityStrings(v, "name") && contextBoolean(v["builtIn"])
		}
	case "stitchdata-api-token":
		if !stitchConnectCredential.MatchString(c.Secret) {
			return unknownVerificationResult("credential_type", "verification requires a Stitch Connect account access token")
		}
		if !stitchClientID.MatchString(p["client_id"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "", "https://api.stitchdata.com")
		path = "/v4/" + p["client_id"] + "/extractions?page=1"
		valid = func(v identityPayload) bool {
			return finalPositiveInteger(v["page"]) && identityNonnegativeIntegers(v, "total") && validIdentityCollection(v, "data", func(v identityPayload) bool {
				var client int64
				return !identityHasErrors(v) && json.Unmarshal(v["stitch_client_id"], &client) == nil && strconv.FormatInt(client, 10) == p["client_id"] && finalPositiveInteger(v["source_id"]) && identityStrings(v, "job_name")
			})
		}
	case "qubole-api-token":
		base = contextBase(p["endpoint"], "", "https://api.qubole.com", "https://in.qubole.com", "https://eu.qubole.com", "https://us.qubole.com", "https://gcp.qubole.com")
		// This reads one month of precomputed usage, not a query or compute job.
		month := time.Now().UTC().Format("2006-01") + "-01"
		path = "/api/v1.2/qcuh_usages?start_date=" + month + "&end_date=" + month + "&group_by=month"
		header, prefix = "X-AUTH-TOKEN", ""
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "qcuh_usages", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "month") && metadataNumbers(v, "spot", "ondemand")
			})
		}
	case "paymongo-secret-key":
		if !strings.HasPrefix(c.Secret, "sk_live_") && !strings.HasPrefix(c.Secret, "sk_test_") {
			return unknownVerificationResult("credential_type", "verification requires a PayMongo secret key")
		}
		base = contextBase(p["endpoint"], "https://invoices-api.paymongo.com", "https://invoices-api.paymongo.com")
		path = "/v1/invoices/settings"
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			return !identityHasErrors(data) && contextBoolean(data["approvals_enabled"])
		}
	case "canny-api-key":
		base = contextBase(p["endpoint"], "https://canny.io/api/v1", "https://canny.io/api/v1")
		path = "/groups/list"
		valid = func(v identityPayload) bool {
			return contextBoolean(v["hasNextPage"]) && validIdentityCollection(v, "items", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "id", "name", "urlName")
			})
		}
	case "scrapingbee-api-key":
		base = contextBase(p["endpoint"], "https://app.scrapingbee.com/api/v1", "https://app.scrapingbee.com/api/v1")
		path = "/usage"
		valid = func(v identityPayload) bool {
			return identityNonnegativeIntegers(v, "max_api_credit", "used_api_credit", "max_concurrency", "current_concurrency")
		}
	default:
		return verifyScopedMetadataProvider(ctx, c)
	}
	if base == "" {
		return missingVerificationContext()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return missingVerificationContext()
	}
	req.Header.Set("Accept", "application/json")
	switch c.DetectorID {
	case "canny-api-key":
		body, _ := json.Marshal(map[string]any{"apiKey": c.Secret, "limit": 1})
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
	case "paymongo-secret-key":
		req.SetBasicAuth(c.Secret, "")
	default:
		req.Header.Set(header, prefix+c.Secret)
	}
	if c.DetectorID == "ngrok-token" {
		req.Header.Set("ngrok-version", "2")
	}
	if c.DetectorID == "flexport-api-key" {
		req.Header.Set("Flexport-Version", "2")
	}
	if c.DetectorID == "stitchdata-api-token" || c.DetectorID == "qubole-api-token" {
		req.Header.Set("Content-Type", "application/json")
	}
	if item != nil {
		return verifyInventoryArray(ctx, req, item)
	}
	return verifyIdentityRequest(ctx, req, valid)
}

func metadataNumbers(p identityPayload, fields ...string) bool {
	for _, field := range fields {
		var n *float64
		if json.Unmarshal(p[field], &n) != nil || n == nil || *n < 0 {
			return false
		}
	}
	return true
}
