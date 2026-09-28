package detectors

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

type contextualProvider struct {
	fields            map[string]string
	credentialPattern string
	assignments       []string
}

var contextualProviders = map[string]contextualProvider{
	"checkly-api-key":      {map[string]string{"checkly_account_id": "account_id", "checkly_api_url": "endpoint"}, `[A-Za-z0-9_-]{32,128}`, []string{"checkly_api_key"}},
	"saladcloud-api-key":   {map[string]string{"salad_organization_name": "organization", "salad_organization": "organization", "salad_api_url": "endpoint"}, "", nil},
	"scaleway-secret-key":  {map[string]string{"scw_access_key": "access_key", "scw_api_url": "endpoint"}, `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, []string{"scw_secret_key"}},
	"semaphore-api-token":  {map[string]string{"semaphore_organization": "organization", "semaphore_api_url": "endpoint"}, `[A-Za-z0-9_-]{32,128}`, []string{"semaphore_api_token", "semaphore_auth_token"}},
	"langsmith-api-key":    {map[string]string{"langsmith_workspace_id": "workspace_id", "langchain_workspace_id": "workspace_id", "langsmith_endpoint": "endpoint", "langchain_endpoint": "endpoint"}, "", nil},
	"crowdin-token":        {map[string]string{"crowdin_organization": "organization", "crowdin_base_url": "endpoint"}, `[A-Za-z0-9_-]{32,128}`, []string{"crowdin_personal_token", "crowdin_access_token"}},
	"growthbook-api-key":   {map[string]string{"growthbook_api_host": "endpoint", "growthbook_api_url": "endpoint"}, `[A-Za-z0-9._-]{32,256}`, []string{"growthbook_api_key", "growthbook_secret_key"}},
	"flagsmith-server-key": {map[string]string{"flagsmith_api_url": "endpoint"}, `[A-Za-z0-9._-]{32,256}`, []string{"flagsmith_environment_key", "flagsmith_server_key"}},
	"airbyte-api-token":    {map[string]string{"airbyte_api_url": "endpoint", "airbyte_credential_type": "credential_type"}, `[A-Za-z0-9._~/-]{32,256}`, []string{"airbyte_access_token", "airbyte_client_secret"}},
	"getresponse-api-key":  {map[string]string{"getresponse_api_url": "endpoint", "getresponse_domain": "domain"}, `[a-z0-9]{32}`, []string{"getresponse_api_key"}},
	"hightouch-api-key":    {map[string]string{"hightouch_api_url": "endpoint"}, `[A-Za-z0-9._-]{32,256}`, []string{"hightouch_api_key"}},
	"deno-deploy-token":    {map[string]string{"deno_api_url": "endpoint"}, "", nil},
	"ngrok-token":          {map[string]string{"ngrok_api_url": "endpoint", "ngrok_credential_type": "credential_type"}, `[A-Za-z0-9_]{20,256}`, []string{"ngrok_api_key", "ngrok_authtoken"}},
	"convertapi-secret":    {map[string]string{"convertapi_api_url": "endpoint", "convertapi_credential_type": "credential_type"}, `[A-Za-z0-9._-]{16,256}`, []string{"convertapi_master_token", "convertapi_api_token"}},
	"voicegain-api-key":    {map[string]string{"voicegain_api_url": "endpoint", "voicegain_sa_config_id": "config_id"}, `ey[A-Za-z0-9_-]{34}\.ey[A-Za-z0-9_-]{108}\.[A-Za-z0-9_-]{43}`, []string{"voicegain_jwt"}},
	"stitchdata-api-token": {map[string]string{"stitch_api_url": "endpoint", "stitch_client_id": "client_id"}, `[a-z0-9_]{35}`, []string{"stitch_api_token"}},
	"qubole-api-token":     {map[string]string{"qubole_api_url": "endpoint"}, `[a-z0-9]{64}`, []string{"qubole_api_token"}},
	"paymongo-secret-key":  {map[string]string{"paymongo_api_url": "endpoint"}, `sk_(?:live|test)_[A-Za-z0-9]{32,128}`, []string{"paymongo_secret_key"}},
	"canny-api-key":        {map[string]string{"canny_api_url": "endpoint"}, `[A-Za-z0-9]{32}`, []string{"canny_api_key"}},
	"scrapingbee-api-key":  {map[string]string{"scrapingbee_api_url": "endpoint"}, `[A-Za-z0-9]{80}`, []string{"scrapingbee_api_key"}},
}

var contextUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var contextSlug = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var contextDomain = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var contextAccessKey = regexp.MustCompile(`^SCW[A-Z0-9]{17}$`)

func missingVerificationContext() VerificationResult {
	return unknownVerificationResult("verification_context", "verification requires supported, unambiguous provider context")
}

// Endpoints are exact provider-owned bases. A discovered URL is context, not
// permission to send credentials to arbitrary or self-hosted infrastructure.
func contextBase(value, fallback string, allowed ...string) string {
	if value == "" {
		value = fallback
	}
	for _, base := range allowed {
		if value == base || value == base+"/" {
			return base
		}
	}
	return ""
}

func verifyContextualProvider(ctx context.Context, c Candidate) VerificationResult {
	p := c.SecretParts
	if p["context_conflict"] != "" {
		return missingVerificationContext()
	}
	for key, value := range p {
		if key != "credential" && value == "" {
			return missingVerificationContext()
		}
	}
	base, path, header, prefix := "", "", "Authorization", "Bearer "
	var valid func(identityPayload) bool
	var item func(identityPayload) bool
	switch c.DetectorID {
	case "checkly-api-key":
		if !contextUUID.MatchString(p["account_id"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://api.checklyhq.com", "https://api.checklyhq.com")
		path = "/next/accounts/" + p["account_id"]
		valid = func(v identityPayload) bool {
			return identityStringEquals(v, "id", p["account_id"]) && identityStrings(v, "name", "runtimeId")
		}
	case "saladcloud-api-key":
		org := p["organization"]
		if len(org) < 2 || !contextSlug.MatchString(org) || org[0] < 'a' || org[0] > 'z' {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://api.salad.com/api/public", "https://api.salad.com/api/public")
		path, header, prefix = "/organizations/"+org+"/gpu-classes", "Salad-Api-Key", ""
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "items", func(v identityPayload) bool { return !identityHasErrors(v) && identityStrings(v, "id", "name") })
		}
	case "scaleway-secret-key":
		if !contextAccessKey.MatchString(p["access_key"]) {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://api.scaleway.com", "https://api.scaleway.com")
		path, header, prefix = "/iam/v1alpha1/api-keys/"+p["access_key"], "X-Auth-Token", ""
		valid = func(v identityPayload) bool {
			return identityStringEquals(v, "access_key", p["access_key"]) && (identityStrings(v, "user_id") != identityStrings(v, "application_id"))
		}
	case "semaphore-api-token":
		if !contextSlug.MatchString(p["organization"]) {
			return missingVerificationContext()
		}
		base = "https://" + p["organization"] + ".semaphoreci.com"
		base = contextBase(p["endpoint"], base, base)
		path, prefix = "/api/v1alpha/agents?page_size=1", "Token "
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "agents", func(v identityPayload) bool {
				status, metadata := identityObject(v, "status"), identityObject(v, "metadata")
				return !identityHasErrors(v) && !identityHasErrors(status) && !identityHasErrors(metadata) && identityStrings(status, "state") && identityStrings(metadata, "name", "type")
			})
		}
	case "langsmith-api-key":
		if p["workspace_id"] != "" && !contextUUID.MatchString(p["workspace_id"]) {
			return missingVerificationContext()
		}
		if strings.HasPrefix(c.Secret, "lsv2_sk_") && p["workspace_id"] == "" {
			return missingVerificationContext()
		}
		base = contextBase(p["endpoint"], "https://api.smith.langchain.com", "https://api.smith.langchain.com", "https://eu.api.smith.langchain.com", "https://apac.api.smith.langchain.com", "https://aws.api.smith.langchain.com")
		path, header, prefix = "/api/v1/settings", "X-API-Key", ""
		valid = func(v identityPayload) bool {
			return identityStrings(v, "id", "display_name", "created_at") && (p["workspace_id"] == "" || identityStringEquals(v, "id", p["workspace_id"]))
		}
	case "crowdin-token":
		base = "https://api.crowdin.com/api/v2"
		if org := p["organization"]; org != "" {
			if !contextSlug.MatchString(org) {
				return missingVerificationContext()
			}
			base = "https://" + org + ".api.crowdin.com/api/v2"
		}
		base = contextBase(p["endpoint"], base, base)
		path = "/user"
		valid = func(v identityPayload) bool {
			data := identityObject(v, "data")
			return !identityHasErrors(data) && finalPositiveInteger(data["id"]) && identityStrings(data, "username")
		}
	case "growthbook-api-key":
		if !strings.HasPrefix(c.Secret, "secret_") {
			return unknownVerificationResult("credential_type", "verification requires a GrowthBook secret key")
		}
		base = contextBase(p["endpoint"], "", "https://api.growthbook.io/api")
		path = "/v1/projects?limit=1&offset=0"
		valid = func(v identityPayload) bool {
			return identityNonnegativeIntegers(v, "limit", "offset", "count", "total") && contextBoolean(v["hasMore"]) && validIdentityCollection(v, "projects", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "id", "name", "dateCreated", "dateUpdated")
			})
		}
	case "flagsmith-server-key":
		if !strings.HasPrefix(c.Secret, "ser.") {
			return unknownVerificationResult("credential_type", "verification requires a Flagsmith server environment key")
		}
		base = contextBase(p["endpoint"], "", "https://edge.api.flagsmith.com/api/v1", "https://api.flagsmith.com/api/v1")
		path, header, prefix = "/flags/", "X-Environment-Key", ""
		item = func(v identityPayload) bool {
			feature := identityObject(v, "feature")
			return !identityHasErrors(v) && !identityHasErrors(feature) && contextBoolean(v["enabled"]) && identityStrings(feature, "name")
		}
	case "airbyte-api-token":
		if p["credential_type"] != "bearer" {
			return unknownVerificationResult("credential_type", "verification requires explicit Airbyte bearer-token context")
		}
		base = contextBase(p["endpoint"], "", "https://api.airbyte.com/v1")
		path = "/workspaces?limit=1"
		valid = func(v identityPayload) bool {
			return validIdentityCollection(v, "data", func(v identityPayload) bool {
				return !identityHasErrors(v) && identityStrings(v, "workspaceId", "name", "dataResidency")
			})
		}
	case "getresponse-api-key":
		base = contextBase(p["endpoint"], "https://api.getresponse.com/v3", "https://api.getresponse.com/v3", "https://api3.getresponse360.pl/v3", "https://api3.getresponse360.com/v3")
		max := base != "" && base != "https://api.getresponse.com/v3"
		if (max && !contextDomain.MatchString(p["domain"])) || (!max && p["domain"] != "") {
			return missingVerificationContext()
		}
		path, header, prefix = "/accounts?fields=accountId,email", "X-Auth-Token", "api-key "
		valid = func(v identityPayload) bool {
			_, code := v["code"]
			_, status := v["httpStatus"]
			return !code && !status && identityStrings(v, "accountId", "email")
		}
	default:
		return verifyMetadataContextProvider(ctx, c)
	}
	if base == "" {
		return missingVerificationContext()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return missingVerificationContext()
	}
	req.Header.Set(header, prefix+c.Secret)
	req.Header.Set("Accept", "application/json")
	if c.DetectorID == "checkly-api-key" {
		req.Header.Set("X-Checkly-Account", p["account_id"])
	}
	if c.DetectorID == "langsmith-api-key" && p["workspace_id"] != "" {
		req.Header.Set("X-Tenant-Id", p["workspace_id"])
	}
	if c.DetectorID == "getresponse-api-key" && p["domain"] != "" {
		req.Header.Set("X-Domain", p["domain"])
	}
	if item != nil {
		return verifyInventoryArray(ctx, req, item)
	}
	return verifyIdentityRequest(ctx, req, valid)
}

// Keep standalone verifier entry points conservative: they have no record context.
func verifyContextlessProvider(ctx context.Context, id, secret string) VerificationResult {
	return verifyContextualProvider(ctx, Candidate{DetectorID: id, Secret: secret})
}
