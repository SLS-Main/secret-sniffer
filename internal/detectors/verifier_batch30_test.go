package detectors

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const batch30UUID = "12345678-1234-1234-1234-123456789abc"

var batch30Contracts = []struct {
	id, assignment, secret, context, endpoint, header, prefix string
	valid, invalid                                            []string
}{
	{"checkly-api-key", "CHECKLY_API_KEY", strings.Repeat("A", 40), "CHECKLY_ACCOUNT_ID=" + batch30UUID,
		"https://api.checklyhq.com/next/accounts/" + batch30UUID, "Authorization", "Bearer ",
		[]string{`{"id":"` + batch30UUID + `","name":"private-data","runtimeId":"2026.1","plan":null}`},
		[]string{`{"id":"other","name":"name","runtimeId":"runtime"}`, `{"id":"` + batch30UUID + `","name":"name","runtimeId":null}`}},
	{"saladcloud-api-key", "SALAD_API_KEY", "salad_cloud_demo_" + strings.Repeat("A", 40), "SALAD_ORGANIZATION_NAME=acme",
		"https://api.salad.com/api/public/organizations/acme/gpu-classes", "Salad-Api-Key", "",
		[]string{`{"items":[]}`, `{"items":[{"id":"id","name":"gpu","prices":[]}]}`},
		[]string{`{"items":null}`, `{"items":[{"id":1,"name":"gpu"}]}`, `{"items":[{"id":"id","name":"gpu","error":"denied"}]}`}},
	{"scaleway-secret-key", "SCW_SECRET_KEY", batch30UUID, "SCW_ACCESS_KEY=SCWABCDEFGHIJKLMNOPQ",
		"https://api.scaleway.com/iam/v1alpha1/api-keys/SCWABCDEFGHIJKLMNOPQ", "X-Auth-Token", "",
		[]string{`{"access_key":"SCWABCDEFGHIJKLMNOPQ","user_id":"user","application_id":null,"secret_key":null}`, `{"access_key":"SCWABCDEFGHIJKLMNOPQ","application_id":"app","secret_key":"private-data"}`},
		[]string{`{"access_key":"other","user_id":"user"}`, `{"access_key":"SCWABCDEFGHIJKLMNOPQ"}`, `{"access_key":"SCWABCDEFGHIJKLMNOPQ","user_id":"user","application_id":"app"}`}},
	{"semaphore-api-token", "SEMAPHORE_API_TOKEN", strings.Repeat("A", 40), "SEMAPHORE_ORGANIZATION=acme",
		"https://acme.semaphoreci.com/api/v1alpha/agents?page_size=1", "Authorization", "Token ",
		[]string{`{"agents":[],"cursor":""}`, `{"agents":[{"status":{"state":"offline"},"metadata":{"name":"agent","type":"s1","ip_address":"private-data"}}],"cursor":"next"}`},
		[]string{`{"agents":null}`, `{"agents":[{"status":{"state":"offline"},"metadata":{}}]}`, `{"agents":[{"status":{"state":"offline","error":"denied"},"metadata":{"name":"agent","type":"s1"}}]}`}},
	{"langsmith-api-key", "LANGSMITH_API_KEY", "lsv2_sk_" + strings.Repeat("a", 32) + "_" + strings.Repeat("b", 10), "LANGSMITH_WORKSPACE_ID=" + batch30UUID + "\nLANGSMITH_ENDPOINT=https://eu.api.smith.langchain.com",
		"https://eu.api.smith.langchain.com/api/v1/settings", "X-API-Key", "",
		[]string{`{"id":"` + batch30UUID + `","display_name":"workspace","created_at":"2026-09-28T00:00:00Z","tenant_handle":null}`},
		[]string{`{"id":"other","display_name":"workspace","created_at":"date"}`, `{"id":"` + batch30UUID + `","display_name":null,"created_at":"date"}`}},
	{"crowdin-token", "CROWDIN_PERSONAL_TOKEN", strings.Repeat("A", 40), "CROWDIN_ORGANIZATION=acme",
		"https://acme.api.crowdin.com/api/v2/user", "Authorization", "Bearer ",
		[]string{`{"data":{"id":1,"username":"private-data","email":null}}`},
		[]string{`{"data":{"id":"1","username":"name"}}`, `{"data":{"id":1,"username":"name","error":"denied"}}`}},
	{"growthbook-api-key", "GROWTHBOOK_SECRET_KEY", "secret_" + strings.Repeat("A", 40), "GROWTHBOOK_API_HOST=https://api.growthbook.io/api",
		"https://api.growthbook.io/api/v1/projects?limit=1&offset=0", "Authorization", "Bearer ",
		[]string{`{"projects":[],"limit":1,"offset":0,"count":0,"total":0,"hasMore":false,"nextOffset":null}`, `{"projects":[{"id":"id","name":"private-data","dateCreated":"date","dateUpdated":"date"}],"limit":1,"offset":0,"count":1,"total":4,"hasMore":true,"nextOffset":1}`},
		[]string{`{"projects":[]}`, `{"projects":null,"limit":1,"offset":0,"count":0,"total":0,"hasMore":false}`, `{"projects":[],"limit":1,"offset":0,"count":0,"total":0,"hasMore":"false"}`}},
	{"flagsmith-server-key", "FLAGSMITH_SERVER_KEY", "ser." + strings.Repeat("A", 40), "FLAGSMITH_API_URL=https://edge.api.flagsmith.com/api/v1/",
		"https://edge.api.flagsmith.com/api/v1/flags/", "X-Environment-Key", "",
		[]string{`[]`, `[{"enabled":false,"feature":{"name":"private-data"},"feature_state_value":null}]`},
		[]string{`[{}]`, `[{"enabled":"false","feature":{"name":"flag"}}]`, `[{"enabled":true,"feature":{"name":"flag","error":"denied"}}]`}},
	{"airbyte-api-token", "AIRBYTE_ACCESS_TOKEN", strings.Repeat("A", 40), "AIRBYTE_API_URL=https://api.airbyte.com/v1",
		"https://api.airbyte.com/v1/workspaces?limit=1", "Authorization", "Bearer ",
		[]string{`{"data":[]}`, `{"data":[{"workspaceId":"id","name":"private-data","dataResidency":"us"}],"next":"https://other.invalid"}`},
		[]string{`{"data":null}`, `{"data":[{"workspaceId":1,"name":"name","dataResidency":"us"}]}`, `{"data":[{"workspaceId":"id","name":"name","dataResidency":"us","error":"denied"}]}`}},
	{"getresponse-api-key", "GETRESPONSE_API_KEY", strings.Repeat("a", 32), "GETRESPONSE_API_URL=https://api3.getresponse360.pl/v3\nGETRESPONSE_DOMAIN=tenant.example",
		"https://api3.getresponse360.pl/v3/accounts?fields=accountId,email", "X-Auth-Token", "api-key ",
		[]string{`{"accountId":"id","email":"private-data"}`},
		[]string{`{"accountId":1,"email":"mail"}`, `{"accountId":"id","email":"mail","code":1014}`, `{"accountId":"id","email":"mail","httpStatus":401}`}},
}

func batch30Registry() map[string]Detector {
	registry := map[string]Detector{}
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	return registry
}

func batch30Candidate(t *testing.T, d Detector, input string) Candidate {
	t.Helper()
	c := d.Detect([]byte(input))
	if len(c) != 1 {
		t.Fatalf("%s: candidates=%+v", d.Info().ID, c)
	}
	return c[0]
}

func TestThirtiethBatchContracts(t *testing.T) {
	registry := batch30Registry()
	if len(batch30Contracts) != 10 {
		t.Fatal("expected ten providers")
	}
	for _, tc := range batch30Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			c := batch30Candidate(t, d, tc.assignment+"="+tc.secret+"\n"+tc.context)
			if c.Secret != tc.secret || c.VerificationSafety != VerificationSafetyReadOnly {
				t.Fatalf("%+v", c)
			}
			bodies := append(append([]string{}, tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-data"}`)
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.Method != "GET" || req.URL.String() != tc.endpoint || req.Header.Get(tc.header) != tc.prefix+tc.secret || req.Header.Get("Accept") != "application/json" || req.Body != nil {
							t.Fatalf("unexpected %s %s %v", req.Method, req.URL, req.Header)
						}
						if tc.id == "checkly-api-key" && req.Header.Get("X-Checkly-Account") != batch30UUID {
							t.Fatal("missing account header")
						}
						if tc.id == "langsmith-api-key" && req.Header.Get("X-Tenant-Id") != batch30UUID {
							t.Fatal("missing tenant header")
						}
						if tc.id == "getresponse-api-key" && req.Header.Get("X-Domain") != "tenant.example" {
							t.Fatal("missing MAX domain")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if r.Status != want || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-data") {
						t.Fatalf("status=%d body=%s result=%+v calls=%d", status, body, r, calls)
					}
				}
			}
		})
	}
}

func TestThirtiethBatchContextIsolation(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch30Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			key := tc.assignment + "=" + tc.secret
			forward := batch30Candidate(t, d, key+"\n"+tc.context)
			reverse := batch30Candidate(t, d, tc.context+"\n"+key)
			if forward.VerificationCacheKey() != reverse.VerificationCacheKey() {
				t.Fatal("field order changes context")
			}
			ini := batch30Candidate(t, d, "[provider]\n"+key+"\n"+tc.context)
			if ini.VerificationCacheKey() != forward.VerificationCacheKey() {
				t.Fatalf("INI context mismatch: %v", ini.SecretParts)
			}
			// Isolate valid JSON sibling mappings even on the same line.
			fields := map[string]string{tc.assignment: tc.secret}
			contextFields := map[string]string{}
			for _, line := range strings.Split(tc.context, "\n") {
				k, v, _ := strings.Cut(line, "=")
				fields[k] = v
				contextFields[k] = v
			}
			encoded, _ := json.Marshal(fields)
			structured := batch30Candidate(t, d, string(encoded))
			if structured.VerificationCacheKey() != forward.VerificationCacheKey() {
				t.Fatalf("structured context=%v env=%v", structured.SecretParts, forward.SecretParts)
			}
			credentialOnly, _ := json.Marshal(map[string]string{tc.assignment: tc.secret})
			other, _ := json.Marshal(contextFields)
			separate := batch30Candidate(t, d, `[`+string(credentialOnly)+`,`+string(other)+`]`)
			for part := range forward.SecretParts {
				if part != "credential" && part != "credential_type" && separate.SecretParts[part] != "" {
					t.Fatalf("sibling context leak: %v", separate.SecretParts)
				}
			}
			for _, boundary := range []string{"\n\n", "\n---\n", "\n[another]\n", "\n" + strings.Repeat("#", 600) + "\n"} {
				separate := batch30Candidate(t, d, key+boundary+tc.context)
				for part := range forward.SecretParts {
					if part != "credential" && part != "credential_type" && separate.SecretParts[part] != "" {
						t.Fatalf("boundary context leak: %v", separate.SecretParts)
					}
				}
			}
			// A same-field conflict cannot choose a tenant or endpoint arbitrarily.
			first := strings.Split(tc.context, "\n")[0]
			name, _, _ := strings.Cut(first, "=")
			conflict := batch30Candidate(t, d, key+"\n"+tc.context+"\n"+name+"=other")
			if conflict.SecretParts["context_conflict"] != "true" {
				t.Fatalf("conflict lost: %v", conflict.SecretParts)
			}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("conflicting context sent"); return nil, nil })}
			if r := conflict.Verify(WithVerificationHTTPClient(context.Background(), client)); r.Status != VerificationUnknown {
				t.Fatalf("%+v", r)
			}
			if forward.VerificationCacheKey() == conflict.VerificationCacheKey() {
				t.Fatal("context omitted from cache key")
			}
			if got := d.Detect([]byte(key + "+suffix")); len(got) != 0 {
				t.Fatalf("truncated credential: %+v", got)
			}
		})
	}
}

func TestThirtiethBatchMissingAndUnsupportedContext(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unsupported context sent"); return nil, nil })}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch30Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.context)
		for _, endpoint := range []string{"https://evil.invalid", "https://api.checklyhq.com.evil.invalid", "http://api.checklyhq.com", "https://user@api.checklyhq.com", "https://api.checklyhq.com:443", "https://api.checklyhq.com?x=1", "https://api.checklyhq.com/#fragment", ""} {
			parts := cloneStringMap(c.SecretParts)
			parts["endpoint"] = endpoint
			c.SecretParts = parts
			if r := c.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
		if tc.id != "crowdin-token" && tc.id != "getresponse-api-key" {
			c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret)
			if r := c.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
	}
	for _, id := range []string{"flagsmith-server-key", "growthbook-api-key"} {
		c := Candidate{DetectorID: id, Secret: strings.Repeat("A", 40)}
		if r := verifyContextualProvider(ctx, c); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("%+v", r)
		}
	}
	for _, field := range []string{"AIRBYTE_CLIENT_SECRET", "client_secret"} {
		input := "airbyte\n" + field + "=" + strings.Repeat("A", 40) + "\nAIRBYTE_API_URL=https://api.airbyte.com/v1\nAIRBYTE_CREDENTIAL_TYPE=bearer"
		c := batch30Candidate(t, registry["airbyte-api-token"], input)
		if r := c.Verify(ctx); r.Status != VerificationUnknown {
			t.Fatalf("client secret sent: %+v", r)
		}
	}
}

func TestThirtiethBatchTransportAndCap(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch30Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.context)
		for _, mode := range []string{"network", "read", "oversize", "cancelled"} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "network" {
					return nil, errors.New("private-data")
				}
				if mode == "cancelled" {
					return nil, context.Canceled
				}
				if mode == "read" {
					return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.valid[0] + strings.Repeat(" ", maxVerificationResponseBytes)))}, nil
			})}
			r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
			if r.Status != VerificationUnknown || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-data") {
				t.Fatalf("%s %s: %+v calls=%d", tc.id, mode, r, calls)
			}
		}
	}
}

func TestThirtiethBatchAmbiguousRecords(t *testing.T) {
	d := batch30Registry()["checkly-api-key"]
	input := "CHECKLY_API_KEY=" + strings.Repeat("A", 40) + "\nCHECKLY_ACCOUNT_ID=" + batch30UUID + "\nCHECKLY_API_KEY=" + strings.Repeat("B", 40)
	candidates := d.Detect([]byte(input))
	if len(candidates) != 2 {
		t.Fatalf("%+v", candidates)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("ambiguous record sent"); return nil, nil })}
	for _, c := range candidates {
		if r := c.Verify(WithVerificationHTTPClient(context.Background(), client)); r.Status != VerificationUnknown || c.SecretParts["context_conflict"] != "true" {
			t.Fatalf("%+v parts=%v", r, c.SecretParts)
		}
	}
	// A failed JSON parse must not drop an explicit self-hosted endpoint and
	// silently use the provider's default cloud deployment.
	d = batch30Registry()["crowdin-token"]
	c := batch30Candidate(t, d, `{"CROWDIN_PERSONAL_TOKEN":"`+strings.Repeat("A", 40)+`","CROWDIN_BASE_URL":"https://selfhost.invalid",}`)
	if r := c.Verify(WithVerificationHTTPClient(context.Background(), client)); r.Status != VerificationUnknown {
		t.Fatalf("%+v", r)
	}
	d = batch30Registry()["getresponse-api-key"]
	for _, endpoint := range []string{`https://api.getresponse.com/v3#fragment`, `"https://api.getresponse.com/v3" + suffix`, `"https://api.getresponse.com/v3"#fragment`, `https://api.getresponse.com/v3,other`} {
		c := batch30Candidate(t, d, "GETRESPONSE_API_KEY="+strings.Repeat("a", 32)+"\nGETRESPONSE_API_URL="+endpoint)
		if r := c.Verify(WithVerificationHTTPClient(context.Background(), client)); r.Status != VerificationUnknown {
			t.Fatalf("%s: %+v", endpoint, r)
		}
	}
}
