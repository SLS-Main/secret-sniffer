package detectors

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

var batch31Contracts = []struct {
	id, assignment, secret, fields, endpoint, header, prefix string
	valid, invalid                                           []string
}{
	{"hightouch-api-key", "HIGHTOUCH_API_KEY", strings.Repeat("A", 40), "", "https://api.hightouch.com/api/v1/events/domains?limit=1&offset=0", "Authorization", "Bearer ",
		[]string{`{"data":[]}`, `{"data":[{"id":"id","name":"domain","workspaceId":42,"description":"private-data"}]}`},
		[]string{`{"data":null}`, `{"data":[{"id":"id","name":"domain","workspaceId":"42"}]}`, `{"data":[{"id":"id","name":"domain","workspaceId":42,"error":"denied"}]}`}},
	{"deno-deploy-token", "DENO_DEPLOY_TOKEN", "ddo_" + strings.Repeat("A", 36), "", "https://api.deno.com/v2/domains?limit=1", "Authorization", "Bearer ",
		[]string{`[]`, `[{"id":"id","organization_id":"org","domain":"example.test","is_validated":false,"verification_token":"private-data","certificates":[]}]`},
		[]string{`[{}]`, `[{"id":"id","organization_id":"org","domain":"example.test","is_validated":"false"}]`, `[{"id":"id","organization_id":"org","domain":"example.test","is_validated":true,"error":"denied"}]`}},
	{"ngrok-token", "NGROK_API_KEY", strings.Repeat("A", 40), "", "https://api.ngrok.com/agent_ingresses?limit=1", "Authorization", "Bearer ",
		[]string{`{"ingresses":[],"uri":"/agent_ingresses","next_page_uri":null}`, `{"ingresses":[{"id":"id","domain":"example.test","created_at":"date","metadata":"private-data"}],"uri":"/agent_ingresses","next_page_uri":"https://other.invalid"}`},
		[]string{`{"ingresses":[]}`, `{"ingresses":null,"uri":"/agent_ingresses"}`, `{"ingresses":[{"id":"id","domain":"example.test","created_at":"date","error":"denied"}],"uri":"/agent_ingresses"}`}},
	{"convertapi-secret", "CONVERTAPI_MASTER_TOKEN", strings.Repeat("A", 40), "", "https://v2.convertapi.com/user", "Authorization", "Bearer ",
		[]string{`{"Active":false,"Email":"private-data","ConversionsTotal":0,"ConversionsConsumed":0}`, `{"Active":true,"Email":"mail","FullName":null,"ConversionsTotal":100,"ConversionsConsumed":120}`},
		[]string{`{"Id":"id"}`, `{"Active":null,"Email":"mail","ConversionsTotal":0,"ConversionsConsumed":0}`, `{"Active":true,"Email":"mail","ConversionsTotal":"100","ConversionsConsumed":0}`}},
	{"voicegain-api-key", "VOICEGAIN_JWT", "ey" + strings.Repeat("A", 34) + ".ey" + strings.Repeat("B", 108) + "." + strings.Repeat("C", 43), "VOICEGAIN_API_URL=https://api.voicegain.ai/v1\nVOICEGAIN_SA_CONFIG_ID=" + batch30UUID,
		"https://api.voicegain.ai/v1/sa/config/" + batch30UUID, "Authorization", "Bearer ",
		[]string{`{"saConfId":"` + batch30UUID + `","name":"cfg","builtIn":false,"llmSummaryPrompt":"private-data"}`, `{"saConfId":"` + batch30UUID + `","name":"cfg","builtIn":true,"published":false}`},
		[]string{`{}`, `{"saConfId":"other","name":"cfg","builtIn":false}`, `{"saConfId":"` + batch30UUID + `","name":"cfg","builtIn":"false"}`}},
	{"stitchdata-api-token", "STITCH_API_TOKEN", "ac_" + strings.Repeat("a", 32), "STITCH_API_URL=https://api.stitchdata.com\nSTITCH_CLIENT_ID=123",
		"https://api.stitchdata.com/v4/123/extractions?page=1", "Authorization", "Bearer ",
		[]string{`{"data":[],"page":1,"total":0,"links":{}}`, `{"data":[{"stitch_client_id":123,"source_id":42,"job_name":"job","tap_exit_status":1,"tap_description":"private-data"}],"page":1,"total":101,"links":{"next":"https://other.invalid"}}`},
		[]string{`{"data":[],"page":"1","total":0}`, `{"data":null,"page":1,"total":0}`, `{"data":[{"stitch_client_id":321,"source_id":42,"job_name":"job"}],"page":1,"total":1}`, `{"data":[{"stitch_client_id":123,"source_id":42,"job_name":"job","error":"denied"}],"page":1,"total":1}`}},
	{"qubole-api-token", "QUBOLE_API_TOKEN", strings.Repeat("a", 64), "QUBOLE_API_URL=https://eu.qubole.com", "https://eu.qubole.com/api/v1.2/qcuh_usages", "X-AUTH-TOKEN", "",
		[]string{`{"qcuh_usages":[]}`, `{"qcuh_usages":[{"month":"2026-09-01 00:00:00","spot":0,"ondemand":42.25}],"last_updated_qcuh":"date"}`},
		[]string{`{"qcuh_usages":null}`, `{"qcuh_usages":[{"month":"date","spot":"0","ondemand":0}]}`, `{"qcuh_usages":[{"month":"date","spot":null,"ondemand":0}]}`, `{"qcuh_usages":[{"month":"date","spot":-1,"ondemand":0}]}`}},
	{"paymongo-secret-key", "PAYMONGO_SECRET_KEY", "sk_test_" + strings.Repeat("A", 40), "", "https://invoices-api.paymongo.com/v1/invoices/settings", "", "",
		[]string{`{"data":{"approvals_enabled":false}}`, `{"data":{"approvals_enabled":true}}`},
		[]string{`{"data":{}}`, `{"data":{"approvals_enabled":null}}`, `{"data":{"approvals_enabled":false,"error":"denied"}}`, `{"data":[{"approvals_enabled":true}]}`}},
	{"canny-api-key", "CANNY_API_KEY", strings.Repeat("A", 32), "", "https://canny.io/api/v1/groups/list", "", "",
		[]string{`{"items":[],"hasNextPage":false,"cursor":null}`, `{"items":[{"id":"id","name":"group","urlName":"group","description":"private-data"}],"hasNextPage":true,"cursor":"next"}`},
		[]string{`{"boards":[]}`, `{"items":null,"hasNextPage":false}`, `{"items":[],"hasNextPage":"false"}`, `{"items":[{"id":"id","name":"group","urlName":"group","error":"denied"}],"hasNextPage":true}`}},
	{"scrapingbee-api-key", "SCRAPINGBEE_API_KEY", strings.Repeat("A", 80), "", "https://app.scrapingbee.com/api/v1/usage", "Authorization", "Bearer ",
		[]string{`{"max_api_credit":0,"used_api_credit":0,"max_concurrency":0,"current_concurrency":0}`, `{"max_api_credit":100,"used_api_credit":100,"max_concurrency":10,"current_concurrency":0,"renewal_subscription_date":null}`},
		[]string{`{"max_api_credit":100}`, `{"max_api_credit":"100","used_api_credit":0,"max_concurrency":10,"current_concurrency":0}`, `{"max_api_credit":100,"used_api_credit":null,"max_concurrency":10,"current_concurrency":0}`}},
}

func TestThirtyFirstBatchContracts(t *testing.T) {
	registry := batch30Registry()
	if len(batch31Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for _, tc := range batch31Contracts {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
			if c.VerificationSafety != VerificationSafetyReadOnly || c.Secret != tc.secret {
				t.Fatalf("%+v", c)
			}
			bodies := append(append([]string{}, tc.valid...), tc.invalid...)
			bodies = append(bodies, `null`, `"ok"`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-data"}`)
			// A structured provider error never overrides itself with success data.
			for _, field := range []string{"error", "error_code", "errors"} {
				var obj identityPayload
				var array []identityPayload
				body := tc.valid[len(tc.valid)-1]
				if tc.id == "deno-deploy-token" {
					_ = json.Unmarshal([]byte(body), &array)
					obj = array[0]
				} else {
					_ = json.Unmarshal([]byte(body), &obj)
				}
				obj[field] = json.RawMessage(`"private-data"`)
				var raw []byte
				if array != nil {
					raw, _ = json.Marshal(array)
				} else {
					raw, _ = json.Marshal(obj)
				}
				bodies = append(bodies, string(raw))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						endpoint := tc.endpoint
						method := http.MethodGet
						if tc.id == "qubole-api-token" {
							month := time.Now().UTC().Format("2006-01") + "-01"
							endpoint += "?start_date=" + month + "&end_date=" + month + "&group_by=month"
						}
						if tc.id == "canny-api-key" {
							method = http.MethodPost
						}
						if req.URL.String() != endpoint || req.Method != method || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
						}
						if tc.header != "" && req.Header.Get(tc.header) != tc.prefix+tc.secret {
							t.Fatal("wrong authentication")
						}
						if tc.id == "ngrok-token" && req.Header.Get("ngrok-version") != "2" {
							t.Fatal("missing API version")
						}
						if tc.id == "paymongo-secret-key" {
							user, pass, ok := req.BasicAuth()
							if !ok || user != tc.secret || pass != "" {
								t.Fatal("wrong Basic authentication")
							}
						}
						if tc.id == "canny-api-key" {
							var payload map[string]any
							if req.Header.Get("Authorization") != "" || req.Header.Get("Content-Type") != "application/json" || json.NewDecoder(req.Body).Decode(&payload) != nil || len(payload) != 2 || payload["apiKey"] != tc.secret || payload["limit"] != float64(1) {
								t.Fatal("wrong read-only POST body")
							}
						} else if req.Body != nil {
							t.Fatal("unexpected GET body")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}, "Link": []string{"<https://other.invalid>; rel=next"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if calls != 1 || r.Status != want || r.Response != "" || strings.Contains(r.Message, "private-data") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestThirtyFirstBatchContextAndFamilies(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unsupported context sent"); return nil, nil })}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch31Contracts {
		input := tc.assignment + "=" + tc.secret + "\n" + tc.fields
		c := batch30Candidate(t, registry[tc.id], input)
		for _, base := range []string{"https://evil.invalid", "http://api.voicegain.ai/v1", "https://api.stitchdata.com.evil.invalid", "https://api.ngrok.com:443", "https://api.ngrok.com?token=secret", "https://user@api.ngrok.com", ""} {
			parts := cloneStringMap(c.SecretParts)
			if parts == nil {
				parts = map[string]string{}
			}
			parts["endpoint"] = base
			altered := c
			altered.SecretParts = parts
			if r := altered.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
		if got := registry[tc.id].Detect([]byte(tc.assignment + "=" + tc.secret + "+suffix")); len(got) != 0 {
			t.Fatalf("%s truncated credential", tc.id)
		}
	}
	for _, tc := range []struct{ id, input string }{
		{"ngrok-token", "NGROK_AUTHTOKEN=" + strings.Repeat("A", 40)},
		{"ngrok-token", "ngrok_pat_" + strings.Repeat("a", 30)},
		{"ngrok-token", "NGROK_AUTHTOKEN=" + strings.Repeat("A", 40) + "\nNGROK_CREDENTIAL_TYPE=api"},
		{"convertapi-secret", "convertapi secret=secret_" + strings.Repeat("a", 16)},
		{"convertapi-secret", "CONVERTAPI_API_TOKEN=" + strings.Repeat("A", 40)},
		{"convertapi-secret", "CONVERTAPI_API_TOKEN=" + strings.Repeat("A", 40) + "\nCONVERTAPI_CREDENTIAL_TYPE=master"},
		{"deno-deploy-token", "ddp_" + strings.Repeat("A", 36)},
		{"deno-deploy-token", "ddw_" + strings.Repeat("A", 36)},
		{"stitchdata-api-token", "STITCH_API_TOKEN=ep_" + strings.Repeat("a", 32) + "\nSTITCH_API_URL=https://api.stitchdata.com\nSTITCH_CLIENT_ID=123"},
		{"stitchdata-api-token", "STITCH_API_TOKEN=ac_" + strings.Repeat("a", 32)},
		{"voicegain-api-key", "VOICEGAIN_JWT=" + batch31Contracts[4].secret},
		{"voicegain-api-key", "VOICEGAIN_JWT=" + batch31Contracts[4].secret + "\nVOICEGAIN_SA_CONFIG_ID=" + batch30UUID + "\nVOICEGAIN_API_URL=https://edge.invalid/v1"},
		{"qubole-api-token", "QUBOLE_API_TOKEN=" + strings.Repeat("a", 64)},
	} {
		c := batch30Candidate(t, registry[tc.id], tc.input)
		if r := c.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
			t.Fatalf("%s: %+v", tc.id, r)
		}
	}
}

func TestThirtyFirstBatchRecordIsolation(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch31Contracts {
		if tc.fields == "" {
			continue
		}
		d := registry[tc.id]
		key := tc.assignment + "=" + tc.secret
		c := batch30Candidate(t, d, key+"\n"+tc.fields)
		reverse := batch30Candidate(t, d, tc.fields+"\n"+key)
		if c.VerificationCacheKey() != reverse.VerificationCacheKey() {
			t.Fatal("order changed identity")
		}
		contextFields := map[string]string{}
		for _, line := range strings.Split(tc.fields, "\n") {
			name, value, _ := strings.Cut(line, "=")
			contextFields[name] = value
		}
		full := cloneStringMap(contextFields)
		full[tc.assignment] = tc.secret
		data, _ := json.Marshal(full)
		structured := batch30Candidate(t, d, string(data))
		if structured.VerificationCacheKey() != c.VerificationCacheKey() {
			t.Fatalf("%s structured=%v env=%v", tc.id, structured.SecretParts, c.SecretParts)
		}
		other, _ := json.Marshal(contextFields)
		primary, _ := json.Marshal(map[string]string{tc.assignment: tc.secret})
		for _, input := range []string{`[` + string(primary) + `,` + string(other) + `]`, key + "\n\n" + tc.fields, key + "\n---\n" + tc.fields} {
			separate := batch30Candidate(t, d, input)
			if len(separate.SecretParts) != 0 {
				t.Fatalf("%s borrowed context: %v", tc.id, separate.SecretParts)
			}
		}
	}
}

func TestThirtyFirstBatchFailuresAndCaps(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch31Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
		for _, mode := range []string{"network", "read", "oversize", "cancel", "timeout"} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "network":
					return nil, errors.New("private-data")
				case "read":
					return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
				case "cancel":
					return nil, context.Canceled
				case "timeout":
					return nil, context.DeadlineExceeded
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

func TestThirtyFirstBatchStructuredCredentialKinds(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range []struct{ id, label, selector, kind, incompatible string }{
		{"ngrok-token", "NGROK_API_KEY", "NGROK_CREDENTIAL_TYPE", "api", "agent"},
		{"convertapi-secret", "CONVERTAPI_MASTER_TOKEN", "CONVERTAPI_CREDENTIAL_TYPE", "master", "api"},
	} {
		secret := strings.Repeat("A", 40)
		for _, input := range []string{
			`{"` + tc.label + `":"` + secret + `"}`,
			tc.label + ": '" + secret + "'\n",
		} {
			c := batch30Candidate(t, registry[tc.id], input)
			if c.SecretParts["credential_type"] != tc.kind {
				t.Fatalf("%s lost inferred type: %v", tc.id, c.SecretParts)
			}
		}
		input := `{"` + tc.label + `":"` + secret + `","` + tc.selector + `":"` + tc.incompatible + `"}`
		c := batch30Candidate(t, registry[tc.id], input)
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("conflicting structured type sent a request")
			return nil, nil
		})}
		if c.SecretParts["context_conflict"] != "true" || c.Verify(WithVerificationHTTPClient(context.Background(), client)).Status != VerificationUnknown {
			t.Fatalf("%s accepted contradictory credential types", tc.id)
		}
	}
}

func TestThirtyFirstBatchQuboleDeployments(t *testing.T) {
	for _, host := range []string{"api.qubole.com", "in.qubole.com", "eu.qubole.com", "us.qubole.com", "gcp.qubole.com"} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Host != host || req.URL.Path != "/api/v1.2/qcuh_usages" {
				t.Fatal("wrong deployment")
			}
			return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"error":"role or deployment"}`))}, nil
		})}
		c := Candidate{DetectorID: "qubole-api-token", Secret: "secret", SecretParts: map[string]string{"endpoint": "https://" + host}}
		r := verifyContextualProvider(WithVerificationHTTPClient(context.Background(), client), c)
		if r.Status != VerificationUnknown || calls != 1 || r.Response != "" {
			t.Fatalf("%+v calls=%d", r, calls)
		}
	}
}
