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

var batch28Contracts = []struct {
	id                              string
	verify                          Verifier
	secret, endpoint, header, value string
	valid, invalid                  []string
	regions                         []string
}{
	{"grafana-token", verifyGrafanaCloud, "secret", "https://www.grafana.com/api/v1/tokens?region=us&pageSize=1", "Authorization", "Bearer secret",
		[]string{`{"items":[]}`, `{"items":[{"id":"id","accessPolicyId":"policy","name":"private-metadata"}],"metadata":{"pagination":{"nextPage":"https://other.invalid"}}}`},
		[]string{`{}`, `{"items":null}`, `{"items":[{}]}`, `{"items":[{"id":"id","accessPolicyId":"policy","name":"name","error":"denied"}]}`, `{"message":"required scope accesspolicies:read"}`},
		[]string{"https://www.grafana.com/api/v1/tokens?region=us&pageSize=1", "https://www.grafana.com/api/v1/tokens?region=eu&pageSize=1", "https://www.grafana.com/api/v1/tokens?region=au&pageSize=1"}},
	{"fal-ai-api-key", verifyFalAI, "secret", "https://api.fal.ai/v1/account/billing", "Authorization", "Key secret",
		[]string{`{"username":"private-metadata"}`, `{"username":"account","credits":null}`},
		[]string{`{}`, `{"username":null}`, `{"username":1}`, `{"username":" "}`, `{"username":"account","error":{"type":"authorization_error"}}`}, nil},
	{"salesforce-access-token", verifySalesforce, "secret", "https://login.salesforce.com/services/oauth2/userinfo", "Authorization", "Bearer secret",
		[]string{`{"sub":"subject","user_id":"user","organization_id":"org","active":false,"email":null}`},
		[]string{`{}`, `{"sub":"subject","user_id":"user"}`, `{"sub":1,"user_id":"user","organization_id":"org"}`, `Bad_OAuth_Token`},
		[]string{"https://login.salesforce.com/services/oauth2/userinfo", "https://test.salesforce.com/services/oauth2/userinfo"}},
	{"apisports-api-key", verifyAPISports, "secret", "https://v3.football.api-sports.io/status", "x-apisports-key", "secret",
		[]string{`{"get":"status","results":1,"errors":[],"response":{"account":{"email":"private-metadata"},"subscription":{"plan":"Free","active":false},"requests":{"current":0,"limit_day":0}}}`, `{"get":"status","results":1,"errors":{},"response":{"account":{"email":"mail"},"subscription":{"plan":"Free","active":"true"},"requests":{"current":100,"limit_day":100}}}`, `{"get":"status","results":1,"errors":[],"response":{"account":{"email":"mail"},"subscription":{"plan":"Free"},"requests":{"current":0,"limit_day":0}}}`},
		[]string{`{"results":1,"errors":[]}`, `{"get":"status","results":1,"errors":{"token":"Invalid token"},"response":[]}`, `{"get":"status","results":1,"errors":[],"response":{"account":{"email":"mail"},"subscription":{"plan":null,"active":false},"requests":{"current":0,"limit_day":0}}}`, `{"get":"status","results":1,"errors":[],"response":{"account":{"email":"mail"},"subscription":{"plan":"Free","active":false},"requests":{"current":"0","limit_day":0}}}`}, nil},
	{"trayio-api-token", verifyTrayIO, "secret", "https://api.tray.io/core/v1/workspaces?first=1", "Authorization", "Bearer secret",
		[]string{`{"elements":[],"pageInfo":{"hasNextPage":false,"hasPreviousPage":false}}`, `{"pageInfo":{"hasNextPage":false,"hasPreviousPage":false}}`, `{"elements":[{"id":"id","name":"private-metadata","type":"PERSONAL"}],"pageInfo":{"hasNextPage":true,"hasPreviousPage":false,"endCursor":"https://other.invalid"}}`},
		[]string{`{"elements":[]}`, `{"elements":null,"pageInfo":{"hasNextPage":false,"hasPreviousPage":false}}`, `{"elements":[{}],"pageInfo":{"hasNextPage":false,"hasPreviousPage":false}}`, `{"pageInfo":{"hasNextPage":null,"hasPreviousPage":false}}`},
		[]string{"https://api.tray.io/core/v1/workspaces?first=1", "https://api.eu1.tray.io/core/v1/workspaces?first=1", "https://api.ap1.tray.io/core/v1/workspaces?first=1"}},
	{"vagrant-cloud-token", verifyVagrantCloud, "secret", "https://vagrantcloud.com/api/v2/authenticate", "Authorization", "Bearer secret",
		[]string{`{"user":{"username":"private-metadata"}}`}, []string{`{}`, `[]`, `{"user":{"username":null}}`, `{"user":{"username":"name","error":"denied"}}`, `{"code":16,"message":"authentication is required","errors":["authentication is required"]}`, `{"message":"migrate to HCP"}`}, nil},
	{"percy-token", verifyPercy, "secret", "https://percy.io/api/v1/projects", "Authorization", "Token token=secret",
		[]string{`{"data":{"type":"projects","id":"id","attributes":{"name":"private-metadata","slug":"project","full-slug":"org/project","publicly-readable":false,"is-enabled":false}},"links":{"next":"https://other.invalid"}}`, `{"data":{"type":"projects","id":"id","attributes":{"name":"project","slug":"project","full-slug":"org/project","publicly-readable":true}}}`},
		[]string{`{"data":[]}`, `{"data":[{"type":"projects","id":"id"}]}`, `{"data":{"type":"projects","id":"id","attributes":{"name":"name","slug":"slug","full-slug":"org/slug","publicly-readable":null}}}`, `{"data":{"type":"users","id":"id","attributes":{"name":"name","slug":"slug","full-slug":"org/slug","publicly-readable":false}}}`}, nil},
	{"pepipost-api-key", verifyPepipost, "secret", "https://emailapi.netcorecloud.net/v6/suppressions/global/domain?limit=1", "Authorization", "Bearer secret",
		[]string{`[]`, `[{"domain":"example.com","created":"2024-03-20 10:00:00","modified":"2024-03-20 10:00:00","status":5}]`},
		[]string{`{}`, `[{}]`, `[{"domain":"example.com","created":"date","modified":"date","status":null}]`, `[{"domain":"example.com","created":"date","modified":"date","status":5,"error":"denied"}]`},
		[]string{"https://emailapi.netcorecloud.net/v6/suppressions/global/domain?limit=1", "https://apieu.netcorecloud.net/v6/suppressions/global/domain?limit=1"}},
	{"cliengo-api-key", verifyCliengo, "sk_live_secret", "https://connect.cliengo.com/v1/users/me", "Authorization", "Bearer sk_live_secret",
		[]string{`{"id":"id","email":"private-metadata","active":false,"name":null}`},
		[]string{`{}`, `{"id":"id"}`, `{"id":1,"email":"mail"}`, `{"id":"id","email":"mail","error":"denied"}`}, nil},
	{"datagov-api-key", verifyDataGov, "secret", "https://developer.nlr.gov/api/alt-fuel-stations/v1.json?limit=0&api_key=secret", "", "",
		[]string{`{"total_results":0,"station_locator_url":"https://afdc.energy.gov/stations","fuel_stations":[]}`, `{"total_results":9000,"station_locator_url":"https://afdc.energy.gov/stations","fuel_stations":[]}`},
		[]string{`{}`, `{"total_results":"0","station_locator_url":"url","fuel_stations":[]}`, `{"total_results":0,"station_locator_url":"url","fuel_stations":null}`, `{"total_results":1,"station_locator_url":"url","fuel_stations":[{}]}`, `{"error":{"code":"API_KEY_INVALID"}}`}, nil},
}

func checkBatch28Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch28Contracts[index]
	endpoint := tc.endpoint
	if len(tc.regions) > 0 && call < len(tc.regions) {
		endpoint = tc.regions[call]
	} else if call > 0 {
		t.Fatal("unexpected extra request")
	}
	accept := "application/json"
	if tc.id == "percy-token" {
		accept = "application/vnd.percy+json; version=3"
	}
	if req.Method != http.MethodGet || req.URL.String() != endpoint || req.Header.Get("Accept") != accept || (req.Body != nil && req.Body != http.NoBody) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
	}
	if tc.header != "" && req.Header.Get(tc.header) != tc.value {
		t.Fatal("wrong authentication")
	}
	if tc.header != "Authorization" && req.Header.Get("Authorization") != "" {
		t.Fatal("unexpected authorization")
	}
}

func TestTwentyEighthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[d.Info().ID] = r
		}
	}
	if len(batch28Contracts) != 10 {
		t.Fatal("expected ten verifiers")
	}
	for index, tc := range batch28Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.id == "vagrant-cloud-token" {
				safety = VerificationSafetyAuthOnly
			}
			if d.Info().VerificationSafety != safety {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `null`, `"ok"`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"errors":["private-metadata"]}`)
			for _, field := range []string{"error", "error_code", "errors"} {
				body := tc.valid[len(tc.valid)-1]
				var object identityPayload
				var array []identityPayload
				isArray := strings.HasPrefix(body, "[")
				if isArray {
					if err := json.Unmarshal([]byte(body), &array); err != nil || len(array) != 1 {
						t.Fatal("invalid fixture")
					}
					object = array[0]
				} else if err := json.Unmarshal([]byte(body), &object); err != nil {
					t.Fatal(err)
				}
				object[field] = json.RawMessage(`"private-metadata"`)
				var encoded []byte
				if isArray {
					encoded, _ = json.Marshal(array)
				} else {
					encoded, _ = json.Marshal(object)
				}
				bodies = append(bodies, string(encoded))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch28Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: tc.secret, Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want, wantCalls := VerificationUnknown, 1
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if len(tc.regions) > 0 && (status == 401 || status == 403) {
						wantCalls = len(tc.regions)
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwentyEighthBatchFailuresAndFallback(t *testing.T) {
	for index, tc := range batch28Contracts {
		t.Run(tc.id, func(t *testing.T) {
			for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					checkBatch28Request(t, index, calls, req)
					calls++
					if failure != nil {
						return nil, failure
					}
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxVerificationResponseBytes) + tc.valid[0]))}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret)
				if r.Status != VerificationUnknown || calls != 1 || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("%+v calls=%d", r, calls)
				}
			}
			if len(tc.regions) > 0 {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					checkBatch28Request(t, index, calls, req)
					calls++
					status, body := 403, `{"error":"region or scope"}`
					if calls == len(tc.regions) {
						status, body = 200, tc.valid[0]
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret)
				if r.Status != VerificationVerified || calls != len(tc.regions) || r.Response != "" {
					t.Fatalf("%+v calls=%d", r, calls)
				}
			}
		})
	}
}

func TestTwentyEighthBatchCliengoFamilies(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != "https://connect.stagecliengo.com/v1/users/me" || req.Header.Get("Authorization") != "Bearer sk_test_secret" {
			t.Fatal("wrong test routing")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"id","email":"mail"}`))}, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	if r := verifyCliengo(ctx, "01234567-89ab-cdef-0123-456789abcdef"); r.Status != VerificationUnknown || calls != 0 {
		t.Fatalf("legacy: %+v calls=%d", r, calls)
	}
	if r := verifyCliengo(ctx, "sk_test_secret"); r.Status != VerificationVerified || calls != 1 {
		t.Fatalf("test: %+v calls=%d", r, calls)
	}
}

func TestTwentyEighthBatchBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	for _, tc := range []struct{ id, prefix, secret string }{
		{"grafana-token", "", "glc_eyJ" + strings.Repeat("A", 80) + "=="},
		{"fal-ai-api-key", "fal.ai api_key", "12345678-1234-1234-1234-123456789abc:" + strings.Repeat("A", 31) + "-"},
		{"salesforce-access-token", "", "00" + strings.Repeat("A", 13) + "!" + strings.Repeat("A", 95) + "."},
		{"apisports-api-key", "api-sports api_key", strings.Repeat("A", 31) + "-"},
		{"trayio-api-token", "tray.io token", strings.Repeat("a", 40)},
		{"vagrant-cloud-token", "vagrant token", strings.Repeat("A", 64)},
		{"percy-token", "PERCY_TOKEN", "web_" + strings.Repeat("A", 40)},
		{"pepipost-api-key", "netcore key", strings.Repeat("A", 31) + "-"},
		{"cliengo-api-key", "cliengo key", "sk_live_" + strings.Repeat("A", 40)},
		{"cliengo-api-key", "cliengo key", "sk_test_" + strings.Repeat("A", 40)},
		{"cliengo-api-key", "cliengo key", "12345678-1234-1234-1234-123456789abc"},
		{"datagov-api-key", "data.gov key", strings.Repeat("A", 40)},
	} {
		got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + `"`))
		if len(got) != 1 || got[0].Secret != tc.secret {
			t.Fatalf("%s lost credential: %+v", tc.id, got)
		}
		if got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + strings.Repeat("A", 2000) + `"`)); len(got) != 0 {
			t.Fatalf("%s truncated credential", tc.id)
		}
	}
}

func TestTwentyEighthBatchReadFailuresAndCancellation(t *testing.T) {
	for _, tc := range batch28Contracts {
		t.Run(tc.id, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
			})}
			if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret); r.Status != VerificationUnknown || r.Response != "" || calls != 1 {
				t.Fatalf("%+v calls=%d", r, calls)
			}
			if len(tc.regions) == 0 {
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls = 0
			client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				cancel()
				return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"error":"region"}`))}, nil
			})
			if r := tc.verify(WithVerificationHTTPClient(ctx, client), tc.secret); r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" || calls != 1 {
				t.Fatalf("%+v calls=%d", r, calls)
			}
		})
	}
}
