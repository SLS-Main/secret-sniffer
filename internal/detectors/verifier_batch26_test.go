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

var batch26Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	header, value  string
	valid, invalid []string
}{
	{"harness-pat", verifyHarness, []string{"https://app.harness.io/ng/api/user/currentUser?accountIdentifier=" + strings.Repeat("A", 22)}, "x-api-key", "",
		[]string{`{"status":"SUCCESS","data":{"uuid":"id","email":"mail","disabled":true,"name":null,"token":"private-metadata"}}`},
		[]string{`{"status":"SUCCESS","data":{}}`, `{"status":"FAILURE","data":{"uuid":"id","email":"mail"}}`, `{"status":"SUCCESS","data":{"uuid":"id","email":"mail"},"code":"INVALID_TOKEN"}`, `{"status":"SUCCESS","data":{"uuid":"id","email":"mail","error":"denied"}}`}},
	{"sanity-auth-token", verifySanity, []string{"https://api.sanity.io/v2021-10-21/users/me"}, "Authorization", "Bearer secret",
		[]string{`{"id":"id","name":"","email":null,"profileImage":null}`, `{"id":"id","name":"name","role":"viewer"}`},
		[]string{`{"id":"id"}`, `{"id":"id","name":null}`, `{"id":1,"name":"name"}`}},
	{"temporal-cloud-api-key", verifyTemporalCloud, []string{"https://saas-api.tmprl.cloud/cloud/current-identity"}, "Authorization", "Bearer secret",
		[]string{`{"user":{"id":"id","spec":{"email":"mail"},"state":"RESOURCE_STATE_DISABLED"}}`, `{"serviceAccount":{"id":"id","spec":{"name":"name"}},"principalApiKey":{"id":"private-metadata"}}`},
		[]string{`{"principalApiKey":{"id":"id"}}`, `{"user":{"id":"id","spec":{"email":"mail"}},"serviceAccount":{"id":"id","spec":{"name":"name"}}}`, `{"user":{"id":"id","spec":null}}`, `{"user":{"id":"id","spec":{"email":"mail","error":"denied"}}}`, `{"user":{"id":"id","spec":{"email":"mail"}},"code":7}`}},
	{"bunny-api-key", verifyBunny, []string{"https://api.bunny.net/statistics"}, "AccessKey", "secret",
		[]string{`{"TotalBandwidthUsed":0,"TotalOriginTraffic":0,"AverageOriginResponseTime":0,"TotalRequestsServed":0,"CacheHitRate":0}`, `{"TotalBandwidthUsed":10,"TotalOriginTraffic":5,"AverageOriginResponseTime":1,"TotalRequestsServed":2,"CacheHitRate":50.5,"BandwidthUsedChart":null}`},
		[]string{`{"TotalBandwidthUsed":0}`, `{"TotalBandwidthUsed":0,"TotalOriginTraffic":0,"AverageOriginResponseTime":0,"TotalRequestsServed":null,"CacheHitRate":0}`, `{"TotalBandwidthUsed":0,"TotalOriginTraffic":0,"AverageOriginResponseTime":0,"TotalRequestsServed":0,"CacheHitRate":"0"}`, `{"TotalBandwidthUsed":0,"TotalOriginTraffic":0,"AverageOriginResponseTime":0,"TotalRequestsServed":0,"CacheHitRate":0,"ErrorKey":"unauthorized"}`}},
	{"cronitor-api-key", verifyCronitor, []string{"https://cronitor.io/api/groups?page=1&pageSize=1"}, "Authorization", "Basic c2VjcmV0Og==",
		[]string{`{"count":0,"groups":[]}`, `{"count":1,"groups":[{"key":"key","name":"name","latest_issue":null}]}`},
		[]string{`{"count":0,"groups":null}`, `{"count":"0","groups":[]}`, `{"count":1,"groups":[{}]}`, `{"count":0,"groups":[],"detail":"denied"}`}},
	{"partnerstack-api-key", verifyPartnerStack, []string{"https://api.partnerstack.com/api/v2/partnerships?limit=1&include_offers=false"}, "Authorization", "Bearer secret",
		[]string{`{"status":200,"data":{"has_more":false,"items":[]}}`, `{"status":200,"data":{"has_more":true,"items":[{"key":"key","company":{"id":1},"status":"removed","is_archived":true,"link":null}]}}`},
		[]string{`{"status":401,"data":{"has_more":false,"items":[]}}`, `{"status":"200","data":{"has_more":false,"items":[]}}`, `{"status":200,"data":{"has_more":null,"items":[]}}`, `{"status":200,"data":{"has_more":false,"items":null}}`, `{"status":200,"data":{"has_more":false,"items":[{"key":"key","company":{"id":"1"}}]}}`, `{"status":200,"data":{"has_more":false,"items":[],"error":"denied"}}`}},
	{"feedier-api-key", verifyFeedier, []string{"https://api.bx.feedier.com/v3/teams?page=1&limit=1"}, "Authorization", "Bearer secret",
		[]string{`{"data":[]}`, `{"data":[{"id":1,"name":"name","parent_team_id":null}],"links":{"next":"https://other.invalid"}}`},
		[]string{`{"data":null}`, `{"data":[{"id":"1","name":"name"}]}`, `{"data":[{"id":1,"name":"name","error":"denied"}]}`}},
	{"fulcrum-api-token", verifyFulcrum, []string{"https://api.fulcrumapp.com/api/v2/users.json", "https://api.fulcrumapp-au.com/api/v2/users.json", "https://api.fulcrumapp-ca.com/api/v2/users.json", "https://api.fulcrumapp-eu.com/api/v2/users.json"}, "X-ApiToken", "secret",
		[]string{`{"user":{"id":"id","email":"mail","contexts":[],"first_name":null}}`},
		[]string{`{"users":[]}`, `{"user":{"id":"id"}}`, `{"user":{"id":"id","email":"mail","error":"denied"}}`}},
	{"platformsh-api-token", verifyPlatformSH, []string{"https://auth.upsun.com/oauth2/token"}, "Authorization", "Basic cGxhdGZvcm0tYXBpLXVzZXI6",
		[]string{`{"access_token":"private-metadata","token_type":"bearer","expires_in":900}`, `{"access_token":"private-metadata","token_type":"Bearer","expires_in":1}`},
		[]string{`{"access_token":"private-metadata"}`, `{"access_token":"private-metadata","token_type":"bearer","expires_in":0}`, `{"access_token":"private-metadata","token_type":"bearer","expires_in":"900"}`, `{"access_token":"private-metadata","token_type":"bearer","expires_in":null}`, `{"access_token":"private-metadata","token_type":"Basic","expires_in":900}`, `{"error":"invalid_grant"}`}},
	{"zerotier-api-token", verifyZeroTier, []string{"https://api.zerotier.com/api/v1/status"}, "Authorization", "token secret",
		[]string{`{"id":"central_status","type":"CentralStatus","user":{"id":"id","email":"mail","tokens":[]},"readOnlyMode":true}`},
		[]string{`{"id":"central_status","type":"CentralStatus","user":null}`, `{"id":"central_status","type":"CentralStatus"}`, `{"id":"other","type":"CentralStatus","user":{"id":"id","email":"mail"}}`, `{"id":"central_status","type":"CentralStatus","user":{"id":"id","email":"mail","error":"denied"}}`}},
}

func batch26Secret(id string) string {
	if id == "harness-pat" {
		return "pat." + strings.Repeat("A", 22) + "." + strings.Repeat("b", 24) + "." + strings.Repeat("C", 20)
	}
	return "secret"
}

func checkBatch26Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch26Contracts[index]
	method, url := http.MethodGet, req.URL.String()
	if tc.id == "bunny-api-key" {
		query := req.URL.Query()
		start, e1 := time.Parse(time.RFC3339, query.Get("dateFrom"))
		end, e2 := time.Parse(time.RFC3339, query.Get("dateTo"))
		if len(query) != 2 || e1 != nil || e2 != nil || end.Sub(start) != 24*time.Hour || time.Since(end) < 0 || time.Since(end) > 25*time.Hour {
			t.Fatal("unbounded or stale statistics interval")
		}
		url = req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	}
	if tc.id == "platformsh-api-token" {
		method = http.MethodPost
		body, err := io.ReadAll(req.Body)
		if err != nil || string(body) != "grant_type=api_token&api_token=secret" || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatal("unexpected token exchange")
		}
	} else if req.Body != nil && req.Body != http.NoBody {
		t.Fatal("unexpected request body")
	}
	value := tc.value
	if tc.id == "harness-pat" {
		value = batch26Secret(tc.id)
	}
	if call >= len(tc.urls) || method != req.Method || url != tc.urls[call] || req.Header.Get(tc.header) != value || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	if tc.id == "temporal-cloud-api-key" && req.Header.Get("temporal-cloud-api-version") != "v0.22.0" {
		t.Fatal("missing Temporal version")
	}
	if tc.id == "cronitor-api-key" && req.Header.Get("Cronitor-Version") != "2025-11-28" {
		t.Fatal("missing Cronitor version")
	}
}

func TestTwentySixthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[d.Info().ID] = r
		}
	}
	if len(batch26Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for index, tc := range batch26Contracts {
		t.Run(tc.id, func(t *testing.T) {
			safety := VerificationSafetyReadOnly
			if tc.id == "platformsh-api-token" {
				safety = VerificationSafetyAuthOnly
			}
			d := registry[tc.id]
			if d.Info().VerificationSafety != safety {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `[]`, `<html>OK</html>`, tc.valid[0]+" trailing")
			for _, field := range []string{"error", "errors", "error_code"} {
				var p map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
					t.Fatal(err)
				}
				p[field] = json.RawMessage(`"private-metadata"`)
				b, _ := json.Marshal(p)
				bodies = append(bodies, string(b))
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch26Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: batch26Secret(tc.id), Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want, wantCalls := VerificationUnknown, 1
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if status == 401 || status == 403 {
						wantCalls = len(tc.urls)
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwentySixthBatchFailuresAndRegionalFallback(t *testing.T) {
	for index, tc := range batch26Contracts {
		t.Run(tc.id, func(t *testing.T) {
			for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if failure != nil {
						return nil, failure
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), batch26Secret(tc.id))
				if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
			if len(tc.urls) < 2 {
				return
			}
			for _, status := range []int{401, 403} {
				for _, cancelled := range []bool{false, true} {
					ctx, cancel := context.WithCancel(context.Background())
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch26Request(t, index, calls, req)
						calls++
						code, body := status, `{"error":"denied"}`
						if calls == len(tc.urls) {
							code, body = 200, tc.valid[0]
						}
						if cancelled {
							cancel()
						}
						return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := tc.verify(WithVerificationHTTPClient(ctx, client), batch26Secret(tc.id))
					cancel()
					if cancelled {
						if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
							t.Fatalf("calls=%d result=%+v", calls, r)
						}
					} else if calls != len(tc.urls) || r.Status != VerificationVerified || r.Response != "" {
						t.Fatalf("calls=%d result=%+v", calls, r)
					}
				}
			}
		})
	}
}

func TestTwentySixthBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"", "sanity token", "temporal client_secret", "bunny.net storage_password", "cronitor telemetry_key", "partnerstack api_key", "feedier api_key", "fulcrum token", "platform.sh token", "zero_tier token"}
	secrets := []string{batch26Secret("harness-pat"), "sk" + strings.Repeat("A", 79), strings.Repeat("A", 31) + "/", strings.Repeat("A", 31) + "-", strings.Repeat("A", 31) + "-", strings.Repeat("A", 64), strings.Repeat("A", 32), strings.Repeat("A", 31) + "-", strings.Repeat("A", 31) + "-", strings.Repeat("A", 40)}
	for i, tc := range batch26Contracts {
		got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `"`))
		if len(got) != 1 || got[0].Secret != secrets[i] {
			t.Fatalf("%s lost token: %+v", tc.id, got)
		}
		if got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `+suffix"`)); len(got) != 0 {
			t.Fatalf("%s truncated token", tc.id)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported Harness credential sent")
		return nil, nil
	})}
	for _, secret := range []string{"secret", strings.Replace(batch26Secret("harness-pat"), "pat.", "sat.", 1), batch26Secret("harness-pat") + "/suffix"} {
		if r := verifyHarness(WithVerificationHTTPClient(context.Background(), client), secret); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("result=%+v", r)
		}
	}
}

func TestTwentySixthBatchFulcrumResponseCap(t *testing.T) {
	body := `{"user":{"id":"id","email":"mail","contexts":[{"name":"` + strings.Repeat("A", maxVerificationResponseBytes) + `"}]}}`
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	if r := verifyFulcrum(WithVerificationHTTPClient(context.Background(), client), "secret"); calls != 1 || r.Status != VerificationUnknown || r.Response != "" {
		t.Fatalf("calls=%d result=%+v", calls, r)
	}
}
