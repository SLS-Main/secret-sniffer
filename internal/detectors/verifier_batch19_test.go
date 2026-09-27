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

var batch19Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	header, prefix string
	valid, invalid []string
}{
	{"klaviyo-key", verifyKlaviyo, []string{"https://a.klaviyo.com/api/accounts?fields%5Baccount%5D=timezone"}, "Authorization", "Klaviyo-API-Key ",
		[]string{`{"data":[{"id":"acct1","type":"account","attributes":{"timezone":"UTC"}}]}`},
		[]string{`{"data":[]}`, `{"data":null}`, `{"data":[{"id":"acct1","type":"profile","attributes":{"timezone":"UTC"}}]}`, `{"data":[{"id":"acct1","type":"account","attributes":{"timezone":null}}]}`, `{"data":[{"id":"acct1","type":"account","attributes":{"timezone":"UTC","error":"denied"}}]}`}},
	{"openphone-api-key", verifyOpenPhone, []string{"https://api.quo.com/organization"}, "Authorization", "",
		[]string{`{"data":{"id":"ORabc","name":null,"subscriptionStatus":"active","createdAt":"date","updatedAt":"date"}}`, `{"data":{"id":"ORabc","subscriptionStatus":"expired","createdAt":"date","updatedAt":"date"}}`},
		[]string{`{"data":[]}`, `{"data":{"id":"ORabc"}}`, `{"data":{"id":"ORabc","subscriptionStatus":"unknown","createdAt":"date","updatedAt":"date"}}`}},
	{"socketdev-api-key", verifySocketDev, []string{"https://api.socket.dev/v0/organizations"}, "Authorization", "Bearer ",
		[]string{`{"organizations":{}}`, `{"organizations":{"org1":{"id":"org1","slug":"org","plan":"free","name":null,"image":null}}}`},
		[]string{`{"organizations":[]}`, `{"organizations":null}`, `{"organizations":{"org1":null}}`, `{"organizations":{"org1":{"id":"org1","slug":"org"}}}`, `{"organizations":{"org1":{"id":"org1","slug":"org","plan":"free","error":"denied"}}}`}},
	{"float-api-key", verifyFloat, []string{"https://api.float.com/v3/accounts?per-page=1&fields=account_id,name"}, "Authorization", "Bearer ",
		[]string{`[]`, `[{"account_id":1,"name":"private-metadata"}]`},
		[]string{`[{}]`, `[null]`, `[{"account_id":"1","name":"name"}]`, `[{"account_id":1,"name":"name","error":"denied"}]`}},
	{"nimble-api-key", verifyNimble, []string{"https://app.nimble.com/api/v1/myself"}, "Authorization", "Bearer ",
		[]string{`{"user_id":"user1","company_id":"company1","email":"private-metadata"}`},
		[]string{`{"id":"user1"}`, `{"user_id":"user1","company_id":"company1","email":null}`, `{"user_id":"user1","company_id":"company1","email":"mail","code":108}`}},
	{"yousign-api-key", verifyYousign, []string{"https://api.yousign.app/v3/users?limit=1", "https://api-sandbox.yousign.app/v3/users?limit=1"}, "Authorization", "Bearer ",
		[]string{`{"data":[],"meta":{"next_cursor":null}}`, `{"data":[{"id":"user1","email":"private-metadata","first_name":null,"is_active":false}],"meta":{"next_cursor":"next"}}`},
		[]string{`{"data":[]}`, `{"data":[],"meta":{}}`, `{"data":[],"meta":{"next_cursor":3}}`, `{"data":null,"meta":{"next_cursor":null}}`, `{"data":[{}],"meta":{"next_cursor":null}}`}},
	{"geckoboard-api-key", verifyGeckoboard, []string{"https://api.geckoboard.com/"}, "basic", "",
		[]string{`{}`, " \n{ }\n"}, []string{`{"success":true}`, `{"message":"OK"}`, `{"errors":[]}`, `{"error":"api key you provided is invalid"}`}},
	{"taxjar-api-token", verifyTaxJar, []string{"https://api.taxjar.com/v2/categories", "https://api.sandbox.taxjar.com/v2/categories"}, "Authorization", "Bearer ",
		[]string{`{"categories":[]}`, `{"categories":[{"product_tax_code":"10040","name":"Installation Services"}]}`},
		[]string{`{"categories":null}`, `{"categories":[{}]}`, `{"categories":[{"product_tax_code":10040,"name":"Services"}]}`}},
	{"fastforex-api-key", verifyFastForex, []string{"https://api.fastforex.io/usage"}, "X-API-KEY", "",
		[]string{`{"monthly_quota":0,"usage":{"2026-09-27":0},"current_period":{"start":"2026-09-01","end":"2026-09-30","remaining_quota":0,"usage":0}}`},
		[]string{`{"monthly_quota":1}`, `{"monthly_quota":0,"usage":null,"current_period":{"start":"date","end":"date","remaining_quota":0,"usage":0}}`, `{"monthly_quota":0,"usage":{"2026-09-27":"0"},"current_period":{"start":"date","end":"date","remaining_quota":0,"usage":0}}`, `{"monthly_quota":0,"usage":{"2026-09-27":0},"current_period":{"start":"date","end":"date","remaining_quota":null,"usage":0}}`}},
	{"craftmypdf-api-key", verifyCraftMyPDF, []string{"https://api.craftmypdf.com/v1/get-account-info"}, "X-API-KEY", "",
		[]string{`{"status":"success","username":"private-metadata","created_at":"date","quota_counter":0.5,"quota_max":0}`, `{"status":"success","username":"mail","created_at":"date","quota_counter":0,"quota_max":100}`},
		[]string{`{"status":"success","data":{}}`, `{"status":"error","username":"mail","created_at":"date","quota_counter":0,"quota_max":100}`, `{"status":"success","username":"mail","created_at":"date","quota_counter":null,"quota_max":100}`, `{"status":"success","username":"mail","created_at":"date","quota_counter":"0","quota_max":100}`, `{"status":"success","username":"mail","created_at":"date","quota_counter":-1,"quota_max":100}`}},
}

func TestNineteenthBatchContracts(t *testing.T) {
	if len(batch19Contracts) < 10 {
		t.Fatal("expected ten contracts")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch19Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.id == "geckoboard-api-key" {
				safety = VerificationSafetyAuthOnly
			}
			if d.Info().VerificationSafety != safety {
				t.Fatal("wrong runtime safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `null`, `<html>OK</html>`, tc.valid[0]+" trailing")
			if tc.id != "geckoboard-api-key" {
				bodies = append(bodies, `{}`)
			}
			if tc.id != "float-api-key" {
				for _, field := range []string{"error", "errors", "error_code"} {
					var p map[string]json.RawMessage
					if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
						t.Fatal(err)
					}
					p[field] = json.RawMessage(`"private-metadata"`)
					body, _ := json.Marshal(p)
					bodies = append(bodies, string(body))
				}
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					secret := "test-secret+/=private-metadata"
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						accept := "application/json"
						if tc.id == "klaviyo-key" {
							accept = "application/vnd.api+json"
						}
						if calls >= len(tc.urls) || req.URL.String() != tc.urls[calls] || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != accept {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						calls++
						if tc.header == "basic" {
							u, p, ok := req.BasicAuth()
							if !ok || u != secret || p != "" {
								t.Fatal("incorrect Basic auth")
							}
						} else if req.Header.Get(tc.header) != tc.prefix+secret {
							t.Fatal("incorrect auth header")
						}
						if tc.id == "openphone-api-key" && req.Header.Get("Quo-Api-Version") != "2026-03-30" {
							t.Fatal("missing Quo version")
						}
						if tc.id == "klaviyo-key" && req.Header.Get("revision") != "2026-07-15" {
							t.Fatal("missing Klaviyo revision")
						}
						if tc.id == "float-api-key" && !strings.Contains(req.Header.Get("User-Agent"), "sls-jmantz@users.noreply.github.com") {
							t.Fatal("missing Float contact")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: secret, Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
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

func TestNineteenthBatchTransportAndFallback(t *testing.T) {
	for _, tc := range batch19Contracts {
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
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "test-secret")
				if calls != 1 || r.Status != VerificationUnknown || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
			if len(tc.urls) < 2 {
				return
			}
			for _, firstStatus := range []int{401, 403} {
				for _, cancelled := range []bool{false, true} {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if calls >= len(tc.urls) || req.URL.String() != tc.urls[calls] {
							t.Fatal("unexpected fallback host")
						}
						calls++
						status, body := firstStatus, `{"error":"permission denied"}`
						if calls == len(tc.urls) {
							status, body = 200, tc.valid[0]
						}
						if cancelled {
							cancel()
						}
						return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := tc.verify(WithVerificationHTTPClient(ctx, client), "test-secret")
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

func TestNineteenthBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	for _, tc := range []struct{ id, context, secret string }{
		{"craftmypdf-api-key", "craftmypdf api_key", strings.Repeat("Ab3+", 8) + "="},
		{"craftmypdf-api-key", "craftmypdf api_key", strings.Repeat("Ab3/", 8) + "=="},
		{"taxjar-api-token", "taxjar api_key", strings.Repeat("ab3d", 7)},
		{"geckoboard-api-key", "geckoboard api_key", strings.Repeat("Ab3d", 11)},
		{"nimble-api-key", "nimble api_key", strings.Repeat("Ab3", 10)},
		{"fastforex-api-key", "fastforex api_key", strings.Repeat("ab3d", 8)},
		{"openphone-api-key", "quo api_key", strings.Repeat("Ab3d", 10)},
		{"socketdev-api-key", "socketdev api_key", strings.Repeat("Ab3d", 10)},
	} {
		matches := registry[tc.id].Detect([]byte(tc.context + ` = "` + tc.secret + `"`))
		if len(matches) != 1 || matches[0].Secret != tc.secret {
			t.Fatalf("%s failed whole-secret capture: %+v", tc.id, matches)
		}
		if tc.id == "openphone-api-key" || tc.id == "socketdev-api-key" {
			continue
		}
		// A supported prefix must never be sent as a truncated larger credential.
		if matches := registry[tc.id].Detect([]byte(tc.context + ` = "` + tc.secret + strings.Repeat("Z", 150) + `"`)); len(matches) != 0 {
			t.Fatalf("%s truncated oversized key: %+v", tc.id, matches)
		}
	}
}
