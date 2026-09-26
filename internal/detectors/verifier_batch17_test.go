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

var batch17Contracts = []struct {
	id                    string
	verify                Verifier
	urls                  []string
	header, prefix, query string
	valid, invalid        []string
}{
	{"snyk-api-key", verifySnyk, []string{"https://api.snyk.io/rest/self?version=2024-10-15", "https://api.us.snyk.io/rest/self?version=2024-10-15", "https://api.eu.snyk.io/rest/self?version=2024-10-15", "https://api.au.snyk.io/rest/self?version=2024-10-15"}, "Authorization", "token ", "",
		[]string{`{"data":{"id":"user1","type":"user","attributes":{"email":"private-metadata"}}}`, `{"data":{"id":"svc1","type":"service_account","attributes":{"name":"CI"}}}`, `{"data":{"id":"app1","type":"app_instance","attributes":{"name":"app"}}}`},
		[]string{`{"data":{"id":"user1","type":"user","attributes":{}}}`, `{"data":{"id":"user1","type":"unknown","attributes":{"email":"mail"}}}`, `{"data":{"id":"user1","type":"user","attributes":{"email":"mail","error":"denied"}}}`}},
	{"meraki-api-key", verifyMeraki, []string{"https://api.meraki.com/api/v1/administered/identities/me"}, "Authorization", "Bearer ", "",
		[]string{`{"name":"private-metadata","email":"mail"}`}, []string{`{"name":"name"}`, `{"name":null,"email":"mail"}`}},
	{"productboard-api-token", verifyProductboard, []string{"https://api.productboard.com/v2/members"}, "Authorization", "Bearer ", "",
		[]string{`{"data":[]}`, `{"data":[{"id":"member1","type":"member","fields":{"role":"viewer","email":"[redacted]"}}],"links":{"next":"https://other.invalid/"}}`},
		[]string{`{"data":null}`, `{"data":[{}]}`, `{"data":[{"id":"member1","type":"member","fields":{}}]}`, `{"data":[{"id":"member1","type":"team","fields":{"role":"admin"}}]}`}},
	{"wistia-api-token", verifyWistia, []string{"https://api.wistia.com/modern/token"}, "Authorization", "Bearer ", "",
		[]string{`{"type":"permanent","scopes":[],"application":null,"name":"private-metadata"}`, `{"type":"expiring","scopes":["read"],"application":null,"name":null}`, `{"type":"oauth","scopes":[],"application":{"name":"app","scopes":[]},"name":null}`},
		[]string{`{"type":"permanent","scopes":null,"application":null,"name":null}`, `{"type":"permanent","scopes":[null],"application":null,"name":null}`, `{"type":"permanent","scopes":[],"name":null}`, `{"type":"permanent","scopes":[],"application":null}`, `{"type":"oauth","scopes":[],"application":null,"name":null}`, `{"type":"oauth","scopes":[],"application":{"name":"app","scopes":[1]},"name":null}`}},
	{"twelvedata-api-key", verifyTwelveData, []string{"https://api.twelvedata.com/api_usage"}, "", "", "apikey",
		[]string{`{"timestamp":"2026-09-26","plan_category":"private-metadata","current_usage":0,"plan_limit":0}`, `{"timestamp":"date","plan_category":"enterprise","current_usage":100,"plan_limit":10,"daily_usage":0,"plan_daily_limit":0}`},
		[]string{`{"timestamp":"date","plan_category":"basic","current_usage":-1,"plan_limit":10}`, `{"timestamp":"date","plan_category":"basic","current_usage":1.5,"plan_limit":10}`, `{"timestamp":"date","plan_category":"basic","current_usage":1,"plan_limit":10,"daily_usage":null}`, `{"timestamp":"date","plan_category":"basic","current_usage":1,"plan_limit":10,"code":401}`}},
	{"guardian-api-key", verifyGuardian, []string{"https://content.guardianapis.com/search?page-size=1"}, "", "", "api-key",
		[]string{`{"response":{"status":"ok","userTier":"developer","total":0,"results":[]}}`, `{"response":{"status":"ok","userTier":"developer","total":1,"results":[{"id":"article1","type":"article","webUrl":"https://example.org","webTitle":"private-metadata"}]}}`},
		[]string{`{"response":{"status":"ok"}}`, `{"response":{"status":"ok","userTier":"developer","total":0,"results":null}}`, `{"response":{"status":"ok","userTier":"developer","total":1,"results":[{}]}}`}},
	{"newsapi-key", verifyNewsAPI, []string{"https://newsapi.org/v2/top-headlines?country=us&pageSize=1"}, "X-Api-Key", "", "",
		[]string{`{"status":"ok","totalResults":0,"articles":[]}`, `{"status":"ok","totalResults":1,"articles":[{"url":"https://example.org","publishedAt":"date","title":null,"author":null,"content":"private-metadata"}]}`},
		[]string{`{"status":"ok"}`, `{"status":"ok","totalResults":0,"articles":null}`, `{"status":"ok","totalResults":1,"articles":[{}]}`, `{"status":"ok","totalResults":0,"articles":[],"code":"apiKeyInvalid"}`}},
	{"northflank-api-token", verifyNorthflank, []string{"https://api.northflank.com/v1/auth"}, "Authorization", "Bearer ", "",
		[]string{`{"data":{"tokenKind":"api","id":"token1","entityId":"team1","entityUid":"uid1","entityType":"team","createdAt":"date","name":"private-metadata"}}`, `{"data":{"tokenKind":"session","id":"session1","entityId":"org1","entityUid":"uid1","entityType":"org","createdAt":"date"}}`},
		[]string{`{"data":{"tokenKind":"api","id":"token1"}}`, `{"data":{"tokenKind":"unknown","id":"token1","entityId":"team1","entityUid":"uid1","entityType":"team","createdAt":"date"}}`}},
	{"shotstack-api-key", verifyShotstack, []string{"https://api.shotstack.io/edit/stage/templates", "https://api.shotstack.io/edit/v1/templates"}, "x-api-key", "", "",
		[]string{`{"success":true,"response":{"owner":"user1","templates":[]}}`, `{"success":true,"response":{"owner":"user1","templates":[{"id":"template1","name":"private-metadata"}]}}`},
		[]string{`{"success":true}`, `{"success":false,"response":{"owner":"user1","templates":[]}}`, `{"success":true,"response":{"owner":"user1","templates":null}}`, `{"success":true,"response":{"owner":"user1","templates":[{}]}}`}},
	{"optimizely-api-key", verifyOptimizely, []string{"https://api.optimizely.com/v2/me"}, "Authorization", "Bearer ", "",
		[]string{`{"id":"user1","profile":{"email":"private-metadata"}}`},
		[]string{`{"id":"user1"}`, `{"id":"user1","profile":{"email":"mail","error":"denied"}}`, `{"id":"user1","profile":{"email":"mail"},"code":"denied"}`}},
}

func TestSeventeenthBatchContracts(t *testing.T) {
	if len(batch17Contracts) < 10 {
		t.Fatal("expected at least ten contracts")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch17Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.id == "wistia-api-token" || tc.id == "northflank-api-token" {
				safety = VerificationSafetyAuthOnly
			}
			if d.Info().VerificationSafety != safety {
				t.Fatal("incorrect runtime safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `[]`, `<html>OK</html>`, tc.valid[0]+" trailing")
			for _, field := range []string{"error", "errors", "error_code"} {
				var p map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
					t.Fatal(err)
				}
				p[field] = json.RawMessage(`"private-metadata"`)
				body, _ := json.Marshal(p)
				bodies = append(bodies, string(body))
			}
			if tc.id == "wistia-api-token" {
				bodies = append(bodies, `{"type":"permanent","scopes":[],"application":null,"name":null,"code":"account_inactive"}`)
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					secret := "test-secret+/?=&"
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						actual := *req.URL
						if tc.query != "" {
							q := actual.Query()
							if q.Get(tc.query) != secret {
								t.Fatal("query authentication not escaped correctly")
							}
							q.Del(tc.query)
							actual.RawQuery = q.Encode()
						} else if req.Header.Get(tc.header) != tc.prefix+secret {
							t.Fatal("incorrect authentication")
						}
						if calls >= len(tc.urls) || actual.String() != tc.urls[calls] || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						if tc.id == "wistia-api-token" && req.Header.Get("X-Wistia-API-Version") != "2026-07" {
							t.Fatal("missing API version")
						}
						calls++
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

func TestSeventeenthBatchFailuresAndFallback(t *testing.T) {
	for _, tc := range batch17Contracts {
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
							t.Fatalf("unexpected URL %s", req.URL)
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

func TestSeventeenthBatchNewsAPIRejections(t *testing.T) {
	for _, status := range []int{200, 201, 302, 400, 401, 403, 429, 500} {
		for _, code := range []string{"apiKeyInvalid", "apiKeyDisabled", "apiKeyExhausted", "apiKeyMissing", "rateLimited", "unexpectedError"} {
			for _, contradiction := range []bool{false, true} {
				body := `{"status":"error","code":"` + code + `","message":"private-metadata"`
				if contradiction {
					body += `,"articles":[],"totalResults":0`
				}
				body += `}`
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				r := verifyNewsAPI(WithVerificationHTTPClient(context.Background(), client), "test-secret")
				want := VerificationUnknown
				if status == 401 && !contradiction && (code == "apiKeyInvalid" || code == "apiKeyDisabled") {
					want = VerificationUnverified
				}
				if r.Status != want || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("status=%d body=%s result=%+v", status, body, r)
				}
			}
		}
	}
}
