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

var batch24Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	header, prefix string
	valid, invalid []string
}{
	{"iterable-api-key", verifyIterable, []string{"https://api.iterable.com/api/users/getFields", "https://api.eu.iterable.com/api/users/getFields"}, "Api-Key", "",
		[]string{`{"fields":{}}`, `{"fields":{"email":"string","custom":{"nested":"long"}}}`},
		[]string{`{"fields":null}`, `{"fields":[]}`, `{"fields":{},"code":"BadApiKey"}`}},
	{"zoho-crm-token", verifyZohoCRM, []string{"https://www.zohoapis.com/crm/v8/users?type=CurrentUser", "https://www.zohoapis.eu/crm/v8/users?type=CurrentUser", "https://www.zohoapis.in/crm/v8/users?type=CurrentUser", "https://www.zohoapis.com.au/crm/v8/users?type=CurrentUser", "https://www.zohoapis.jp/crm/v8/users?type=CurrentUser", "https://www.zohoapis.ca/crm/v8/users?type=CurrentUser", "https://www.zohoapis.sa/crm/v8/users?type=CurrentUser"}, "Authorization", "Zoho-oauthtoken ",
		[]string{`{"users":[]}`, `{"users":[{"id":"id","email":"mail","last_name":null,"status":"inactive"}]}`},
		[]string{`{"users":null}`, `{"users":[{"id":"id"}]}`, `{"users":[],"code":"OAUTH_SCOPE_MISMATCH"}`}},
	{"nylas-api-key", verifyNylas, []string{"https://api.us.nylas.com/v3/grants?limit=1&offset=0", "https://api.eu.nylas.com/v3/grants?limit=1&offset=0"}, "Authorization", "Bearer ",
		[]string{`{"data":[]}`, `{"data":[{"id":"id","provider":"virtual-calendar","created_at":0,"grant_status":"invalid","email":null}]}`},
		[]string{`{"data":null}`, `{"data":[{"id":"id","provider":"google","created_at":null}]}`, `{"data":[{}]}`}},
	{"phrase-access-token", verifyPhrase, []string{"https://api.phrase.com/v2/user", "https://api.us.app.phrase.com/v2/user"}, "Authorization", "token ",
		[]string{`{"id":"id","username":"user","email":"mail","position":null}`},
		[]string{`{"id":"id","username":"user"}`, `{"id":1,"username":"user","email":"mail"}`}},
	{"gusto-api-token", verifyGusto, []string{"https://api.gusto.com/v1/token_info", "https://api.gusto-demo.com/v1/token_info"}, "Authorization", "Bearer ",
		[]string{`{"scope":"","resource":null,"resource_owner":null}`, `{"scope":"public","resource":{"type":"Oauth::Application","uuid":"id"},"resource_owner":null}`, `{"scope":"public","resource":{"type":"Company","uuid":"id"},"resource_owner":{"type":"Employee","uuid":"id"}}`},
		[]string{`{"scope":null,"resource":null,"resource_owner":null}`, `{"scope":"public"}`, `{"scope":"public","resource":{},"resource_owner":null}`, `{"scope":"public","resource":null,"resource_owner":{"type":"Employee","uuid":"id","error":"denied"}}`}},
	{"thousandeyes-token", verifyThousandEyes, []string{"https://api.thousandeyes.com/v7/account-groups"}, "Authorization", "Bearer ",
		[]string{`{"accountGroups":[]}`, `{"accountGroups":[{"aid":"1234","accountGroupName":"name","isCurrentAccountGroup":false}],"_links":{"self":{"href":"https://other.invalid"}}}`},
		[]string{`{"accountGroups":null}`, `{"accountGroups":[{"aid":1234,"accountGroupName":"name"}]}`, `{"accountGroups":[],"status":403}`, `{"accountGroups":[],"detail":"denied"}`}},
	{"envoy-api-key", verifyEnvoy, []string{"https://api.envoy.com/rest/v1/locations?page=1&perPage=1"}, "X-Api-Key", "",
		[]string{`{"data":[]}`, `{"data":[{"id":"1","name":"name","companyId":"2","enabled":false}]}`},
		[]string{`{"data":null}`, `{"data":[{"id":"1","name":"name"}]}`, `{"data":[{"id":1,"name":"name","companyId":"2"}]}`}},
	{"frameio-api-token", verifyFrameIO, []string{"https://api.frame.io/v2/me"}, "Authorization", "Bearer ",
		[]string{`{"id":"id","account_id":"account","email":"mail","bio":null}`},
		[]string{`{"id":"id","email":"mail"}`, `{"id":"id","account_id":null,"email":"mail"}`}},
	{"codacy-api-token", verifyCodacy, []string{"https://api.codacy.com/api/v3/user"}, "api-token", "",
		[]string{`{"data":{"id":0,"mainEmail":"mail","isActive":false}}`},
		[]string{`{"data":{"id":"1","mainEmail":"mail"}}`, `{"data":{"id":null,"mainEmail":"mail"}}`, `{"data":{"id":1,"mainEmail":"mail","error":"denied"}}`}},
	{"jumpcloud-api-key", verifyJumpCloud, []string{"https://console.jumpcloud.com/api/systemusers?limit=1&skip=0&fields=_id", "https://console.eu.jumpcloud.com/api/systemusers?limit=1&skip=0&fields=_id", "https://console.in.jumpcloud.com/api/systemusers?limit=1&skip=0&fields=_id"}, "x-api-key", "",
		[]string{`{"totalCount":0,"results":[]}`, `{"totalCount":10,"results":[{"_id":"id"}]}`},
		[]string{`{"totalCount":0,"results":null}`, `{"totalCount":"0","results":[]}`, `{"totalCount":1,"results":[{}]}`, `{"totalCount":0,"results":[],"code":401}`}},
}

func checkBatch24Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch24Contracts[index]
	if call >= len(tc.urls) || req.URL.String() != tc.urls[call] || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get(tc.header) != tc.prefix+"secret" || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	if tc.id == "gusto-api-token" && req.Header.Get("X-Gusto-API-Version") != "2026-06-15" {
		t.Fatal("missing API version")
	}
}

func TestTwentyFourthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	if len(batch24Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for index, tc := range batch24Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.id == "gusto-api-token" {
				safety = VerificationSafetyAuthOnly
			}
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
						checkBatch24Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: "secret", Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
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

func TestTwentyFourthBatchTransportAndFallback(t *testing.T) {
	for index, tc := range batch24Contracts {
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
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "secret")
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
						checkBatch24Request(t, index, calls, req)
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
					r := tc.verify(WithVerificationHTTPClient(ctx, client), "secret")
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

func TestTwentyFourthBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"iterable api_key", "", "nylas client_secret", "phrase access_token", "gusto_api token", "thousand_eyes token", "envoy api_key", "frame.io token", "codacy token", "jumpcloud api_key"}
	secrets := []string{strings.Repeat("A", 31) + "-", "1000." + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32), strings.Repeat("A", 31) + "-", strings.Repeat("A", 40), strings.Repeat("A", 31) + "/", strings.Repeat("A", 32), strings.Repeat("A", 220), strings.Repeat("A", 32), strings.Repeat("A", 32), strings.Repeat("A", 40)}
	for i, tc := range batch24Contracts {
		got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `"`))
		if len(got) != 1 || got[0].Secret != secrets[i] {
			t.Fatalf("%s lost token: %+v", tc.id, got)
		}
		if got := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `+suffix"`)); len(got) != 0 {
			t.Fatalf("%s truncated token", tc.id)
		}
	}
}
