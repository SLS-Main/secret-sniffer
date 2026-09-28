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

var batch29Contracts = []struct {
	id                              string
	verify                          Verifier
	secret, endpoint, header, value string
	valid, invalid                  []string
	authOnly                        bool
}{
	{"complyadvantage-api-key", verifyComplyAdvantage, "secret", "https://api.complyadvantage.com/users", "Authorization", "Token secret",
		[]string{`{"status":"success","content":{"data":[]}}`, `{"status":"success","content":{"data":[{"id":1,"email":"mail","name":"private-metadata","phone":null}]}}`},
		[]string{`{"status":"success","content":[]}`, `{"status":"failure","content":{"data":[]}}`, `{"status":"success","content":{"data":null}}`, `{"status":"success","content":{"data":[{"id":"1","email":"mail","name":"name"}]}}`, `{"status":"success","content":{"data":[],"error":"denied"}}`}, false},
	{"sourcegraph-cody-token", verifySourcegraphCody, "secret", "https://cody-gateway.sourcegraph.com/v1/limits", "Authorization", "Bearer secret",
		[]string{`{}`, `{"chat_completions":{"limit":0,"usage":0,"interval":"24h0m0s","expiry":null}}`, `{"embeddings":{"limit":-1,"usage":4,"interval":"1h0m0s","expiry":"2026-09-28T12:00:00Z"}}`},
		[]string{`{"chat_completions":{}}`, `{"chat_completions":{"limit":null,"usage":0,"interval":"24h"}}`, `{"chat_completions":{"limit":1,"usage":0,"interval":"24h","expiry":"bad"}}`, `{"chat_completions":{"limit":1,"usage":0,"interval":"24h","error":"denied"}}`, `{"message":"forbidden"}`}, false},
	{"twitter-bearer-token", verifyTwitterBearer, "secret", "https://api.x.com/2/usage/credits", "Authorization", "Bearer secret",
		[]string{`{"data":{"total_balance":0,"prepaid_balance":-2.5,"free_balance":0,"free_grants":[]}}`, `{"data":{"total_balance":1.25,"prepaid_balance":0,"free_balance":1.25,"free_grants":[{"amount":1.25,"expires_at":"2027-01-01T00:00:00Z"}]}}`, `{"data":{"total_balance":0,"prepaid_balance":0,"free_balance":0,"free_grants":[{"amount":0}]}}`},
		[]string{`{"data":{"id":"20"}}`, `{"data":{"total_balance":"0","prepaid_balance":0,"free_balance":0,"free_grants":[]}}`, `{"data":{"total_balance":0,"prepaid_balance":0,"free_balance":0,"free_grants":null}}`, `{"data":{"total_balance":0,"prepaid_balance":0,"free_balance":0,"free_grants":[{"amount":null}]}}`, `{"data":{"total_balance":-1,"prepaid_balance":-1,"free_balance":0,"free_grants":[]}}`, `{"data":{"total_balance":0,"prepaid_balance":0,"free_balance":0,"free_grants":[],"error":"denied"}}`}, false},
	{"sendbird-organization-api-token", verifySendbirdOrganization, "secret", "https://gate.sendbird.com/api/v2/organization_members/predefined_roles", "SENDBIRDORGANIZATIONAPITOKEN", "secret",
		[]string{`[]`, `["OWNER","ADMIN","DEFAULT"]`},
		[]string{`{}`, `[null]`, `[{}]`, `[""]`, `{"detail":"Invalid token header"}`, `{"applications":[{"api_token":"private-metadata"}]}`}, false},
	{"atera-api-key", verifyAtera, "secret", "https://app.atera.com/api/v3/agents?page=1&itemsInPage=1", "X-API-KEY", "secret",
		[]string{`{"TotalItemCount":0,"Items":[]}`, `{"TotalItemCount":1,"Items":[{"AgentID":1,"MachineID":"private-metadata","Online":false}],"NextLink":"https://other.invalid"}`},
		[]string{`{"TotalItemCount":0,"Items":null}`, `{"TotalItemCount":"1","Items":[{"AgentID":1}]}`, `{"TotalItemCount":1,"Items":[{"AgentID":"1"}]}`, `{"TotalItemCount":1,"Items":[{"AgentID":1,"error":"denied"}]}`}, false},
	{"bombbomb-api-key", verifyBombBomb, "jwt-secret", "https://app.bombbomb.com/app/api/api.php", "", "",
		[]string{`{"status":"success","info":{"userId":"user","clientId":"client","jwtoken":"private-metadata"}}`, `{"status":"success","info":{"user_id":1,"client_id":2}}`},
		[]string{`{"status":"success"}`, `{"status":"failure","info":{"userId":"user","clientId":"client"}}`, `{"status":"success","info":{"userId":null,"clientId":"client"}}`, `{"status":"success","info":{"userId":"user","clientId":"client","error":"denied"}}`}, true},
	{"ngc-api-key", verifyNGC, strings.Repeat("A", 40), "https://authn.nvidia.com/token?service=ngc", "", "",
		[]string{`{"token":"private-metadata","expires_in":3600}`, `{"token":"private-metadata"}`},
		[]string{`{}`, `{"token":null}`, `{"token":"token","expires_in":"3600"}`, `{"token":"token","expires_in":0}`, `{"token":"token","error":"denied"}`}, true},
	{"nvapi-key", verifyNVAPI, "nvapi-" + strings.Repeat("A", 64), "https://api.ngc.nvidia.com/v3/keys/get-caller-info", "", "",
		[]string{`{"requestStatus":{"statusCode":"SUCCESS"},"type":"SERVICE_KEY","orgName":"org","products":[],"user":null}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"PERSONAL_KEY","orgName":"org","products":["NGC"],"userId":"id","user":{"roles":[],"email":"private-metadata"}}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"PERSONAL_KEY","orgName":"org","products":[],"userId":"id"}`},
		[]string{`{"id":"id"}`, `{"requestStatus":{"statusCode":"FORBIDDEN"},"type":"SERVICE_KEY","orgName":"org","products":[]}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"PERSONAL_KEY","orgName":"org","products":[]}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"SERVICE_KEY","orgName":"org","products":null}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"UNKNOWN","orgName":"org","products":[]}`, `{"requestStatus":{"statusCode":"SUCCESS"},"type":"PERSONAL_KEY","orgName":"org","products":[],"userId":"id","user":{"error":"denied"}}`}, true},
	{"prodpad-api-key", verifyProdPad, "secret", "https://api.prodpad.com/v1/tags", "Authorization", "Bearer secret",
		[]string{`[]`, `[{"id":"1","tag":"private-metadata","created_at":null}]`},
		[]string{`{}`, `[{}]`, `[{"id":1,"tag":"tag"}]`, `[{"id":"1","tag":"tag","error":"denied"}]`}, false},
	{"vyte-api-key", verifyVyte, "secret", "https://api.vyte.in/v2/events?limit=1", "Authorization", "secret",
		[]string{`[]`, `[{"_id":"id","title":"","confirmed":{"flag":false,"updated_at":null},"messages":[{"body":"private-metadata"}]}]`},
		[]string{`{}`, `[{}]`, `[{"_id":"id","title":null,"confirmed":{"flag":true}}]`, `[{"_id":"id","title":"title","confirmed":{"flag":null}}]`, `[{"_id":"id","title":"title","confirmed":{"flag":true,"error":"denied"}}]`}, false},
	{"alienvault-otx-api-key", verifyAlienVaultOTX, "secret", "https://otx.alienvault.com/api/v1/user/me", "X-OTX-API-KEY", "secret",
		[]string{`{"user_id":2,"username":"private-metadata","pulse_count":0,"avatar_url":null}`},
		[]string{`{}`, `{"id":2,"username":"name"}`, `{"user_id":"2","username":"name"}`, `{"user_id":2,"username":null}`, `{"detail":"Authentication required"}`}, false},
}

func checkBatch29Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch29Contracts[index]
	endpoint, method := tc.endpoint, http.MethodGet
	if tc.id == "complyadvantage-api-key" && call < 3 {
		endpoint = "https://" + []string{"api.complyadvantage.com", "api.us.complyadvantage.com", "api.ap.complyadvantage.com"}[call] + "/users"
	} else if call > 0 {
		t.Fatal("unexpected extra request")
	}
	if tc.id == "nvapi-key" || tc.id == "bombbomb-api-key" {
		method = http.MethodPost
	}
	if req.Method != method || req.URL.String() != endpoint || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
	}
	if tc.header != "" && req.Header.Get(tc.header) != tc.value {
		t.Fatal("wrong authentication")
	}
	switch tc.id {
	case "ngc-api-key":
		user, pass, ok := req.BasicAuth()
		if !ok || user != "$oauthtoken" || pass != tc.secret {
			t.Fatal("wrong legacy authentication")
		}
	case "nvapi-key":
		if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || req.Header.Get("Authorization") != "" {
			t.Fatal("wrong scoped authentication")
		}
		if err := req.ParseForm(); err != nil || len(req.PostForm) != 1 || req.PostForm.Get("credentials") != tc.secret {
			t.Fatal("wrong caller-info body")
		}
	case "bombbomb-api-key":
		if req.Header.Get("Authorization") != "" {
			t.Fatal("unexpected bearer authentication")
		}
		if err := req.ParseMultipartForm(4096); err != nil {
			t.Fatal(err)
		}
		defer req.MultipartForm.RemoveAll()
		if len(req.MultipartForm.File) != 0 || len(req.MultipartForm.Value) != 2 || req.FormValue("method") != "ValidateJsonWebToken" || req.FormValue("jwt") != tc.secret {
			t.Fatal("wrong JWT validation request")
		}
	default:
		if tc.header != "Authorization" && req.Header.Get("Authorization") != "" {
			t.Fatal("unexpected authorization")
		}
	}
	if method == http.MethodGet && req.Body != nil && req.Body != http.NoBody {
		t.Fatal("unexpected GET body")
	}
}

func TestTwentyNinthBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[d.Info().ID] = r
		}
	}
	if len(batch29Contracts) != 11 {
		t.Fatal("expected eleven supported contracts plus two blocked contracts")
	}
	for index, tc := range batch29Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.authOnly {
				safety = VerificationSafetyAuthOnly
			}
			if d.Info().VerificationSafety != safety {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `null`, `"ok"`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-metadata"}`)
			// Inject provider failures into otherwise successful objects and records.
			if tc.id != "sendbird-organization-api-token" {
				for _, field := range []string{"error", "error_code", "errors"} {
					body := tc.valid[len(tc.valid)-1]
					var p identityPayload
					var array []identityPayload
					isArray := strings.HasPrefix(body, "[")
					if isArray {
						if err := json.Unmarshal([]byte(body), &array); err != nil || len(array) != 1 {
							t.Fatal("bad fixture")
						}
						p = array[0]
					} else if err := json.Unmarshal([]byte(body), &p); err != nil {
						t.Fatal(err)
					}
					p[field] = json.RawMessage(`"private-metadata"`)
					var encoded []byte
					if isArray {
						encoded, _ = json.Marshal(array)
					} else {
						encoded, _ = json.Marshal(p)
					}
					bodies = append(bodies, string(encoded))
				}
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch29Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: tc.secret, Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want, wantCalls := VerificationUnknown, 1
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if tc.id == "complyadvantage-api-key" && (status == 401 || status == 403) {
						wantCalls = 3
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestTwentyNinthBatchFailuresAndCaps(t *testing.T) {
	for _, tc := range batch29Contracts {
		t.Run(tc.id, func(t *testing.T) {
			for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if failure != nil {
						return nil, failure
					}
					return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
				})}
				if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret); r.Status != VerificationUnknown || calls != 1 || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("%+v calls=%d", r, calls)
				}
			}
			for _, status := range []int{200, 401, 403} {
				calls := 0
				// A complete success prefix must not authenticate an oversized body.
				body := tc.valid[0] + strings.Repeat(" ", maxVerificationResponseBytes)
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret); r.Status != VerificationUnknown || r.ErrorCategory != "provider_response" || calls != 1 || r.Response != "" {
					t.Fatalf("oversize: %+v calls=%d", r, calls)
				}
			}
		})
	}
}

func TestTwentyNinthBatchNGCFamilies(t *testing.T) {
	for _, verify := range []Verifier{verifyNGC, verifyNVAPI} {
		calls := 0
		key := "nvapi-" + strings.Repeat("A", 64)
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.String() != "https://api.ngc.nvidia.com/v3/keys/get-caller-info" || req.Method != "POST" || req.Header.Get("Authorization") != "" {
				t.Fatal("wrong family route")
			}
			if err := req.ParseForm(); err != nil || req.PostForm.Get("credentials") != key {
				t.Fatal("wrong credentials")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(batch29Contracts[7].valid[0]))}, nil
		})}
		if r := verify(WithVerificationHTTPClient(context.Background(), client), key); r.Status != VerificationVerified || r.Response != "" || calls != 1 {
			t.Fatalf("%+v calls=%d", r, calls)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unsupported format sent"); return nil, nil })}
	for _, tc := range []struct {
		verify Verifier
		key    string
	}{{verifyNGC, "nvapi-invalid"}, {verifyNGC, "invalid"}, {verifyNVAPI, strings.Repeat("A", 64)}} {
		if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.key); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("%+v", r)
		}
	}
}

func TestTwentyNinthBatchBlockedContracts(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unproven contract sent credentials")
		return nil, nil
	})}
	for _, d := range DefaultRegistry() {
		if d.Info().ID != "cloudplan-api-key" && d.Info().ID != "cloverly-api-key" {
			continue
		}
		r := d.(RegexDetector)
		if r.Info().VerificationSafety != VerificationSafetyUnreviewed {
			t.Fatal("blocked contract promoted")
		}
		candidate := Candidate{Secret: "secret", Verifier: r.Verifier, VerificationSafety: r.Info().VerificationSafety}
		ctx := WithVerificationHTTPClient(context.Background(), client)
		if result := candidate.Verify(ctx); result.Status != VerificationNotAttempted || result.ErrorCategory != "unreviewed_verification_disabled" {
			t.Fatalf("%+v", result)
		}
		if result := candidate.VerifyWithPolicy(ctx, VerificationPolicy{AllowUnreviewed: true, AllowUnsafe: true}); result.Status != VerificationUnknown || result.ErrorCategory != "provider_contract" || result.Response != "" {
			t.Fatalf("%+v", result)
		}
	}
}

func TestTwentyNinthBatchRegionalCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			checkBatch29Request(t, 0, calls, req)
			calls++
			status, body := 403, `{"error":"region or scope"}`
			if calls == 3 {
				status, body = 200, batch29Contracts[0].valid[0]
			}
			if cancelled {
				cancel()
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		r := verifyComplyAdvantage(WithVerificationHTTPClient(ctx, client), "secret")
		cancel()
		if cancelled {
			if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
				t.Fatalf("%+v calls=%d", r, calls)
			}
		} else if calls != 3 || r.Status != VerificationVerified || r.Response != "" {
			t.Fatalf("%+v calls=%d", r, calls)
		}
	}
}

func TestTwentyNinthBatchBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	for _, tc := range []struct{ id, prefix, secret string }{
		{"complyadvantage-api-key", "comply_advantage key", strings.Repeat("A", 31) + "-"},
		{"sourcegraph-cody-token", "", "slk_" + strings.Repeat("a", 64)},
		{"twitter-bearer-token", "TWITTER_BEARER_TOKEN", "AAAA" + strings.Repeat("A", 82) + "%2F"},
		{"sendbird-organization-api-token", "sendbird organization_api_token", strings.Repeat("a", 24)},
		{"atera-api-key", "atera key", strings.Repeat("A", 31) + "-"},
		{"bombbomb-api-key", "bomb_bomb key", "eyJ" + strings.Repeat("A", 20) + ".eyJ" + strings.Repeat("B", 20) + "." + strings.Repeat("C", 20) + "-"},
		{"cloudplan-api-key", "cloudplan key", strings.Repeat("A", 31) + "-"},
		{"cloverly-api-key", "cloverly key", strings.Repeat("a", 27) + "_"},
		{"ngc-api-key", "ngc key", strings.Repeat("A", 40)},
		{"ngc-api-key", "nvidia key", "nvapi-" + strings.Repeat("A", 64)},
		{"nvapi-key", "", "nvapi-" + strings.Repeat("A", 63) + "-"},
		{"prodpad-api-key", "prodpad key", strings.Repeat("a", 64)},
		{"vyte-api-key", "vyte key", strings.Repeat("a", 50)},
		{"alienvault-otx-api-key", "levelblue key", strings.Repeat("a", 64)},
	} {
		got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + `"`))
		if len(got) != 1 || got[0].Secret != tc.secret {
			t.Fatalf("%s lost credential: %+v", tc.id, got)
		}
		for _, suffix := range []string{"/suffix", "+suffix"} {
			// X tokens legitimately contain these characters; overlong tokens must
			// still not be accepted as a truncated match.
			if tc.id == "twitter-bearer-token" {
				suffix = strings.Repeat("A", 400)
			}
			if got := registry[tc.id].Detect([]byte(tc.prefix + `="` + tc.secret + suffix + `"`)); len(got) != 0 {
				t.Fatalf("%s truncated token", tc.id)
			}
		}
	}
}

func TestVerificationResponseCapRejectsCompleteJSONPrefix(t *testing.T) {
	for _, size := range []int{maxVerificationResponseBytes - 1, maxVerificationResponseBytes, maxVerificationResponseBytes + 1} {
		body := `{}` + strings.Repeat(" ", size-2)
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		ctx := WithVerificationHTTPClient(context.Background(), client)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.invalid/metadata", nil)
		r := verifyHTTPRequest(ctx, req)
		if size <= maxVerificationResponseBytes {
			if r.Status != VerificationVerified {
				t.Fatalf("size=%d result=%+v", size, r)
			}
		} else if r.Status != VerificationUnknown || r.ErrorCategory != "provider_response" {
			t.Fatalf("oversized success prefix authenticated: %+v", r)
		}
	}
}
