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

var batch22Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	valid, invalid []string
}{
	{"buildkite-token", verifyBuildkite, []string{"https://api.buildkite.com/v2/access-token"},
		[]string{`{"uuid":"token-id","created_at":"date","scopes":[]}`, `{"uuid":"token-id","created_at":"date","scopes":["read_build"],"user":null}`},
		[]string{`{"uuid":"id","created_at":"date","scopes":null}`, `{"uuid":"id","created_at":"date","scopes":[null]}`, `{"uuid":"id","scopes":[]}`}},
	{"increase-api-key", verifyIncrease, []string{"https://api.increase.com/programs?limit=1", "https://sandbox.increase.com/programs?limit=1"},
		[]string{`{"data":[],"next_cursor":null}`, `{"data":[{"type":"program","id":"p1","name":"name","lending":null}],"next_cursor":"next"}`},
		[]string{`{"data":null}`, `{"data":[{"id":"p1","name":"name","type":"account"}]}`, `{"data":[{}]}`}},
	{"persona-api-key", verifyPersona, []string{"https://api.withpersona.com/api/v1/inquiries?page%5Bsize%5D=1&fields%5Binquiry%5D=status"},
		[]string{`{"data":[],"links":{"next":null}}`, `{"data":[{"type":"inquiry","id":"inq_1","attributes":{"status":"new-status"}}],"links":{"next":"https://other.invalid"}}`},
		[]string{`{"data":null}`, `{"data":[{"type":"inquiry","id":"inq_1","attributes":{"status":null}}]}`, `{"data":[{"type":"inquiry","id":"inq_1","attributes":{"status":"pending","error":"denied"}}]}`}},
	{"circle-api-key", verifyCircle, []string{"https://api.circle.com/v1/configuration", "https://api-sandbox.circle.com/v1/configuration"},
		[]string{`{"data":{"payments":{"masterWalletId":"212000"}}}`},
		[]string{`{"data":{"payments":{"masterWalletId":212000}}}`, `{"data":{"payments":{}}}`, `{"data":{"payments":{"masterWalletId":"212000"}},"code":401}`, `{"data":{"payments":{"masterWalletId":"212000","error":"denied"}}}`}},
	{"cockroachcloud-api-key", verifyCockroachCloud, []string{"https://cockroachlabs.cloud/api/v1/clusters?pagination.limit=1"},
		[]string{`{"clusters":[]}`, `{"clusters":[{"id":"id","name":"name","state":"CREATING","account_id":""}]}`},
		[]string{`{"clusters":null}`, `{"clusters":[{"id":"id","name":"name"}]}`, `{"clusters":[],"code":7}`}},
	{"polar-access-token", verifyPolar, []string{"https://api.polar.sh/v1/organizations/?page=1&limit=1", "https://sandbox-api.polar.sh/v1/organizations/?page=1&limit=1"},
		[]string{`{"items":[],"pagination":{"total_count":0,"max_page":0}}`, `{"items":[{"id":"id","name":"name","slug":"slug","email":null}],"pagination":{"total_count":1,"max_page":1}}`},
		[]string{`{"items":[]}`, `{"items":[],"pagination":{"total_count":"0","max_page":0}}`, `{"items":[],"pagination":{"total_count":0,"max_page":0},"detail":"insufficient scope organizations:read"}`, `{"items":[{}],"pagination":{"total_count":1,"max_page":1}}`}},
	{"wrike-access-token", verifyWrike, []string{"https://www.wrike.com/api/v4/contacts?me=true", "https://app-eu.wrike.com/api/v4/contacts?me=true", "https://app-us2.wrike.com/api/v4/contacts?me=true"},
		[]string{`{"kind":"contacts","data":[]}`, `{"kind":"contacts","data":[{"id":"USER1234","type":"Robot","me":true,"firstName":""}]}`},
		[]string{`{"kind":"contacts","data":[{"id":"USER1234","type":"Person","me":false}]}`, `{"kind":"users","data":[]}`, `{"kind":"contacts","data":[{}]}`, `{"error":"access_forbidden"}`}},
	{"messagebird-api-key", verifyMessageBird, []string{"https://rest.messagebird.com/balance"},
		[]string{`{"payment":"postpaid","type":"euros","amount":0}`, `{"payment":"prepaid","type":"USD","amount":-0.01}`},
		[]string{`{"payment":"prepaid","type":"euros","amount":null}`, `{"payment":"prepaid","type":"euros","amount":"103"}`, `{"payment":"other","type":"euros","amount":0}`, `{"errors":[{"code":2,"description":"incorrect access_key"}]}`}},
	{"imgix-api-token", verifyImgix, []string{"https://api.imgix.com/api/v1/sources?page%5Bnumber%5D=0&page%5Bsize%5D=1&fields%5Bsources%5D=name"},
		[]string{`{"data":[]}`, `{"data":[{"type":"sources","id":"id","attributes":{"name":"name"}}]}`},
		[]string{`{"data":null}`, `{"data":[{"type":"sources","id":"id","attributes":{}}]}`, `{"data":[{"type":"sources","id":"id","attributes":{"name":"name","error":"denied"}}]}`}},
	{"zerobounce-api-key", verifyZeroBounce, []string{"https://api.zerobounce.net/v2/getcredits?api_key=bkua_test-secret"},
		[]string{`{"Credits":0}`, `{"Credits":2375323}`},
		[]string{`{"Credits":null}`, `{"Credits":"1"}`, `{"Credits":1.5}`, `{"Credits":-2}`, `{"Credits":9223372036854775808}`}},
}

func checkBatch22Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch22Contracts[index]
	if call >= len(tc.urls) || req.Method != http.MethodGet || req.URL.String() != tc.urls[call] || (req.Body != nil && req.Body != http.NoBody) {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	auth, accept := "Bearer bkua_test-secret", "application/json"
	if tc.id == "messagebird-api-key" {
		auth = "AccessKey bkua_test-secret"
	}
	if tc.id == "zerobounce-api-key" {
		auth = ""
	}
	if tc.id == "imgix-api-token" {
		accept = "application/vnd.api+json"
	}
	if req.Header.Get("Authorization") != auth || req.Header.Get("Accept") != accept {
		t.Fatal("incorrect request headers")
	}
	if tc.id == "cockroachcloud-api-key" && req.Header.Get("Cc-Version") != "2024-09-16" {
		t.Fatal("missing API version")
	}
}

func TestTwentySecondBatchContracts(t *testing.T) {
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	if len(batch22Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	for index, tc := range batch22Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			safety := VerificationSafetyReadOnly
			if tc.id == "buildkite-token" {
				safety = VerificationSafetyAuthOnly
			}
			if d.Info().VerificationSafety != safety {
				t.Fatal("incorrect safety")
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
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						checkBatch22Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: "bkua_test-secret", Verifier: d.Verifier, VerificationSafety: safety}).Verify(WithVerificationHTTPClient(context.Background(), client))
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

func TestTwentySecondBatchFallbackAndFailures(t *testing.T) {
	for index, tc := range batch22Contracts {
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
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "bkua_test-secret")
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
						checkBatch22Request(t, index, calls, req)
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
					r := tc.verify(WithVerificationHTTPClient(ctx, client), "bkua_test-secret")
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

func TestTwentySecondBatchZeroBounceInvalid(t *testing.T) {
	for _, body := range []string{`{"Credits":-1}`, `{"Credits":-1,"error":"denied"}`, `{"Credits":-1} {}`, `{"Credits":"-1"}`} {
		for _, status := range []int{200, 201, 302, 400, 401, 403, 429, 500} {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			want := VerificationUnknown
			if status == 200 && body == `{"Credits":-1}` {
				want = VerificationUnverified
			}
			if r := verifyZeroBounce(WithVerificationHTTPClient(context.Background(), client), "secret"); r.Status != want || r.Response != "" {
				t.Fatalf("status=%d body=%s result=%+v", status, body, r)
			}
		}
	}
}

func TestTwentySecondBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"", "increase api_key", "persona api_key", "circle api_key", "cockroach api_key", "", "wrike token", "messagebird api_key", "imgix api_key", "zerobounce api_key"}
	secrets := []string{"bkua_" + strings.Repeat("A", 30), strings.Repeat("A", 31) + "-", strings.Repeat("A", 32), strings.Repeat("A", 32), strings.Repeat("A", 31) + "/", "polar_oat_" + strings.Repeat("A", 20) + "-", "ey" + strings.Repeat("A", 333), strings.Repeat("A", 25), strings.Repeat("A", 32), strings.Repeat("A", 32)}
	for i, tc := range batch22Contracts {
		matches := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `"`))
		if len(matches) != 1 || matches[0].Secret != secrets[i] {
			t.Fatalf("%s whole credential lost: %+v", tc.id, matches)
		}
		if matches := registry[tc.id].Detect([]byte(contexts[i] + `="` + secrets[i] + `+suffix"`)); len(matches) != 0 {
			t.Fatalf("%s truncated key", tc.id)
		}
	}
	for _, prefix := range []string{"test_", "live_", ""} {
		if got := registry["messagebird-api-key"].Detect([]byte(`messagebird api_key="` + prefix + strings.Repeat("A", 25) + `"`)); len(got) != 1 || got[0].Secret != prefix+strings.Repeat("A", 25) {
			t.Fatalf("MessageBird %s: %+v", prefix, got)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unsupported token submitted"); return nil, nil })}
	for _, prefix := range []string{"bkpa_", "bkca_"} {
		secret := prefix + strings.Repeat("A", 30)
		if got := registry["buildkite-token"].Detect([]byte(secret)); len(got) != 1 {
			t.Fatal("unsupported family no longer detected")
		}
		if r := verifyBuildkite(WithVerificationHTTPClient(context.Background(), client), secret); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("result=%+v", r)
		}
	}
}
