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

var batch14Contracts = []struct {
	id                          string
	verify                      Verifier
	hosts                       []string
	path, query, header, prefix string
	valid, invalid              []string
}{
	{"weightsandbiases-api-key", verifyWeightsAndBiases, []string{"api.wandb.ai"}, "/graphql", "", "basic", "api",
		[]string{`{"data":{"viewer":{"id":"private-metadata"}}}`, `{"data":{"viewer":{"id":"viewer-1"}},"errors":[]}`},
		[]string{`{"data":{"viewer":null}}`, `{"data":{"viewer":{"id":1}}}`, `{"data":{"me":{"id":"viewer-1"}}}`, `{"data":{"viewer":{"id":"viewer-1"}},"errors":[{"message":"permission denied"}]}`}},
	{"posthog-personal-api-key", verifyPostHog, []string{"us.posthog.com", "eu.posthog.com"}, "/api/users/@me/", "", "Authorization", "Bearer ",
		[]string{`{"uuid":"user-1","email":"private-metadata"}`},
		[]string{`{"uuid":"user-1"}`, `{"uuid":null,"email":"email"}`}},
	{"chroma-cloud-api-key", verifyChromaCloud, []string{"api.trychroma.com", "europe-west1.gcp.trychroma.com"}, "/api/v2/auth/identity", "", "X-Chroma-Token", "",
		[]string{`{"user_id":"user-1","tenant":"private-metadata","databases":[]}`, `{"user_id":"user-1","tenant":"tenant-1","databases":["*"]}`},
		[]string{`{"user_id":"user-1"}`, `{"user_id":"user-1","tenant":"tenant-1","databases":null}`, `{"user_id":"user-1","tenant":"tenant-1","databases":[null]}`, `{"user_id":"user-1","tenant":"tenant-1","databases":[1]}`}},
	{"singlestore-api-key", verifySingleStore, []string{"api.singlestore.com"}, "/v2/organizations/current", "", "Authorization", "Bearer ",
		[]string{`{"orgID":"org-1","name":"private-metadata"}`},
		[]string{`{"id":"org-1","name":"name"}`, `{"orgID":"org-1"}`, `{"orgID":false,"name":"name"}`}},
	{"locationiq-api-key", verifyLocationIQ, []string{"us1.locationiq.com", "eu1.locationiq.com"}, "/v1/balance", "query-key", "", "",
		[]string{`{"status":"ok","balance":{"day":0,"bonus":0}}`, `{"status":"ok","balance":{"day":30000,"bonus":10}}`},
		[]string{`{"status":"error","balance":{"day":0,"bonus":0}}`, `{"status":"ok","balance":{"day":0}}`, `{"status":"ok","balance":{"day":null,"bonus":0}}`, `{"status":"ok","balance":{"day":"0","bonus":0}}`, `{"status":"ok","balance":{"day":-1,"bonus":0}}`}},
	{"oanda-api-token", verifyOANDA, []string{"api-fxpractice.oanda.com", "api-fxtrade.oanda.com"}, "/v3/accounts", "", "Authorization", "Bearer ",
		[]string{`{"accounts":[]}`, `{"accounts":[{"id":"private-metadata","tags":[]}]}`},
		[]string{`{"accounts":null}`, `{"accounts":[{}]}`, `{"accounts":[{"id":1}]}`, `{"accounts":[],"errorCode":"unauthorized"}`}},
	{"transferwise-api-token", verifyWise, []string{"api.wise.com", "api.wise-sandbox.com"}, "/2026Q3/me", "", "Authorization", "Bearer ",
		[]string{`{"id":101,"email":"private-metadata","active":true}`},
		[]string{`{"id":101}`, `{"id":0,"email":"email"}`, `{"id":null,"email":"email"}`}},
	{"imagekit-private-key", verifyImageKit, []string{"api.imagekit.io"}, "/v1/files", "limit=1&type=file", "basic", "",
		[]string{`[]`, `[{"fileId":"file-1","name":"private-metadata"}]`},
		[]string{`{"files":[]}`, `[null]`, `[{}]`, `[{"fileId":false,"name":"file"}]`, `[{"fileId":"file-1","name":"file","error":"permission denied"}]`}},
	{"lob-api-key", verifyLob, []string{"api.lob.com"}, "/v1/addresses", "limit=1", "basic", "",
		[]string{`{"object":"list","data":[]}`, `{"object":"list","data":[{"object":"address","id":"adr_123","name":"private-metadata"}],"next_url":"https://other.invalid/"}`},
		[]string{`{"data":[]}`, `{"object":"list","data":null}`, `{"object":"list","data":[{"object":"postcard","id":"psc_123"}]}`, `{"object":"list","data":[{}]}`}},
	{"qase-api-token", verifyQase, []string{"api.qase.io"}, "/v1/project", "limit=1&offset=0", "Token", "",
		[]string{`{"status":true,"result":{"entities":[]}}`, `{"status":true,"result":{"entities":[{"code":"PRJ","title":"private-metadata"}]}}`},
		[]string{`{"result":{"entities":[]}}`, `{"status":false,"result":{"entities":[]}}`, `{"status":true,"result":{"entities":null}}`, `{"status":true,"result":{"entities":[{}]}}`, `{"status":true,"result":{"entities":[]},"errorMessage":"permission denied"}`}},
}

func TestFourteenthBatchContractsAndResponses(t *testing.T) {
	if len(batch14Contracts) < 10 {
		t.Fatal("batch must cover at least ten verifiers")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch14Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d, ok := registry[tc.id]
			if !ok || d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("missing read-only promotion")
			}
			secret := strings.Repeat("a", 64)
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 403, 404, 429, 500, 503} {
				bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
				bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-metadata"}`)
				if tc.id != "imagekit-private-key" {
					for _, field := range []string{"error", "error_code", "errors"} {
						var p map[string]json.RawMessage
						if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
							t.Fatal(err)
						}
						p[field] = json.RawMessage(`"private-metadata"`)
						body, _ := json.Marshal(p)
						bodies = append(bodies, string(body))
					}
				}
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if calls >= len(tc.hosts) || req.URL.Host != tc.hosts[calls] || req.URL.Scheme != "https" || req.URL.Path != tc.path || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
						}
						calls++
						if tc.query == "query-key" {
							if req.URL.Query().Get("key") != secret || req.URL.Query().Get("format") != "json" || len(req.URL.Query()) != 2 {
								t.Fatal("incorrect query authentication")
							}
						} else if req.URL.RawQuery != tc.query {
							t.Fatalf("query=%s", req.URL.RawQuery)
						}
						if tc.header == "basic" {
							u, p, ok := req.BasicAuth()
							wantU, wantP := secret, ""
							if tc.prefix == "api" {
								wantU, wantP = "api", secret
							}
							if !ok || u != wantU || p != wantP {
								t.Fatal("incorrect basic authentication")
							}
						} else if tc.header != "" && req.Header.Get(tc.header) != tc.prefix+secret {
							t.Fatal("incorrect authentication header")
						}
						if tc.id == "weightsandbiases-api-key" {
							query, _ := io.ReadAll(req.Body)
							if req.Method != http.MethodPost || string(query) != `{"query":"query { viewer { id } }"}` || req.Header.Get("Content-Type") != "application/json" {
								t.Fatalf("unexpected GraphQL query: %s", query)
							}
						} else if req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) {
							t.Fatal("expected bodyless GET")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					candidate := Candidate{Secret: secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}
					r := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
					if status == 401 || status == 403 {
						wantCalls = len(tc.hosts)
					}
					if r.Status != want || r.Response != "" || calls != wantCalls || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestFourteenthBatchFallbackAndTransport(t *testing.T) {
	for _, tc := range batch14Contracts {
		t.Run(tc.id, func(t *testing.T) {
			secret := strings.Repeat("a", 64)
			for _, failure := range []error{errors.New("private-metadata"), context.Canceled, context.DeadlineExceeded, nil} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					if failure != nil {
						return nil, failure
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), secret)
				if r.Status != VerificationUnknown || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-metadata") {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
			if len(tc.hosts) < 2 {
				return
			}
			for _, cancelAfterFirst := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if calls >= len(tc.hosts) || req.URL.Host != tc.hosts[calls] {
						t.Fatalf("unexpected host: %s", req.URL)
					}
					status, body := 401, `{}`
					if calls == 1 {
						status, body = 200, tc.valid[0]
					}
					calls++
					if cancelAfterFirst {
						cancel()
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				r := tc.verify(WithVerificationHTTPClient(ctx, client), secret)
				if cancelAfterFirst {
					if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
						t.Fatalf("calls=%d result=%+v", calls, r)
					}
				} else if calls != 2 || r.Status != VerificationVerified || r.Response != "" {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
		})
	}
}

func TestFourteenthBatchSingleStoreUnsupportedMakesNoRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported credential made a request")
		return nil, errors.New("unexpected")
	})}
	for _, secret := range []string{"database-password", strings.Repeat("z", 64), strings.Repeat("a", 63)} {
		if r := verifySingleStore(WithVerificationHTTPClient(context.Background(), client), secret); r.Status != VerificationUnsupported {
			t.Fatalf("result=%+v", r)
		}
	}
}
