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

var batch15Contracts = []struct {
	id                       string
	verify                   Verifier
	endpoint, header, prefix string
	valid, invalid           []string
}{
	{"restpack-htmltopdf-api-key", verifyRestpack, "https://restpack.io/api/html2pdf/usage", "X-Access-Token", "",
		[]string{`{"from":"2026-09-01","to":"2026-09-25","limit":0,"total":0,"days":[]}`, `{"from":"2026-09-01","to":"2026-09-25","limit":1000,"total":5,"days":[{"day":"2026-09-24","count":5}]}`},
		[]string{`{"limit":100}`, `{"usage":10}`, `{"from":"a","to":"b","limit":1,"total":0,"days":null}`, `{"from":"a","to":"b","limit":1,"total":0,"days":[{"day":"today","count":null}]}`}},
	{"restpack-screenshot-api-key", verifyRestpackScreenshot, "https://restpack.io/api/screenshot/usage", "X-Access-Token", "",
		[]string{`{"from":"2026-09-01","to":"2026-09-25","limit":100,"total":0,"days":[]}`},
		[]string{`{"remaining":100}`, `{"limit":100}`, `{"from":"a","to":"b","limit":1,"total":0,"days":[null]}`, `{"from":"a","to":"b","limit":1,"total":0,"days":[{"day":"today","count":-1}]}`}},
	{"pdfshift-api-key", verifyPDFShift, "https://api.pdfshift.io/v3/credits/usage", "X-API-Key", "",
		[]string{`{"success":true,"credits":{"base":0,"remaining":0,"total":0,"used":0}}`, `{"success":true,"credits":{"base":100,"remaining":99,"total":100,"used":1}}`},
		[]string{`{"success":false,"credits":{"base":0,"remaining":0,"total":0,"used":0}}`, `{"success":true,"credits":{"base":0,"remaining":0,"total":0,"used":null}}`, `{"success":true,"credits":{"base":0,"remaining":0,"total":0,"used":-1}}`, `{"success":true,"credits":{"base":0,"remaining":0,"total":0,"used":0,"error":"denied"}}`}},
	{"convertkit-api-secret", verifyConvertKit, "https://api.convertkit.com/v3/account", "query", "",
		[]string{`{"name":"private-metadata","primary_email_address":"owner@example.com"}`},
		[]string{`{"id":1}`, `{"name":"team","email":"owner@example.com"}`}},
	{"lemlist-api-key", verifyLemlist, "https://api.lemlist.com/api/team", "basic-password", "",
		[]string{`{"_id":"tea_1","name":"team","hooks":[{"targetUrl":"private-metadata"}]}`},
		[]string{`{"id":"tea_1","name":"team"}`, `{"_id":"tea_1"}`}},
	{"squarespace-api-key", verifySquarespace, "https://api.squarespace.com/1.0/authorization/website", "Authorization", "Bearer ",
		[]string{`{"id":"site-1","siteId":"site-1","title":"private-metadata"}`},
		[]string{`{"id":"site-1"}`, `{"siteId":"site-1"}`}},
	{"helpscout-api-key", verifyHelpScout, "https://docsapi.helpscout.net/v1/collections", "basic-user", "X",
		[]string{`{"collections":{"items":[]}}`, `{"collections":{"items":[{"id":"c1","siteId":"s1","name":"private-metadata"}],"pages":20}}`},
		[]string{`{"collections":[]}`, `{"collections":{"items":null}}`, `{"collections":{"items":[{}]}}`, `{"collections":{"items":[],"error":"denied"}}`, `{"collections":{"items":[{"id":"c1","siteId":"s1","name":"collection","error":"denied"}]}}`}},
	{"aiven-token", verifyAiven, "https://api.aiven.io/v1/project", "Authorization", "aivenv1 ",
		[]string{`{"projects":[]}`, `{"projects":[{"project_name":"private-metadata"}],"errors":[]}`},
		[]string{`{"projects":null}`, `{"projects":[null]}`, `{"projects":[{}]}`, `{"projects":[{"project_name":"name","error":"denied"}]}`}},
	{"sparkpost-api-key", verifySparkPost, "https://api.sparkpost.com/api/v1/account", "Authorization", "",
		[]string{`{"results":{"customer_id":123,"company_name":"private-metadata","status":"active"}}`},
		[]string{`{"results":{}}`, `{"results":{"customer_id":0,"company_name":"name","status":"active"}}`, `{"results":{"customer_id":123,"company_name":"name","status":"active","errors":[{"message":"denied"}]}}`}},
	{"miro-api-token", verifyMiro, "https://api.miro.com/v1/oauth-token", "Authorization", "Bearer ",
		[]string{`{"type":"oAuthToken","user":{"type":"user","id":"user1","name":"private-metadata"},"scopes":[]}`, `{"type":"oAuthToken","user":{"type":"user","id":"user1"},"scopes":["boards:read"]}`},
		[]string{`{"type":"oAuthToken"}`, `{"type":"oAuthToken","user":{"type":"team","id":"user1"},"scopes":[]}`, `{"type":"oAuthToken","user":{"type":"user","id":"user1"},"scopes":null}`, `{"type":"oAuthToken","user":{"type":"user","id":"user1"},"scopes":[null]}`, `{"type":"oAuthToken","user":{"type":"user","id":"user1","error":"denied"},"scopes":[]}`}},
}

func TestFifteenthBatchContracts(t *testing.T) {
	if len(batch15Contracts) < 10 {
		t.Fatal("expected at least ten verifiers")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch15Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d, ok := registry[tc.id]
			wantSafety := VerificationSafetyReadOnly
			if tc.id == "miro-api-token" {
				wantSafety = VerificationSafetyAuthOnly
			}
			if !ok || d.Info().VerificationSafety != wantSafety {
				t.Fatal("missing safety promotion")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `[]`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-metadata"}`)
			for _, field := range []string{"error", "error_code", "errors"} {
				var p map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
					t.Fatal(err)
				}
				p[field] = json.RawMessage(`"private-metadata"`)
				body, _ := json.Marshal(p)
				bodies = append(bodies, string(body))
			}
			// Required fields must not authenticate when missing, null or of another type.
			var valid map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.valid[0]), &valid); err != nil {
				t.Fatal(err)
			}
			for field, original := range valid {
				if field == "hooks" {
					continue
				}
				for _, bad := range []string{"", `null`, `false`, `""`, `123.5`} {
					if bad == "" {
						delete(valid, field)
					} else {
						valid[field] = json.RawMessage(bad)
					}
					body, _ := json.Marshal(valid)
					bodies = append(bodies, string(body))
				}
				valid[field] = original
			}
			secret := "test-secret+/?=&private-metadata"
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						endpoint := tc.endpoint
						if calls == 1 && tc.id == "sparkpost-api-key" {
							endpoint = "https://api.eu.sparkpost.com/api/v1/account"
						}
						actual := *req.URL
						actual.RawQuery = ""
						if calls > 1 || actual.String() != endpoint || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						calls++
						switch tc.header {
						case "query":
							if req.URL.Query().Get("api_secret") != secret || len(req.URL.Query()) != 1 || req.Header.Get("Authorization") != "" {
								t.Fatal("incorrect escaped query authentication")
							}
						case "basic-user", "basic-password":
							u, p, ok := req.BasicAuth()
							wantU, wantP := secret, tc.prefix
							if tc.header == "basic-password" {
								wantU, wantP = "", secret
							}
							if !ok || u != wantU || p != wantP {
								t.Fatal("incorrect Basic authentication")
							}
						default:
							if req.Header.Get(tc.header) != tc.prefix+secret {
								t.Fatal("incorrect authentication header")
							}
						}
						if tc.header != "query" && req.URL.RawQuery != "" {
							t.Fatal("unexpected query")
						}
						if tc.id == "pdfshift-api-key" && req.Header.Get("Authorization") != "" {
							t.Fatal("legacy PDFShift authentication used")
						}
						if tc.id == "squarespace-api-key" && req.Header.Get("User-Agent") != "secret-sniffer credential verifier" {
							t.Fatal("missing required User-Agent")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					wantCalls := 1
					if tc.id == "sparkpost-api-key" && (status == 401 || status == 403) {
						wantCalls = 2
					}
					if r.Status != want || calls != wantCalls || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestFifteenthBatchTransport(t *testing.T) {
	for _, tc := range batch15Contracts {
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
		})
	}
}

func TestFifteenthBatchQuotaFieldTypes(t *testing.T) {
	for _, tc := range batch15Contracts[:3] {
		t.Run(tc.id, func(t *testing.T) {
			fields := []string{"limit", "total"}
			if tc.id == "pdfshift-api-key" {
				fields = []string{"base", "remaining", "total", "used"}
			}
			for _, field := range fields {
				for _, bad := range []string{"", `null`, `"0"`, `false`, `-1`, `0.5`, `9223372036854775808`} {
					var p map[string]json.RawMessage
					if err := json.Unmarshal([]byte(tc.valid[0]), &p); err != nil {
						t.Fatal(err)
					}
					target := p
					if tc.id == "pdfshift-api-key" {
						target = make(map[string]json.RawMessage)
						if err := json.Unmarshal(p["credits"], &target); err != nil {
							t.Fatal(err)
						}
					}
					if bad == "" {
						delete(target, field)
					} else {
						target[field] = json.RawMessage(bad)
					}
					if tc.id == "pdfshift-api-key" {
						p["credits"], _ = json.Marshal(target)
					}
					body, _ := json.Marshal(p)
					client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
					})}
					if r := tc.verify(WithVerificationHTTPClient(context.Background(), client), "test-secret"); r.Status != VerificationUnknown || r.Response != "" {
						t.Fatalf("field=%s value=%s result=%+v", field, bad, r)
					}
				}
			}
		})
	}
}

func TestFifteenthBatchSparkPostFallback(t *testing.T) {
	for _, cancelAfterFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			status, body := 403, `{"errors":[{"message":"permission denied for scope"}]}`
			if calls == 2 {
				if req.URL.Host != "api.eu.sparkpost.com" {
					t.Fatal("incorrect fallback")
				}
				status, body = 200, `{"results":{"customer_id":123,"company_name":"company","status":"active"}}`
			}
			if cancelAfterFirst {
				cancel()
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		r := verifySparkPost(WithVerificationHTTPClient(ctx, client), "test-secret")
		if cancelAfterFirst {
			if calls != 1 || r.Status != VerificationUnknown || r.ErrorCategory != "cancelled" {
				t.Fatalf("calls=%d result=%+v", calls, r)
			}
		} else if calls != 2 || r.Status != VerificationVerified || r.Response != "" {
			t.Fatalf("calls=%d result=%+v", calls, r)
		}
	}
}
