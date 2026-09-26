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

var batch16Contracts = []struct {
	id             string
	verify         Verifier
	urls           []string
	header, prefix string
	valid, invalid []string
}{
	{"signaturit-api-key", verifySignaturit, []string{"https://api.signaturit.com/v3/signatures.json?limit=1", "https://api.sandbox.signaturit.com/v3/signatures.json?limit=1"}, "Authorization", "Bearer ",
		[]string{`[]`, `[{"id":"sig1","created_at":"2026-09-25","documents":[{"id":"doc1","status":"error","email":"private-metadata"}]}]`},
		[]string{`[{}]`, `[null]`, `[{"id":"sig1","created_at":"date","documents":null}]`, `[{"id":"sig1","created_at":"date","documents":[{}]}]`, `[{"id":1,"created_at":"date","documents":[]}]`, `[{"id":"sig1","created_at":"date","documents":[],"error":"denied"}]`}},
	{"shippo-api-token", verifyShippo, []string{"https://api.goshippo.com/addresses/?results=1"}, "Authorization", "ShippoToken ",
		[]string{`{"results":[]}`, `{"results":[{"object_id":"addr1","object_owner":"private-metadata","is_complete":false}],"next":"https://other.invalid/"}`},
		[]string{`{"results":null}`, `{"results":[{}]}`, `{"results":[{"object_id":1,"object_owner":"owner"}]}`, `{"results":[{"object_id":"addr1","object_owner":"owner","error":"denied"}]}`}},
	{"shipengine-api-key", verifyShipEngine, []string{"https://api.shipengine.com/v1/account/settings", "https://api.eu.shipengine.com/v1/account/settings"}, "API-Key", "",
		[]string{`{"default_label_layout":"4x6"}`, `{"default_label_layout":"Letter"}`},
		[]string{`{"default_label_layout":"A4"}`, `{"default_label_layout":null}`, `{"default_label_layout":true}`}},
	{"easyship-api-token", verifyEasyship, []string{"https://public-api.easyship.com/2024-09/account"}, "Authorization", "Bearer ",
		[]string{`{"account":{"easyship_company_id":"CHK1","name":"private-metadata"}}`, `{"account":{"easyship_company_id":"CHK1","name":"name","payment_sources":[{"card":{"last_four_digits":"1234"}}]}}`},
		[]string{`{"account":{"id":"CHK1","name":"name"}}`, `{"account":{"easyship_company_id":"CHK1"}}`, `{"account":{"easyship_company_id":"CHK1","name":"name","error":"denied"}}`}},
	{"jotform-api-key", verifyJotform, []string{"https://api.jotform.com/user", "https://eu-api.jotform.com/user", "https://hipaa-api.jotform.com/user"}, "APIKEY", "",
		[]string{`{"responseCode":200,"content":{"username":"user1","email":"private-metadata"}}`},
		[]string{`{"content":{"username":"user1","email":"mail"}}`, `{"responseCode":"200","content":{"username":"user1","email":"mail"}}`, `{"responseCode":401,"content":{"username":"user1","email":"mail"}}`, `{"responseCode":200,"content":{"username":"user1","email":null}}`, `{"responseCode":200,"content":{"username":"user1","email":"mail","error":"denied"}}`}},
	{"klipfolio-api-key", verifyKlipfolio, []string{"https://app.klipfolio.com/api/1.0/profile"}, "kf-api-key", "",
		[]string{`{"data":{"id":"user1","email":"private-metadata"}}`, `{"meta":{"success":true},"data":{"id":"user1","email":"mail"}}`},
		[]string{`{"meta":{"success":true}}`, `{"meta":{"success":false},"data":{"id":"user1","email":"mail"}}`, `{"meta":null,"data":{"id":"user1","email":"mail"}}`, `{"data":{"id":"user1"}}`, `{"data":{"id":"user1","email":"mail","error":"denied"}}`}},
	{"moosend-api-key", verifyMoosend, []string{"https://api.moosend.com/v3/lists/1/1.json"}, "query", "",
		[]string{`{"Code":0,"Error":null,"Context":{"MailingLists":[]}}`, `{"Code":0,"Error":"","Context":{"MailingLists":[{"ID":"list1","Name":"private-metadata"}],"Paging":{"PageSize":1}}}`},
		[]string{`{"Context":{"MailingLists":[]}}`, `{"Code":null,"Context":{"MailingLists":[]}}`, `{"Code":"0","Context":{"MailingLists":[]}}`, `{"Code":0,"Error":"USER_NOT_FOUND","Context":{"MailingLists":[]}}`, `{"Code":100,"Error":"USER_NOT_FOUND"}`, `{"Code":0,"Context":{"MailingLists":null}}`, `{"Code":0,"Context":{"MailingLists":[{}]}}`, `{"Code":0,"Context":{"MailingLists":[],"error":"denied"}}`}},
	{"ayrshare-api-key", verifyAyrshare, []string{"https://api.ayrshare.com/api/user"}, "Authorization", "Bearer ",
		[]string{`{"refId":"profile1","email":"private-metadata"}`, `{"refId":"profile1","email":"mail","activeSocialAccounts":[]}`},
		[]string{`{"refId":"profile1","email":null}`, `{"refId":"profile1","email":"mail","status":"error","code":102}`, `{"refId":"profile1","email":"mail","code":144}`}},
	{"dynalist-api-token", verifyDynalist, []string{"https://dynalist.io/api/v1/file/list"}, "body", "",
		[]string{`{"_code":"OK","root_file_id":"root","files":[]}`, `{"_code":"OK","root_file_id":"root","files":[{"id":"root","type":"folder","title":"private-metadata"},{"id":"doc1","type":"document","title":""}]}`},
		[]string{`{"_code":"OK"}`, `{"_code":"OK","root_file_id":"root","files":null}`, `{"_code":"OK","root_file_id":"root","files":[{}]}`, `{"_code":"OK","root_file_id":"root","files":[{"id":"file1","type":"user"}]}`, `{"_code":"InvalidToken","files":[]}`, `{"_code":"LockFail"}`, `{"_code":"TooManyRequests"}`}},
	{"ticket-tailor-api-key", verifyTicketTailor, []string{"https://api.tickettailor.com/v1/overview"}, "basic", "",
		[]string{`{"box_office_name":"private-metadata","period":"four weeks","currency":{"code":"gbp","symbol":"£"},"revenue":0}`},
		[]string{`{"box_office_name":"name"}`, `{"box_office_name":"name","period":"four weeks","currency":null}`, `{"box_office_name":"name","period":"four weeks","currency":{"code":"gbp","symbol":"£","error":"denied"}}`}},
}

func TestSixteenthBatchContracts(t *testing.T) {
	if len(batch16Contracts) < 10 {
		t.Fatal("expected at least ten verifiers")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch16Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d, ok := registry[tc.id]
			if !ok || d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("missing read-only promotion")
			}
			secret := "test-secret+/?=&private-metadata"
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing", `{"error":"private-metadata"}`)
			if tc.id != "signaturit-api-key" {
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
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						actual := *req.URL
						if tc.header == "query" {
							actual.RawQuery = ""
						}
						if calls >= len(tc.urls) || actual.String() != tc.urls[calls] || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						calls++
						if tc.header == "body" {
							var p map[string]string
							if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" || json.NewDecoder(req.Body).Decode(&p) != nil || len(p) != 1 || p["token"] != secret {
								t.Fatal("incorrect read-only POST contract")
							}
						} else if req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) {
							t.Fatal("expected bodyless GET")
						}
						switch tc.header {
						case "query":
							if req.URL.Query().Get("apikey") != secret || len(req.URL.Query()) != 1 {
								t.Fatal("incorrect escaped query authentication")
							}
						case "basic":
							u, p, ok := req.BasicAuth()
							if !ok || u != secret || p != "" {
								t.Fatal("incorrect Basic authentication")
							}
						case "body":
						default:
							if req.Header.Get(tc.header) != tc.prefix+secret {
								t.Fatal("incorrect authentication header")
							}
						}
						if tc.id == "shippo-api-token" && req.Header.Get("Shippo-API-Version") != "2018-02-08" {
							t.Fatal("missing API version")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
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

func TestSixteenthBatchTransportAndFallback(t *testing.T) {
	for _, tc := range batch16Contracts {
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

func TestSixteenthBatchDynalistApplicationErrors(t *testing.T) {
	for _, status := range []int{200, 201, 400, 401, 403, 429, 500} {
		for _, code := range []string{"InvalidToken", "Invalid", "LockFail", "TooManyRequests"} {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"_code":"` + code + `","_msg":"private-metadata"}`))}, nil
			})}
			r := verifyDynalist(WithVerificationHTTPClient(context.Background(), client), "test-secret")
			want := VerificationUnknown
			if status == 200 && code == "InvalidToken" {
				want = VerificationUnverified
			}
			if r.Status != want || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
				t.Fatalf("status=%d code=%s result=%+v", status, code, r)
			}
			if status == 200 && code == "TooManyRequests" && r.ErrorCategory != "rate_limited" {
				t.Fatalf("result=%+v", r)
			}
		}
	}
}
