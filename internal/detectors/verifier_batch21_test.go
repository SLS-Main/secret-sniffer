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

var batch21Contracts = []struct {
	id, secret, header, prefix string
	verify                     Verifier
	urls, valid, invalid       []string
	fallbackBody               string
}{
	{"pagerduty-token", "REST-token-abcdefghijklmn", "Authorization", "Token token=", verifyPagerDuty,
		[]string{"https://api.pagerduty.com/abilities"},
		[]string{`{"abilities":[]}`, `{"abilities":["teams","read_only_users"]}`},
		[]string{`{"abilities":null}`, `{"abilities":[null]}`, `{"abilities":[1]}`, `{"abilities":{}}`}, ""},
	{"honeycomb-api-key", strings.Repeat("a", 32), "X-Honeycomb-Team", "", verifyHoneycomb,
		[]string{"https://api.honeycomb.io/1/auth", "https://api.eu1.honeycomb.io/1/auth"},
		[]string{`{"id":"key1","type":"configuration","api_key_access":{},"team":{"name":"private-metadata","slug":"team"},"environment":{"name":"","slug":""}}`, `{"id":"key1","type":"ingest","api_key_access":{"createDatasets":false},"team":{"name":"name","slug":"team"},"environment":{"name":"prod","slug":"prod"}}`},
		[]string{`{"id":"key1","type":"configuration"}`, `{"id":"key1","type":"configuration","api_key_access":{"events":null},"team":{"name":"name","slug":"team"},"environment":{"name":"","slug":""}}`, `{"id":"key1","type":"configuration","api_key_access":{},"team":{"name":"name","slug":"team"},"environment":{"name":null,"slug":""}}`}, ""},
	{"opsgenie-api-key", "123e4567-e89b-12d3-a456-426614174000", "Authorization", "GenieKey ", verifyOpsgenie,
		[]string{"https://api.opsgenie.com/v2/account", "https://api.eu.opsgenie.com/v2/account"},
		[]string{`{"data":{"name":"private-metadata","userCount":0,"plan":null}}`, `{"data":{"name":"name","userCount":1450,"plan":{"maxUserCount":1000}}}`},
		[]string{`{"data":{"name":"name"}}`, `{"data":{"name":"name","userCount":"1"}}`, `{"data":{"name":"name","userCount":null}}`, `{"data":{"name":"name","userCount":1,"error":"denied"}}`}, ""},
	{"postmark-token", "123e4567-e89b-12d3-a456-426614174000", "X-Postmark-Server-Token", "", verifyPostmark,
		[]string{"https://api.postmarkapp.com/stats/outbound", "https://api.postmarkapp.com/senders?count=1&offset=0"},
		[]string{`{"Sent":0,"Bounced":0,"SMTPApiErrors":0}`, `{"Sent":1,"Bounced":0,"SMTPApiErrors":2}`},
		[]string{`{"Sent":0}`, `{"Sent":"0","Bounced":0,"SMTPApiErrors":0}`, `{"Sent":0,"Bounced":0,"SMTPApiErrors":0,"ErrorCode":10}`, `{"ErrorCode":10,"Message":"Bad or missing API token"}`},
		`{"TotalCount":1,"SenderSignatures":[{"ID":1,"EmailAddress":"private-metadata","Confirmed":false}]}`},
	{"cloudinary-url", "cloudinary://123456789012345:abcdefghijklmnopqrstuvwxyz1@cloud", "basic", "", verifyCloudinary,
		[]string{"https://api.cloudinary.com/v1_1/cloud/config", "https://api-eu.cloudinary.com/v1_1/cloud/config", "https://api-ap.cloudinary.com/v1_1/cloud/config"},
		[]string{`{"cloud_name":"cloud","created_at":"date"}`, `{"cloud_name":"cloud","created_at":"date","settings":{"folder_mode":"dynamic"}}`},
		[]string{`{"cloud_name":"other","created_at":"date"}`, `{"cloud_name":"cloud"}`, `{"cloud_name":"cloud","created_at":null}`}, ""},
	{"keycdn-api-key", "sk_prod_" + strings.Repeat("A", 24), "basic", "", verifyKeyCDN,
		[]string{"https://api.keycdn.com/reports/creditbalance.json"},
		[]string{`{"status":"success","data":{"amount":"0"}}`, `{"status":"success","data":{"amount":"-0.01"}}`},
		[]string{`{"status":"success","data":{"amount":0}}`, `{"status":"success","data":{"amount":"NaN"}}`, `{"status":"success","data":{"amount":"Inf"}}`, `{"status":"success","data":{"amount":null}}`, `{"status":"error","data":{"amount":"100"}}`, `{"status":"success","data":{"amount":"100","error":"denied"}}`}, ""},
	{"storecove-api-key", strings.Repeat("A", 42) + "-", "Authorization", "Bearer ", verifyStorecove,
		[]string{"https://api.storecove.com/api/v2/discovery/identifiers"},
		[]string{`{"countries":[]}`, `{"countries":[{"country":"NL","region":"eu_eea","sender":null}]}`},
		[]string{`[]`, `{"countries":null}`, `{"countries":[{}]}`, `{"countries":[{"country":1}]}`}, ""},
	{"flickr-api-key", strings.Repeat("a", 32), "query", "", verifyFlickr,
		[]string{"https://www.flickr.com/services/rest/?method=flickr.test.echo&api_key=" + strings.Repeat("a", 32) + "&format=json&nojsoncallback=1"},
		[]string{`{"stat":"ok","method":{"_content":"flickr.test.echo"},"api_key":{"_content":"` + strings.Repeat("a", 32) + `"}}`},
		[]string{`{"stat":"ok"}`, `{"stat":"ok","method":{"_content":"flickr.test.echo"},"api_key":{"_content":"other"}}`, `{"stat":"ok","code":100}`, `{"stat":"fail","code":105}`, `{"stat":"fail","code":"100"}`, `{"stat":"fail","code":100,"api_key":{"_content":"other"}}`}, ""},
	{"twist-api-token", strings.Repeat("a", 40), "Authorization", "Bearer ", verifyTwist,
		[]string{"https://api.twist.com/api/v3/users/get_session_user"},
		[]string{`{"id":1,"name":"name","email":"private-metadata","token":"private-metadata","off_days":[]}`},
		[]string{`{"id":1}`, `{"id":"1","name":"name","email":"mail"}`, `{"id":1,"name":"name","email":"mail","code":200}`, `{"code":200,"error":"invalid token"}`}, ""},
	{"webscraper-api-key", strings.Repeat("A", 60), "Authorization", "Bearer ", verifyWebScraper,
		[]string{"https://api.webscraper.io/api/v1/sitemaps?page=1"},
		[]string{`{"success":true,"data":[],"current_page":1,"last_page":1,"per_page":100,"total":0}`, `{"success":true,"data":[{"id":1,"name":"private-metadata"}],"current_page":1,"last_page":2,"per_page":100,"total":101,"next_page_url":"https://other.invalid"}`},
		[]string{`{"success":true,"data":[]}`, `{"success":false,"data":[],"current_page":1,"last_page":1,"per_page":100,"total":0}`, `{"success":true,"data":null,"current_page":1,"last_page":1,"per_page":100,"total":0}`, `{"success":true,"data":[{}],"current_page":1,"last_page":1,"per_page":100,"total":1}`}, ""},
}

func batch21Safety(id string) VerificationSafety {
	if id == "honeycomb-api-key" || id == "flickr-api-key" {
		return VerificationSafetyAuthOnly
	}
	return VerificationSafetyReadOnly
}

func checkBatch21Request(t *testing.T, index, call int, req *http.Request) {
	t.Helper()
	tc := batch21Contracts[index]
	accept := "application/json"
	if tc.id == "pagerduty-token" {
		accept = "application/vnd.pagerduty+json;version=2"
	}
	if call >= len(tc.urls) || req.URL.String() != tc.urls[call] || req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || req.Header.Get("Accept") != accept {
		t.Fatalf("unexpected request %s %s", req.Method, req.URL)
	}
	header := tc.header
	if tc.id == "postmark-token" && call == 1 {
		header = "X-Postmark-Account-Token"
		if req.Header.Get("X-Postmark-Server-Token") != "" {
			t.Fatal("server header leaked into account probe")
		}
	}
	switch header {
	case "basic":
		u, p, ok := req.BasicAuth()
		wantUser, wantPass := tc.secret, ""
		if tc.id == "cloudinary-url" {
			wantUser, wantPass = "123456789012345", "abcdefghijklmnopqrstuvwxyz1"
		}
		if !ok || u != wantUser || p != wantPass {
			t.Fatal("incorrect Basic auth")
		}
	case "query":
		if req.URL.Query().Get("api_key") != tc.secret {
			t.Fatal("incorrect query auth")
		}
	default:
		if req.Header.Get(header) != tc.prefix+tc.secret {
			t.Fatal("incorrect header auth")
		}
	}
}

func TestTwentyFirstBatchContracts(t *testing.T) {
	if len(batch21Contracts) != 10 {
		t.Fatal("expected ten contracts")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for index, tc := range batch21Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != batch21Safety(tc.id) {
				t.Fatal("wrong safety")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing")
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
						checkBatch21Request(t, index, calls, req)
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: tc.secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
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

func TestTwentyFirstBatchTransportAndFallback(t *testing.T) {
	for index, tc := range batch21Contracts {
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
				r := tc.verify(WithVerificationHTTPClient(context.Background(), client), tc.secret)
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
						checkBatch21Request(t, index, calls, req)
						calls++
						code, body := status, `{"error":"denied"}`
						if calls == len(tc.urls) {
							code, body = 200, tc.valid[0]
							if tc.fallbackBody != "" {
								body = tc.fallbackBody
							}
						}
						if cancelled {
							cancel()
						}
						return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := tc.verify(WithVerificationHTTPClient(ctx, client), tc.secret)
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

func TestTwentyFirstBatchPostmarkAccountAndFlickrErrors(t *testing.T) {
	for _, tc := range []struct {
		body string
		want VerificationStatus
	}{
		{`{"TotalCount":0,"SenderSignatures":[]}`, VerificationVerified},
		{`{"TotalCount":1,"SenderSignatures":[{"ID":1,"EmailAddress":"mail","Confirmed":false}]}`, VerificationVerified},
		{`{"TotalCount":0,"SenderSignatures":null}`, VerificationUnknown},
		{`{"TotalCount":1,"SenderSignatures":[{"ID":1,"EmailAddress":"mail","Confirmed":null}]}`, VerificationUnknown},
		{`{"TotalCount":0,"SenderSignatures":[],"ErrorCode":10}`, VerificationUnknown},
	} {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			code, body := 401, `{"ErrorCode":10}`
			if calls == 2 {
				code, body = 200, tc.body
			}
			if calls > 2 {
				t.Fatal("extra Postmark request")
			}
			return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		if r := verifyPostmark(WithVerificationHTTPClient(context.Background(), client), "secret"); calls != 2 || r.Status != tc.want || r.Response != "" {
			t.Fatalf("calls=%d result=%+v", calls, r)
		}
	}
	for _, status := range []int{200, 400, 401, 403, 429, 500} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"stat":"fail","code":100}`))}, nil
		})}
		want := VerificationUnknown
		if status == 200 {
			want = VerificationUnverified
		}
		if r := verifyFlickr(WithVerificationHTTPClient(context.Background(), client), strings.Repeat("a", 32)); r.Status != want || r.Response != "" {
			t.Fatalf("status=%d result=%+v", status, r)
		}
	}
}

func TestTwentyFirstBatchCredentialBoundaries(t *testing.T) {
	registry := make(map[string]Detector)
	for _, d := range DefaultRegistry() {
		registry[d.Info().ID] = d
	}
	contexts := []string{"pagerduty token", "honeycomb api_key", "opsgenie api_key", "postmark token", "", "keycdn api_key", "storecove api_key", "flickr api_key", "twist token", "web_scraper api_key"}
	for i, tc := range batch21Contracts {
		matches := registry[tc.id].Detect([]byte(contexts[i] + `="` + tc.secret + `"`))
		if len(matches) != 1 || matches[0].Secret != tc.secret {
			t.Fatalf("%s lost whole credential: %+v", tc.id, matches)
		}
		if matches := registry[tc.id].Detect([]byte(contexts[i] + `="` + tc.secret + strings.Repeat("Z", 300) + `"`)); len(matches) != 0 {
			t.Fatalf("%s truncated key", tc.id)
		}
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported credential made a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	if r := verifyPagerDuty(ctx, strings.Repeat("a", 32)); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
		t.Fatalf("routing key result=%+v", r)
	}
	for _, secret := range []string{strings.Repeat("Z", 32), strings.Repeat("a", 40)} {
		if r := verifyFlickr(ctx, secret); r.Status != VerificationUnknown || r.ErrorCategory != "credential_type" {
			t.Fatalf("Flickr subtype result=%+v", r)
		}
	}
}
