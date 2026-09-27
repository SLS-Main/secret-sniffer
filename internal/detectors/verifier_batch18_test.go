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

var batch18Contracts = []struct {
	id                         string
	verify                     Verifier
	url, header, prefix, query string
	valid, invalid             []string
}{
	{"onfido-api-token", verifyOnfido, "https://api.eu.onfido.com/v3.6/applicants?page=1&per_page=1", "Authorization", "Token token=", "",
		[]string{`{"applicants":[]}`, `{"applicants":[{"id":"applicant1","created_at":"2026-09-26","first_name":"private-metadata","delete_at":null}]}`},
		[]string{`{"applicants":null}`, `{"applicants":[{}]}`, `{"applicants":[{"id":1,"created_at":"date"}]}`, `{"applicants":[{"id":"applicant1","created_at":"date","error":"denied"}]}`}},
	{"snipcart-api-key", verifySnipcart, "https://app.snipcart.com/api/orders?limit=1&format=Excerpt", "basic", "", "",
		[]string{`{"totalItems":0,"offset":0,"limit":1,"items":[]}`, `{"totalItems":1,"offset":0,"limit":1,"items":[{"token":"order1","status":"Cancelled","email":"private-metadata"}]}`},
		[]string{`{"items":[]}`, `{"totalItems":0,"offset":0,"limit":1,"items":null}`, `{"totalItems":1,"offset":0,"limit":1,"items":[{}]}`, `{"totalItems":-1,"offset":0,"limit":1,"items":[]}`}},
	{"scrutinizer-token", verifyScrutinizer, "https://scrutinizer-ci.com/api/user/repositories?page=1&per_page=1", "", "", "access_token",
		[]string{`{"page":1,"limit":1,"_embedded":{"repositories":[]}}`, `{"page":1,"limit":1,"_embedded":{"repositories":[{"type":"b","created_at":"date","repo_slug":"private-metadata","_links":{"self":{"href":"/api/repositories/b/org/repo"}}}]},"_links":{"next":{"href":"https://other.invalid/"}}}`},
		[]string{`{"page":1,"limit":1,"_embedded":{"repositories":null}}`, `{"page":1,"limit":1,"_embedded":{"repositories":[{}]}}`, `{"page":1,"limit":1,"_embedded":{"repositories":[],"error":"denied"}}`}},
	{"codemagic-api-token", verifyCodemagic, "https://api.codemagic.io/apps", "x-auth-token", "", "",
		[]string{`{"applications":[]}`, `{"applications":[{"_id":"app1","appName":"private-metadata"}]}`},
		[]string{`{"applications":null}`, `{"applications":[{}]}`, `{"applications":[{"_id":"app1","appName":"app","error":"denied"}]}`}},
	{"teachable-api-key", verifyTeachable, "https://developers.teachable.com/v1/courses?page=1&per=1", "apiKey", "", "",
		[]string{`{"courses":[],"meta":{"total":0,"page":1,"per_page":1}}`, `{"courses":[{"id":1,"name":"private-metadata","is_published":false,"heading":null}],"meta":{"total":1,"page":1,"per_page":1}}`},
		[]string{`{"courses":[]}`, `{"courses":null,"meta":{"total":0,"page":1,"per_page":1}}`, `{"courses":[{"id":"1","name":"course","is_published":false}],"meta":{"total":1,"page":1,"per_page":1}}`, `{"courses":[{"id":1,"name":"course","is_published":null}],"meta":{"total":1,"page":1,"per_page":1}}`}},
	{"axonaut-api-key", verifyAxonaut, "https://axonaut.com/api/v2/companies?type=all&sort=id", "userApiKey", "", "",
		[]string{`[]`, `[{"id":1,"name":"private-metadata","iban":"suppressed"}]`},
		[]string{`[{}]`, `[null]`, `[{"id":"1","name":"company"}]`, `[{"id":0,"name":"company"}]`, `[{"id":1.5,"name":"company"}]`, `[{"id":1,"name":"company","error":"denied"}]`}},
	{"survicate-api-key", verifySurvicate, "https://data-api.survicate.com/v2/surveys?items_per_page=1", "Authorization", "Basic ", "",
		[]string{`{"pagination_data":{"has_more":false},"data":[]}`, `{"pagination_data":{"has_more":true,"next_url":"/surveys?start=date"},"data":[{"id":"survey1","type":"PageSurvey","name":"private-metadata","created_at":"date","enabled":false}]}`},
		[]string{`{"data":[]}`, `{"pagination_data":{"has_more":null},"data":[]}`, `{"pagination_data":{"has_more":"false"},"data":[]}`, `{"pagination_data":{"has_more":false},"data":null}`, `{"pagination_data":{"has_more":false},"data":[{"id":"survey1","type":"Other","name":"survey","created_at":"date"}]}`}},
	{"betterstack-api-key", verifyBetterStack, "https://betterstack.com/api/v2/team-members?page=1&per_page=1", "Authorization", "Bearer ", "",
		[]string{`{"data":[]}`, `{"data":[{"id":"member1","type":"team_member","attributes":{"email":"private-metadata","role":"custom"}}]}`, `{"data":[{"id":"invite1","type":"team_member_invitation","attributes":{"email":"mail","role":"member"}}],"pagination":{"next":"https://other.invalid/"}}`},
		[]string{`{"data":null}`, `{"data":[{}]}`, `{"data":[{"id":"member1","type":"team_member","attributes":{"email":"mail","role":"member","error":"denied"}}]}`, `{"errors":"This global token has access to multiple teams. Please specify team_name."}`}},
	{"intrinio-api-key", verifyIntrinio, "https://api-v2.intrinio.com/account/current_usage", "Authorization", "Bearer ", "",
		[]string{`{"account":{"email":"private-metadata"},"usage":[]}`, `{"account":{"email":"mail"},"usage":[{"access_code":"realtime","count":"0","limit":"unlimited"}]}`},
		[]string{`{"account":{"email":"mail"}}`, `{"account":{"email":"mail"},"usage":null}`, `{"account":{"email":"mail"},"usage":[{}]}`, `{"account":{"email":"mail"},"usage":[{"access_code":"code","count":0,"limit":"100"}]}`, `{"account":{"email":"mail","error":"denied"},"usage":[]}`}},
	{"mavenlink-api-token", verifyMavenlink, "https://api.mavenlink.com/api/v1/users/me.json", "Authorization", "Bearer ", "",
		[]string{`{"count":1,"results":[{"key":"users","id":"1"}],"users":{"1":{"id":"1","email_address":"private-metadata"}}}`},
		[]string{`{"count":0,"results":[],"users":{}}`, `{"count":1,"results":[{"key":"users","id":"1"}],"users":{"2":{"id":"2","email_address":"mail"}}}`, `{"count":1,"results":[{"key":"users","id":"1"}],"users":{"1":{"id":"2","email_address":"mail"}}}`, `{"count":1,"results":[{"key":"workspaces","id":"1"}],"users":{"1":{"id":"1","email_address":"mail"}}}`, `{"count":1,"results":[{"key":"users","id":"1"}],"users":{"1":{"id":"1","email_address":"mail","error":"denied"}}}`}},
}

func TestEighteenthBatchContracts(t *testing.T) {
	if len(batch18Contracts) < 10 {
		t.Fatal("expected ten contracts")
	}
	registry := make(map[string]RegexDetector)
	for _, d := range DefaultRegistry() {
		if r, ok := d.(RegexDetector); ok {
			registry[r.Info().ID] = r
		}
	}
	for _, tc := range batch18Contracts {
		t.Run(tc.id, func(t *testing.T) {
			d := registry[tc.id]
			if d.Info().VerificationSafety != VerificationSafetyReadOnly {
				t.Fatal("missing read-only classification")
			}
			bodies := append(append([]string(nil), tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `<html>OK</html>`, tc.valid[0]+" trailing")
			if tc.id != "axonaut-api-key" {
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
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 422, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					secret := "test-secret+/?=&"
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						actual := *req.URL
						if tc.query != "" {
							q := actual.Query()
							if q.Get(tc.query) != secret {
								t.Fatal("incorrect query escaping")
							}
							q.Del(tc.query)
							actual.RawQuery = q.Encode()
						} else if tc.header == "basic" {
							u, p, ok := req.BasicAuth()
							if !ok || u != secret || p != "" {
								t.Fatal("incorrect Basic authentication")
							}
						} else if req.Header.Get(tc.header) != tc.prefix+secret {
							t.Fatal("incorrect authentication header")
						}
						if req.Method != http.MethodGet || (req.Body != nil && req.Body != http.NoBody) || actual.String() != tc.url || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						if tc.id == "axonaut-api-key" && req.Header.Get("page") != "1" {
							t.Fatal("missing page header")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}, "Link": []string{"<https://other.invalid/>; rel=next"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := (Candidate{Secret: secret, Verifier: d.Verifier, VerificationSafety: d.Info().VerificationSafety}).Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if r.Status != want || calls != 1 || r.Response != "" || strings.Contains(r.Message, "private-metadata") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, r)
					}
				}
			}
		})
	}
}

func TestEighteenthBatchTransportFailures(t *testing.T) {
	for _, tc := range batch18Contracts {
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

func TestEighteenthBatchOnfidoRegionRouting(t *testing.T) {
	var detector RegexDetector
	for _, d := range DefaultRegistry() {
		if d.Info().ID == "onfido-api-token" {
			detector = d.(RegexDetector)
		}
	}
	for _, mode := range []string{"live", "sandbox"} {
		for _, region := range []string{"", "_us", "_ca"} {
			secret := "api_" + mode + region + "." + strings.Repeat("Ab3d", 10)
			host := "api.eu.onfido.com"
			if region != "" {
				host = "api." + strings.TrimPrefix(region, "_") + ".onfido.com"
			}
			matches := detector.Detect([]byte(secret))
			if len(matches) != 1 || matches[0].Secret != secret {
				t.Fatalf("regional bare token not detected: %s", region)
			}
			for _, status := range []int{200, 401, 403, 429, 503} {
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.Host != host || req.Header.Get("Authorization") != "Token token="+secret {
						t.Fatal("wrong regional credential routing")
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"applicants":[]}`))}, nil
				})}
				r := verifyOnfido(WithVerificationHTTPClient(context.Background(), client), secret)
				want := VerificationUnknown
				if status == 200 {
					want = VerificationVerified
				}
				if calls != 1 || r.Status != want || r.Response != "" {
					t.Fatalf("calls=%d result=%+v", calls, r)
				}
			}
		}
	}
}
