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

var batch33Contracts = []struct {
	id, assignment, secret, fields, endpoint, header, prefix string
	valid, invalid                                           []string
}{
	{"mailmodo-api-key", "MAILMODO_API_KEY", "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ12", "", "https://api.mailmodo.com/api/v1/getAllContactLists", "mmApiKey", "",
		[]string{`{"listDetails":[]}`, `{"listDetails":[{"id":"id","name":"private-data","created_at":"date"}]}`, `{"listDetails":[{"id":"id","name":"list","created_at":"date","contacts_count":0}]}`},
		[]string{`{"data":[]}`, `{"listDetails":null}`, `{"listDetails":[{"id":"id","name":"list","created_at":"date","contacts_count":"0"}]}`, `{"listDetails":[{"id":"id","name":"list","created_at":"date","contacts_count":null}]}`, `{"listDetails":[{"id":"id","name":"list","created_at":"date","error":"denied"}]}`}},
	{"beebole-api-token", "BEEBOLE_API_KEY", strings.Repeat("A", 40), "BEEBOLE_API_URL=https://app.beebole.com/graphql", "https://app.beebole.com/graphql", "apikey", "",
		[]string{`{"data":{"currentPerson":{"name":"private-data","email":"email"}}}`, `{"data":{"currentPerson":{"name":"person","email":"email"}},"permissionsErrors":[],"errors":[]}`},
		[]string{`{"data":{}}`, `{"data":{"currentPerson":{"name":"person","email":null}}}`, `{"data":{"currentPerson":{"name":"person","email":"email","error":"denied"}}}`, `{"data":{"currentPerson":{"name":"person","email":"email"}},"permissionsErrors":["Query.currentPerson"]}`, `{"data":{"currentPerson":{"name":"person","email":"email"}},"permissionsErrors":null}`, `{"data":{"currentPerson":{"name":"person","email":"email"}},"errors":[{"message":"APIKeyError:InvalidKey"}]}`, `{"data":{"currentPerson":{"name":"person","email":"email"},"error":"denied"}}`}},
	{"caflou-api-key", "CAFLOU_ACCESS_TOKEN", "eyJhbGciOiJIUzI1NiJ9." + strings.Repeat("A", 40) + "." + strings.Repeat("B", 43), "CAFLOU_ACCOUNT_ID=42", "https://app.caflou.com/api/v1/42/account_users?per=1&page=1", "Authorization", "Bearer ",
		[]string{`[]`, `[{"id":1,"email":"private-data","active":false}]`, `[{"id":2,"email":"email","active":true,"temporary":true}]`},
		[]string{`[{}]`, `[{"id":"1","email":"email","active":true}]`, `[{"id":1,"email":"email","active":null}]`, `[{"id":1,"email":"email","active":true,"error":"denied"}]`}},
	{"signable-api-key", "SIGNABLE_API_KEY", strings.Repeat("A", 32), "", "https://api.signable.co.uk/v1/settings", "", "",
		[]string{`{"http":200,"setting_signature_more_info":false,"setting_signature_format_default":"typed","setting_signature_format_accepted":"typed,drawn,upload"}`, `{"http":200,"setting_signature_more_info":true,"setting_signature_format_default":"upload","setting_signature_format_accepted":"upload"}`},
		[]string{`{"http":200}`, `{"http":"200","setting_signature_more_info":true,"setting_signature_format_default":"typed","setting_signature_format_accepted":"typed"}`, `{"http":200,"setting_signature_more_info":"false","setting_signature_format_default":"typed","setting_signature_format_accepted":"typed"}`, `{"http":200,"setting_signature_more_info":false,"setting_signature_format_default":"typed","setting_signature_format_accepted":"typed","code":10002}`}},
	{"simplesat-api-key", "SIMPLESAT_API_KEY", strings.Repeat("a", 40), "", "https://api.simplesat.io/api/v1/questions?page_size=1&page=1", "X-Simplesat-Token", "",
		[]string{`{"count":0,"questions":[],"next":null,"previous":null}`, `{"count":2,"questions":[{"id":1,"type":"comment","required":false,"text":"private-data","choices":[]}],"next":"https://other.invalid"}`},
		[]string{`{"count":"0","questions":[]}`, `{"count":0,"questions":null}`, `{"count":1,"questions":[{"id":1,"type":"comment","required":"false"}]}`, `{"count":1,"questions":[{"id":1,"type":"comment","required":false,"error":"denied"}]}`}},
	{"goodday-api-key", "GOODDAY_API_KEY", strings.Repeat("a", 32), "GOODDAY_API_URL=https://api.goodday.work/2.0", "https://api.goodday.work/2.0/skills", "gd-api-token", "",
		[]string{`[]`, `[{"id":"skill","label":"private-data"}]`},
		[]string{`[{}]`, `[{"id":1,"label":"skill"}]`, `[{"id":"skill","label":null}]`, `[{"id":"skill","label":"skill","error":"denied"}]`}},
	{"mixmax-api-key", "MIXMAX_API_KEY", strings.Repeat("A", 40), "", "https://api.mixmax.com/v1/tasks?limit=1", "X-API-Token", "",
		[]string{`{"results":[],"total":0,"next":null,"previous":null,"hasNext":false,"hasPrevious":false}`, `{"results":[{"_id":"id","type":"todo","status":"Completed","isCompleted":true,"description":"private-data"}],"total":2,"next":"opaque","previous":null,"hasNext":true,"hasPrevious":false}`},
		[]string{`{"results":[],"total":"0","hasNext":false,"hasPrevious":false}`, `{"results":[],"total":0,"hasNext":null,"hasPrevious":false}`, `{"results":[{"_id":"id","type":"todo","status":null}],"total":1,"hasNext":false,"hasPrevious":false}`, `{"results":[{"_id":"id","type":"todo","status":"Open","error":"denied"}],"total":1,"hasNext":false,"hasPrevious":false}`}},
	{"overloop-api-key", "OVERLOOP_API_KEY", strings.Repeat("A", 50), "", "https://api.overloop.com/public/v1/me", "Authorization", "",
		[]string{`{"data":{"id":"1","type":"users","attributes":{"name":"private-data","email":"email","disabled":true}}}`, `{"data":{"id":"1","type":"users","attributes":{"name":"person","email":"email","signature":null},"relationships":{"company":{"links":{"related":"https://other.invalid"}}}}}`},
		[]string{`{"data":{"id":"1","type":"companies","attributes":{"name":"person","email":"email"}}}`, `{"data":{"id":1,"type":"users","attributes":{"name":"person","email":"email"}}}`, `{"data":{"id":"1","type":"users","attributes":{"name":"person","email":"email","error":"denied"}}}`, `{"data":{"id":"1","type":"users","attributes":{"name":"person","email":"email"},"error":"denied"}}`}},
	{"worksnaps-api-key", "WORKSNAPS_API_TOKEN", strings.Repeat("A", 40), "WORKSNAPS_PROJECT_ID=42", "https://api.worksnaps.com/api/projects/42.xml", "", "",
		[]string{`<project><id type="integer">42</id><name>private-data</name><description/><status>archived</status></project>`, `<?xml version="1.0"?><project><id>42</id><name>A &amp; B</name><status>active</status></project>`},
		[]string{`<projects/>`, `<project><id>43</id><name>project</name><status>active</status></project>`, `<project><id>42</id><name>project</name><status>active</status><error>denied</error></project>`, `<project><id>42</id><name>project</name><status>active</status></project><error>denied</error>`, `<project><id>42</id><id>43</id><name>project</name><status>active</status></project>`, `<project><id>42</id><name><b>project</b></name><status>active</status></project>`, `<project><id>42</id><name>project</name><status>active</status></project>trailing`}},
	{"apacta-api-key", "APACTA_ACCESS_TOKEN", batch30UUID, "APACTA_TIME_ENTRY_TYPE_ID=" + batch30UUID, "https://app.apacta.com/api/v1/time_entry_types/" + batch30UUID, "Authorization", "Bearer ",
		[]string{`{"success":true,"data":{"id":"` + batch30UUID + `","name":"private-data"}}`, `{"success":true,"data":{"id":"` + batch30UUID + `","name":"type","erp_id":null,"deleted":null}}`},
		[]string{`{"status":"ok","database":true,"searchEngine":true}`, `{"success":false,"data":{"id":"` + batch30UUID + `","name":"type"}}`, `{"success":"true","data":{"id":"` + batch30UUID + `","name":"type"}}`, `{"success":true,"data":{"id":"other","name":"type"}}`, `{"success":true,"data":{"id":"` + batch30UUID + `","name":"type","error":"denied"}}`}},
}

func TestThirtyThirdBatchContracts(t *testing.T) {
	registry := batch30Registry()
	if len(batch33Contracts) != 10 {
		t.Fatal("expected ten providers")
	}
	for _, tc := range batch33Contracts {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
			if c.Secret != tc.secret || c.VerificationSafety != VerificationSafetyReadOnly {
				t.Fatalf("%+v", c)
			}
			bodies := append(append([]string{}, tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `"ok"`, `<html>login</html>`, tc.valid[0]+" trailing")
			if tc.id == "mailmodo-api-key" {
				bodies = append(bodies, `{"listDetails":[],"Error":"API key missing"}`)
			}
			if tc.id == "goodday-api-key" {
				bodies = append(bodies, `[{"id":"id","label":"label","errorMessage":"Auth Failed."}]`)
			}
			if tc.id != "worksnaps-api-key" {
				for _, field := range []string{"error", "error_code", "errors"} {
					var obj identityPayload
					var array []identityPayload
					if tc.id == "caflou-api-key" || tc.id == "goodday-api-key" {
						_ = json.Unmarshal([]byte(tc.valid[1]), &array)
						obj = array[0]
					} else {
						_ = json.Unmarshal([]byte(tc.valid[0]), &obj)
					}
					obj[field] = json.RawMessage(`"private-data"`)
					var raw []byte
					if array != nil {
						raw, _ = json.Marshal(array)
					} else {
						raw, _ = json.Marshal(obj)
					}
					bodies = append(bodies, string(raw))
				}
			}
			for _, status := range []int{200, 201, 204, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						method, accept := http.MethodGet, "application/json"
						if tc.id == "beebole-api-token" {
							method = http.MethodPost
						}
						if tc.id == "worksnaps-api-key" {
							accept = "application/xml"
						}
						if tc.id == "overloop-api-key" {
							accept = "application/vnd.api+json"
						}
						if req.Method != method || req.URL.String() != tc.endpoint || req.Header.Get("Accept") != accept {
							t.Fatalf("unexpected request %s %s", req.Method, req.URL)
						}
						if tc.header != "" && req.Header.Get(tc.header) != tc.prefix+tc.secret {
							t.Fatal("wrong authentication")
						}
						if tc.header == "" {
							u, p, ok := req.BasicAuth()
							want := "x"
							if tc.id == "worksnaps-api-key" {
								want = "ignored"
							}
							if !ok || u != tc.secret || p != want {
								t.Fatal("wrong Basic authentication")
							}
						}
						if tc.id == "beebole-api-token" {
							payload, err := io.ReadAll(req.Body)
							if err != nil || string(payload) != `{"query":"{ currentPerson { name email } }"}` || req.Header.Get("Content-Type") != "application/json" {
								t.Fatal("not the sparse read-only query")
							}
						} else if req.Body != nil {
							t.Fatal("GET body")
						}
						if tc.id == "simplesat-api-key" && req.Header.Get("Content-Type") != "application/json" {
							t.Fatal("wrong JSON content type")
						}
						if tc.id == "overloop-api-key" && req.Header.Get("Content-Type") != "application/vnd.api+json; charset=utf-8" {
							t.Fatal("wrong JSON:API content type")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if r.Status != want || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-data") {
						t.Fatalf("status=%d body=%s result=%+v calls=%d", status, body, r, calls)
					}
				}
			}
		})
	}
}

func TestThirtyThirdBatchContextGates(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported context sent a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch33Contracts {
		input := tc.assignment + "=" + tc.secret + "\n" + tc.fields
		c := batch30Candidate(t, registry[tc.id], input)
		for _, endpoint := range []string{"", "https://other.invalid", "http://app.beebole.com/graphql", "https://api.goodday.work:443/2.0", "https://api.goodday.work.evil.invalid/2.0", "https://user@api.goodday.work/2.0", "https://api.goodday.work/2.0#fragment", "https://api.goodday.work/2.0?key=secret"} {
			altered := c
			altered.SecretParts = cloneStringMap(c.SecretParts)
			if altered.SecretParts == nil {
				altered.SecretParts = map[string]string{}
			}
			altered.SecretParts["endpoint"] = endpoint
			if r := altered.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
		if got := registry[tc.id].Detect([]byte(tc.assignment + "=" + tc.secret + "+suffix")); len(got) != 0 {
			t.Fatalf("%s accepted truncated key", tc.id)
		}
		if tc.fields != "" {
			incomplete := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret)
			if r := incomplete.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("missing %s context: %+v", tc.id, r)
			}
		}
	}
	for _, tc := range []struct{ id, input string }{
		{"beebole-api-token", "beebole token=" + strings.Repeat("a", 40)},
		{"beebole-api-token", "BEEBOLE_API_TOKEN=" + strings.Repeat("a", 40) + "\nBEEBOLE_API_URL=https://app.beebole.com/graphql"},
		{"beebole-api-token", "BEEBOLE_API_TOKEN=" + strings.Repeat("a", 40) + "\nBEEBOLE_CREDENTIAL_TYPE=graphql\nBEEBOLE_API_URL=https://app.beebole.com/graphql"},
		{"beebole-api-token", "BEEBOLE_API_KEY=" + strings.Repeat("a", 40) + "\nBEEBOLE_API_URL=https://beebole-apps.com/api/v2"},
		{"apacta-api-key", "APACTA_API_KEY=" + batch30UUID + "\nAPACTA_TIME_ENTRY_TYPE_ID=" + batch30UUID},
		{"apacta-api-key", "APACTA_ACCESS_TOKEN=" + batch30UUID + "\nAPACTA_TIME_ENTRY_TYPE_ID=../../users"},
		{"goodday-api-key", "GOODDAY_API_KEY=" + strings.Repeat("a", 32) + "\nGOODDAY_API_URL=https://api.goodday.work/1.2"},
		{"worksnaps-api-key", "WORKSNAPS_API_KEY=" + strings.Repeat("A", 40) + "\nWORKSNAPS_PROJECT_ID=2147483648"},
		{"worksnaps-api-key", "WORKSNAPS_API_KEY=" + strings.Repeat("A", 40) + "\nWORKSNAPS_PROJECT_ID=0"},
		{"worksnaps-api-key", "WORKSNAPS_API_KEY=" + strings.Repeat("A", 40) + "\nWORKSNAPS_PROJECT_ID=../users"},
		{"caflou-api-key", "CAFLOU_ACCESS_TOKEN=" + batch33Contracts[2].secret + "\nCAFLOU_ACCOUNT_ID=../accounts"},
	} {
		c := batch30Candidate(t, registry[tc.id], tc.input)
		if r := c.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
			t.Fatalf("%s: %+v", tc.id, r)
		}
	}
}

func TestThirtyThirdBatchFailuresAndCaps(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch33Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
		for _, mode := range []string{"network", "read", "oversize", "cancel", "timeout"} {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				switch mode {
				case "network":
					return nil, errors.New("private-data")
				case "read":
					return &http.Response{StatusCode: 200, Body: batch10FailingBody{}}, nil
				case "cancel":
					return nil, context.Canceled
				case "timeout":
					return nil, context.DeadlineExceeded
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.valid[0] + strings.Repeat(" ", maxVerificationResponseBytes)))}, nil
			})}
			r := c.Verify(WithVerificationHTTPClient(context.Background(), client))
			if r.Status != VerificationUnknown || r.Response != "" || calls != 1 || strings.Contains(r.Message, "private-data") {
				t.Fatalf("%s %s: %+v calls=%d", tc.id, mode, r, calls)
			}
		}
	}
}

func TestThirtyThirdBatchXMLDocumentIntegrity(t *testing.T) {
	valid := `<project><id>42</id><name>Project</name><status>active</status></project>`
	for _, body := range []string{
		valid + valid,
		`<html>` + valid + `</html>`,
		strings.Replace(valid, `<project>`, `<project xmlns="https://other.invalid">`, 1),
		strings.Replace(valid, `<id>42</id>`, `<id>42</id><id>42</id>`, 1),
		strings.Replace(valid, `<name>Project</name>`, `<name>Project</name><name>Project</name>`, 1),
		strings.Replace(valid, `<status>active</status>`, `<status>active</status><status>archived</status>`, 1),
		strings.Replace(valid, `<id>42</id>`, `<id><value>42</value></id>`, 1),
		strings.Replace(valid, `</project>`, `<description><error_code>401</error_code></description></project>`, 1),
		strings.Replace(valid, `</project>`, `<error_string>denied</error_string></project>`, 1),
		`<!DOCTYPE project [<!ENTITY token SYSTEM "https://other.invalid">]>` + strings.Replace(valid, "Project", "&token;", 1),
		valid + `<?xml version="1.0"?>`,
		valid[:len(valid)-1],
	} {
		if validWorksnapsProject([]byte(body), "42") {
			t.Fatalf("accepted malformed/ambiguous XML: %s", body)
		}
	}
	for _, body := range []string{valid, "\n" + valid + "\n", strings.Replace(valid, "active", "\n archived \n", 1), strings.Replace(valid, "Project", "<![CDATA[Project]]>", 1)} {
		if !validWorksnapsProject([]byte(body), "42") {
			t.Fatalf("rejected legitimate XML: %s", body)
		}
	}
}

func TestThirtyThirdBatchRecordIsolationAndCache(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("missing or contradictory record context sent a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch33Contracts {
		if tc.fields == "" {
			continue
		}
		d := registry[tc.id]
		key := tc.assignment + "=" + tc.secret
		c := batch30Candidate(t, d, key+"\n"+tc.fields)
		reverse := batch30Candidate(t, d, tc.fields+"\n"+key)
		field, value, _ := strings.Cut(tc.fields, "=")
		full, _ := json.Marshal(map[string]string{tc.assignment: tc.secret, field: value})
		structured := batch30Candidate(t, d, string(full))
		if c.VerificationCacheKey() != reverse.VerificationCacheKey() || c.VerificationCacheKey() != structured.VerificationCacheKey() {
			t.Fatalf("%s context identity depends on ordering or serialization", tc.id)
		}
		primary, _ := json.Marshal(map[string]string{tc.assignment: tc.secret})
		other, _ := json.Marshal(map[string]string{field: value})
		for _, input := range []string{
			key + "\n\n" + tc.fields,
			key + "\n[other]\n" + tc.fields,
			key + "\n---\n" + tc.fields,
			`[` + string(primary) + `,` + string(other) + `]`,
			`{"one":` + string(primary) + `,"two":` + string(other) + `}`,
			key + "\n" + tc.fields + "\n" + field + "=different",
			key + "\n" + tc.fields + " + suffix",
			key + "\n" + strings.Repeat("# padding\n", 70) + tc.fields,
		} {
			isolated := batch30Candidate(t, d, input)
			if isolated.VerificationCacheKey() == c.VerificationCacheKey() {
				t.Fatalf("%s unsupported context shares cache identity", tc.id)
			}
			if r := isolated.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("%s: %+v", tc.id, r)
			}
		}
	}
}
