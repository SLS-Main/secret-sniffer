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

var batch32Contracts = []struct {
	id, assignment, secret, fields, endpoint, header, prefix string
	valid, invalid                                           []string
}{
	{"pandadoc-api-key", "PANDADOC_API_KEY", strings.Repeat("A", 40), "", "https://api.pandadoc.com/public/v1/documents/folders?count=1&page=1", "Authorization", "API-Key ",
		[]string{`{"results":[]}`, `{"results":[{"uuid":"folder","name":"private-data","date_created":"2026-01-01T00:00:00Z","has_folders":false,"has_items":false}]}`},
		[]string{`{"results":null}`, `{"results":[{"uuid":"folder","name":"folder","date_created":"date","has_folders":"false","has_items":false}]}`, `{"results":[{"uuid":"folder","name":"folder","date_created":"date","has_folders":false,"has_items":null}]}`, `{"results":[{"uuid":"folder","name":"folder","date_created":"date","has_folders":false,"has_items":false,"error":"denied"}]}`}},
	{"appointedd-api-key", "APPOINTEDD_API_KEY", strings.Repeat("A", 85) + "+/=", "", "https://api.appointedd.com/v1/resources/groups?limit=1", "X-API-KEY", "",
		[]string{`{"data":[],"total":0,"prev":null,"next":null}`, `{"data":[{"id":"group","name":"private-data"}],"total":2,"next":"https://other.invalid"}`},
		[]string{`{"data":[],"total":"0"}`, `{"data":null,"total":0}`, `{"data":[{"id":1,"name":"group"}],"total":1}`, `{"data":[{"id":"group","name":"group","error":"denied"}],"total":1}`}},
	{"flexport-api-key", "FLEXPORT_ACCESS_TOKEN", "eyJ" + strings.Repeat("A", 36) + ".payload.signature", "FLEXPORT_API_URL=https://api.flexport.com", "https://api.flexport.com/network/me/companies", "Authorization", "Bearer ",
		[]string{`{"_object":"/api/response","version":2,"data":{"_object":"/network/company","id":"company","name":"private-data","editable":false}}`, `{"_object":"/api/response","version":2,"data":{"_object":"/network/company","id":"company","name":"company","editable":true,"entities":[],"contacts":{"link":"https://other.invalid"}}}`},
		[]string{`{"_object":"/api/response","version":3,"data":{"_object":"/network/company","id":"company","name":"company","editable":false}}`, `{"_object":"/api/response","version":"2","data":{"_object":"/network/company","id":"company","name":"company","editable":false}}`, `{"_object":"/api/response","version":2,"data":{"_object":"/network/contact","id":"company","name":"company","editable":false}}`, `{"_object":"/api/response","version":2,"data":{"_object":"/network/company","id":"company","name":"company","editable":null}}`, `{"_object":"/api/response","version":2,"data":{"_object":"/network/company","id":"company","name":"company","editable":false,"error":"denied"}}`}},
	{"gyazo-api-token", "GYAZO_ACCESS_TOKEN", strings.Repeat("A", 40), "", "https://api.gyazo.com/api/users/me", "Authorization", "Bearer ",
		[]string{`{"user":{"uid":"user","email":"private-data","name":null,"profile_image":null}}`, `{"user":{"uid":"user","email":"email","name":"","profile_image":""}}`},
		[]string{`{"uid":"user","email":"email"}`, `{"user":null}`, `{"user":{"uid":1,"email":"email"}}`, `{"user":{"uid":"user","email":""}}`, `{"user":{"uid":"user","email":"email","error":"denied"}}`}},
	{"happyscribe-api-key", "HAPPYSCRIBE_API_KEY", strings.Repeat("A", 24), "", "https://www.happyscribe.com/api/v1/organizations", "Authorization", "Bearer ",
		[]string{`{"organizations":[]}`, `{"organizations":[{"id":1,"name":"private-data","role":"guest","createdAt":"date","updatedAt":"date"}]}`, `{"organizations":[{"id":2,"name":"org","role":"owner","createdAt":"date","updatedAt":"date","membersCount":0,"isHumanTranscriptionAllowed":false}]}`},
		[]string{`{"organizations":null}`, `{"organizations":[{"id":"1","name":"org","role":"guest","createdAt":"date","updatedAt":"date"}]}`, `{"organizations":[{"id":1,"name":"org","role":null,"createdAt":"date","updatedAt":"date"}]}`, `{"organizations":[{"id":1,"name":"org","role":"guest","createdAt":"date","updatedAt":"date","error":"denied"}]}`}},
}

var batch32Blocked = []struct{ id, input, secret, category string }{
	{"google-api-key", "key=AIza" + strings.Repeat("A", 35), "AIza" + strings.Repeat("A", 35), "verification_context"},
	{"abstract-api-key", "abstract api_key=" + strings.Repeat("a", 32), strings.Repeat("a", 32), "verification_context"},
	{"apilayer-key", "apilayer key=" + strings.Repeat("A", 32), strings.Repeat("A", 32), "verification_context"},
	{"configcat-sdk-key", "configcat sdk_key=" + strings.Repeat("A", 22) + "/" + strings.Repeat("B", 22), strings.Repeat("A", 22) + "/" + strings.Repeat("B", 22), "verification_context"},
	{"greenhouse-harvest-api-key", "harvest.greenhouse.io api_key=" + strings.Repeat("A", 40), strings.Repeat("A", 40), "credential_type"},
}

func TestThirtySecondBatchContracts(t *testing.T) {
	registry := batch30Registry()
	if len(batch32Contracts)+len(batch32Blocked) != 10 {
		t.Fatal("expected ten dispositions")
	}
	for _, tc := range batch32Contracts {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
			if c.Secret != tc.secret || c.VerificationSafety != VerificationSafetyReadOnly {
				t.Fatalf("unexpected candidate: %+v", c)
			}
			bodies := append(append([]string{}, tc.valid...), tc.invalid...)
			bodies = append(bodies, `{}`, `null`, `[]`, `"OK"`, `<html>Login</html>`, tc.valid[0]+" trailing")
			for _, field := range []string{"error", "errors", "error_code"} {
				var obj identityPayload
				_ = json.Unmarshal([]byte(tc.valid[0]), &obj)
				obj[field] = json.RawMessage(`"private-data"`)
				raw, _ := json.Marshal(obj)
				bodies = append(bodies, string(raw))
			}
			for _, status := range []int{200, 201, 204, 301, 302, 307, 400, 401, 402, 403, 404, 429, 500, 503} {
				for i, body := range bodies {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.Method != http.MethodGet || req.URL.String() != tc.endpoint || req.Body != nil || req.Header.Get(tc.header) != tc.prefix+tc.secret || req.Header.Get("Accept") != "application/json" {
							t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
						}
						if tc.id == "flexport-api-key" && req.Header.Get("Flexport-Version") != "2" {
							t.Fatal("missing freight API version")
						}
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid"}, "Link": []string{"<https://other.invalid>; rel=next"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					result := c.Verify(WithVerificationHTTPClient(context.Background(), client))
					want := VerificationUnknown
					if status == 200 && i < len(tc.valid) {
						want = VerificationVerified
					}
					if calls != 1 || result.Status != want || result.Response != "" || strings.Contains(result.Message, "private-data") {
						t.Fatalf("status=%d body=%s calls=%d result=%+v", status, body, calls, result)
					}
				}
			}
		})
	}
}

func TestThirtySecondBatchBlockedNoNetwork(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("blocked verifier sent a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch32Blocked {
		t.Run(tc.id, func(t *testing.T) {
			c := batch30Candidate(t, registry[tc.id], tc.input)
			if c.Secret != tc.secret || registry[tc.id].Info().VerificationSafety != VerificationSafetyUnreviewed {
				t.Fatalf("%+v", c)
			}
			if r := c.Verify(ctx); r.Status != VerificationNotAttempted || r.ErrorCategory != "unreviewed_verification_disabled" {
				t.Fatalf("%+v", r)
			}
			for _, policy := range []VerificationPolicy{{AllowUnreviewed: true}, {AllowUnreviewed: true, AllowUnsafe: true}} {
				r := c.VerifyWithPolicy(ctx, policy)
				if r.Status != VerificationUnknown || r.ErrorCategory != tc.category || r.Response != "" || strings.Contains(r.Message, c.Secret) {
					t.Fatalf("%+v", r)
				}
			}
			if r := registry[tc.id].(RegexDetector).Verifier(ctx, tc.secret); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("direct entry point: %+v", r)
			}
			for _, suffix := range []string{"+suffix", "=suffix", "~suffix"} {
				if got := registry[tc.id].Detect([]byte(tc.input + suffix)); len(got) != 0 {
					t.Fatalf("accepted truncated credential: %s", tc.id)
				}
			}
		})
	}
}

func TestThirtySecondBatchUnsupportedContext(t *testing.T) {
	registry := batch30Registry()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported context sent a request")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, tc := range batch32Contracts {
		c := batch30Candidate(t, registry[tc.id], tc.assignment+"="+tc.secret+"\n"+tc.fields)
		for _, endpoint := range []string{"", "https://evil.invalid", "https://api.flexport.com.evil.invalid", "https://api.flexport.com:443", "http://api.flexport.com", "https://user@api.flexport.com", "https://api.flexport.com?test=1", "https://api.flexport.com#fragment"} {
			altered := c
			altered.SecretParts = cloneStringMap(c.SecretParts)
			if altered.SecretParts == nil {
				altered.SecretParts = map[string]string{}
			}
			altered.SecretParts["endpoint"] = endpoint
			if r := altered.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
				t.Fatalf("%s %+v", tc.id, r)
			}
		}
		for _, suffix := range []string{"+suffix", "=suffix"} {
			if got := registry[tc.id].Detect([]byte(tc.assignment + "=" + tc.secret + suffix)); len(got) != 0 {
				t.Fatalf("%s accepted token prefix", tc.id)
			}
		}
	}
	secret := strings.Repeat("A", 40)
	for _, tc := range []struct{ id, input string }{
		{"pandadoc-api-key", "PANDADOC_CLIENT_SECRET=" + secret},
		{"pandadoc-api-key", "PANDADOC_ACCESS_TOKEN=" + secret + "\nPANDADOC_CREDENTIAL_TYPE=api_key"},
		{"gyazo-api-token", "GYAZO_CLIENT_SECRET=" + secret},
		{"gyazo-api-token", "GYAZO_CLIENT_SECRET=" + secret + "\nGYAZO_CREDENTIAL_TYPE=bearer"},
		{"flexport-api-key", "flexport key=shltm_" + secret},
		{"flexport-api-key", "FLEXPORT_ACCESS_TOKEN=shltm_" + secret + "\nFLEXPORT_API_URL=https://api.flexport.com"},
		{"flexport-api-key", "FLEXPORT_ACCESS_TOKEN=" + secret},
		{"flexport-api-key", "FLEXPORT_CLIENT_SECRET=" + secret + "\nFLEXPORT_API_URL=https://api.flexport.com"},
		{"flexport-api-key", "FLEXPORT_CLIENT_SECRET=" + secret + "\nFLEXPORT_CREDENTIAL_TYPE=bearer\nFLEXPORT_API_URL=https://api.flexport.com"},
		{"flexport-api-key", "FLEXPORT_ACCESS_TOKEN=" + secret + "\nFLEXPORT_API_URL=https://logistics-api.flexport.com"},
	} {
		c := batch30Candidate(t, registry[tc.id], tc.input)
		if r := c.Verify(ctx); r.Status != VerificationUnknown || r.Response != "" {
			t.Fatalf("%s %+v", tc.id, r)
		}
	}
}

func TestThirtySecondBatchFailuresAndCaps(t *testing.T) {
	registry := batch30Registry()
	for _, tc := range batch32Contracts {
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

func TestThirtySecondBatchPandaDocCredentialRouting(t *testing.T) {
	d := batch30Registry()["pandadoc-api-key"]
	secret := strings.Repeat("A", 40)
	key := batch30Candidate(t, d, "PANDADOC_API_KEY="+secret)
	token := batch30Candidate(t, d, "PANDADOC_ACCESS_TOKEN="+secret)
	if key.VerificationCacheKey() == token.VerificationCacheKey() {
		t.Fatal("authentication families share a cache entry")
	}
	for _, c := range []Candidate{key, token} {
		client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			prefix := "API-Key "
			if c.SecretParts["credential_type"] == "bearer" {
				prefix = "Bearer "
			}
			if req.Header.Get("Authorization") != prefix+secret {
				t.Fatal("incorrect PandaDoc authentication family")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"results":[]}`))}, nil
		})}
		if r := c.Verify(WithVerificationHTTPClient(context.Background(), client)); r.Status != VerificationVerified {
			t.Fatalf("%+v", r)
		}
	}
}

func TestThirtySecondBatchFreightContextIsolation(t *testing.T) {
	d := batch30Registry()["flexport-api-key"]
	secret := strings.Repeat("A", 40)
	key := "FLEXPORT_ACCESS_TOKEN=" + secret
	base := "FLEXPORT_API_URL=https://api.flexport.com"
	c := batch30Candidate(t, d, key+"\n"+base)
	reverse := batch30Candidate(t, d, base+"\n"+key)
	structured := batch30Candidate(t, d, `{"FLEXPORT_ACCESS_TOKEN":"`+secret+`","FLEXPORT_API_URL":"https://api.flexport.com"}`)
	if c.VerificationCacheKey() != reverse.VerificationCacheKey() || c.VerificationCacheKey() != structured.VerificationCacheKey() {
		t.Fatal("equivalent contexts have different cache identities")
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("borrowed or conflicting freight context sent")
		return nil, nil
	})}
	ctx := WithVerificationHTTPClient(context.Background(), client)
	for _, input := range []string{
		key + "\n\n" + base,
		key + "\n[other]\n" + base,
		key + "\n---\n" + base,
		`[{"FLEXPORT_ACCESS_TOKEN":"` + secret + `"},{"FLEXPORT_API_URL":"https://api.flexport.com"}]`,
		key + "\n" + base + "\nFLEXPORT_API_URL=https://other.invalid",
		key + "\n" + base + "#fragment",
		key + "\n" + base + " + suffix",
		key + "\n" + base + "\nFLEXPORT_CLIENT_SECRET=" + strings.Repeat("B", 40),
	} {
		candidates := d.Detect([]byte(input))
		if len(candidates) == 0 {
			t.Fatalf("missing detection: %s", input)
		}
		for _, candidate := range candidates {
			if candidate.VerificationCacheKey() == c.VerificationCacheKey() {
				t.Fatalf("unsupported context shared valid cache identity: %s", input)
			}
			if r := candidate.Verify(ctx); r.Status != VerificationUnknown {
				t.Fatalf("%+v", r)
			}
		}
	}
}
