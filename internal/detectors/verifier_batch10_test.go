package detectors

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var batch10Verifiers = []struct {
	id                  string
	verify              Verifier
	host, path, success string
}{
	{"runpod-api-key", verifyRunpod, "rest.runpod.io", "/v1/pods", `[{"id":"pod-1","desiredStatus":"RUNNING","env":{"PASSWORD":"private-metadata"}}]`},
	{"novita-api-key", verifyNovita, "api.novita.ai", "/openapi/v1/billing/balance/detail", `{"availableBalance":"1000000","cashBalance":"800000","creditLimit":"200000","pendingCharges":"0","outstandingInvoices":"0","private":"private-metadata"}`},
}

func TestTenthBatchReadOnlyRequestContracts(t *testing.T) {
	for _, tc := range batch10Verifiers {
		t.Run(tc.id, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != tc.host || req.URL.Path != tc.path || req.URL.RawQuery != "" || req.Header.Get("Authorization") != "Bearer synthetic-key" || req.Header.Get("Accept") != "application/json" || (req.Body != nil && req.Body != http.NoBody) {
					t.Fatalf("unexpected request: %s %s %#v", req.Method, req.URL, req.Header)
				}
				if tc.id == "novita-api-key" && req.Header.Get("Content-Type") != "application/json" {
					t.Fatal("missing documented content type")
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.success))}, nil
			})}
			found := false
			for _, detector := range DefaultRegistry() {
				if detector.Info().ID != tc.id {
					continue
				}
				found = true
				info := detector.Info()
				if info.VerificationSafety != VerificationSafetyReadOnly {
					t.Fatalf("unexpected safety: %s", info.VerificationSafety)
				}
				candidate := Candidate{Secret: "synthetic-key", Verifier: detector.(RegexDetector).Verifier, VerificationSafety: info.VerificationSafety}
				result := candidate.Verify(WithVerificationHTTPClient(context.Background(), client))
				if calls != 1 || result.Status != VerificationVerified || result.Response != "" {
					t.Fatalf("default-policy verification: calls=%d result=%+v", calls, result)
				}
			}
			if !found {
				t.Fatal("missing registry entry")
			}
		})
	}
}

func TestTenthBatchSuccessSchemas(t *testing.T) {
	cases := []struct {
		verify Verifier
		body   string
		want   VerificationStatus
	}{
		{verifyRunpod, `[]`, VerificationVerified},
		{verifyRunpod, `[{"id":"pod","desiredStatus":"EXITED"}]`, VerificationVerified},
		{verifyRunpod, `[{"id":"pod","desiredStatus":"TERMINATED"}]`, VerificationVerified},
		{verifyRunpod, `null`, VerificationUnknown},
		{verifyRunpod, `[null]`, VerificationUnknown},
		{verifyRunpod, `[{}]`, VerificationUnknown},
		{verifyRunpod, `[{"id":"pod"}]`, VerificationUnknown},
		{verifyRunpod, `[{"id":123,"desiredStatus":"RUNNING"}]`, VerificationUnknown},
		{verifyRunpod, `[{"id":" ","desiredStatus":"RUNNING"}]`, VerificationUnknown},
		{verifyRunpod, `[{"id":"pod","desiredStatus":"UNKNOWN"}]`, VerificationUnknown},
		{verifyRunpod, `[{"id":"pod","desiredStatus":"RUNNING"},{}]`, VerificationUnknown},
		{verifyRunpod, `{"pods":[]}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"0","cashBalance":"0"}`, VerificationVerified},
		{verifyNovita, `{"availableBalance":"-10000","cashBalance":"0"}`, VerificationVerified},
		{verifyNovita, `{"availableBalance":"123456789012345678901234567890","cashBalance":"0"}`, VerificationVerified},
		{verifyNovita, `{"availableBalance":"0"}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":0,"cashBalance":0}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":null,"cashBalance":"0"}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"NaN","cashBalance":"0"}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"","cashBalance":"0"}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"-","cashBalance":"0"}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"0","cashBalance":"0","creditLimit":null}`, VerificationUnknown},
		{verifyNovita, `{"availableBalance":"0","cashBalance":"0","error":"ACCESS_DENY"}`, VerificationUnknown},
		{verifyNovita, `{"data":[{"id":"public-model"}]}`, VerificationUnknown},
	}
	for _, tc := range cases {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
		})}
		result := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
		if result.Status != tc.want || result.Response != "" {
			t.Errorf("body=%s: got %+v, want %s", tc.body, result, tc.want)
		}
	}
}

func TestTenthBatchAmbiguousResponsesStayUnknown(t *testing.T) {
	for _, tc := range batch10Verifiers {
		t.Run(tc.id, func(t *testing.T) {
			for _, status := range []int{http.StatusCreated, http.StatusNoContent, http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
				for _, body := range []string{tc.success, `{"error":"INVALID_API_KEY","message":"private-metadata"}`, `{"error":"ACCESS_DENY"}`, `{"error":"NOT_ENOUGH_BALANCE"}`, `<html>private-metadata</html>`} {
					calls := 0
					client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						calls++
						return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					result := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
					if calls != 1 || result.Status != VerificationUnknown || result.Response != "" || strings.Contains(result.Message, "private-metadata") {
						t.Fatalf("status=%d calls=%d: %+v", status, calls, result)
					}
				}
			}
			for _, body := range []string{`{}`, `null`, `{"ok":true}`, `<html>success</html>`, tc.success + ` trailing garbage`} {
				client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})}
				result := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
				if result.Status != VerificationUnknown || result.Response != "" {
					t.Fatalf("malformed success: %+v", result)
				}
			}
		})
	}
}

type batch10FailingBody struct{}

func (batch10FailingBody) Read(p []byte) (int, error) {
	return copy(p, "private-metadata"), errors.New("private-metadata read failure")
}
func (batch10FailingBody) Close() error { return nil }

func TestTenthBatchTransportFailuresSuppressData(t *testing.T) {
	for _, tc := range batch10Verifiers {
		for _, transportError := range []error{errors.New("private-metadata network failure"), context.DeadlineExceeded, context.Canceled, nil} {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if transportError != nil {
					return nil, transportError
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: batch10FailingBody{}}, nil
			})}
			result := tc.verify(WithVerificationHTTPClient(context.Background(), client), "synthetic-key")
			if result.Status != VerificationUnknown || result.Response != "" || strings.Contains(result.Message, "private-metadata") {
				t.Fatalf("transport failure leaked data or classified key: %+v", result)
			}
		}
	}
}
