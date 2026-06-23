package main

import (
	"testing"
	"time"
)

func TestShouldRefreshToken(t *testing.T) {
	now := time.Unix(1000, 0)
	if !shouldRefreshToken(time.Time{}, now) {
		t.Fatal("zero expiry should refresh")
	}
	if !shouldRefreshToken(now.Add(9*time.Minute), now) {
		t.Fatal("token inside refresh window should refresh")
	}
	if shouldRefreshToken(now.Add(11*time.Minute), now) {
		t.Fatal("token outside refresh window should not refresh")
	}
}

func TestDefaultOutputPath(t *testing.T) {
	cases := map[string]string{
		"json":  "secret-sniffer-findings.json",
		"jsonl": "secret-sniffer-findings.jsonl",
		"sarif": "secret-sniffer-findings.sarif",
		"human": "",
	}
	for format, want := range cases {
		if got := defaultOutputPath(format); got != want {
			t.Fatalf("defaultOutputPath(%q)=%q, want %q", format, got, want)
		}
	}
}
