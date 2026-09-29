package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestScanScopeInvalidatesCoverageChanges(t *testing.T) {
	flags := flag.NewFlagSet("scope", flag.ContinueOnError)
	flags.String("enable-detectors", "google-api-key", "")
	flags.Bool("scan-resume", false, "")
	flags.Bool("verify", false, "")
	custom := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(custom, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := func() string {
		t.Helper()
		h, err := scanJobScope(flags, []string{"detector"}, custom)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	original := scope()
	state := &scanJobState{}
	if err := state.validateScope(original, false); err != nil {
		t.Fatal(err)
	}
	state.Targets = map[string]scanJobTarget{"target": {Status: scanJobCompleted}}
	flags.Set("scan-resume", "true")
	if err := state.validateScope(scope(), true); err != nil {
		t.Fatalf("same configuration: %v", err)
	}
	flags.Set("enable-detectors", "github-token")
	if err := state.validateScope(scope(), true); err == nil {
		t.Fatal("changed detector accepted")
	}
	flags.Set("enable-detectors", "google-api-key")
	flags.Set("verify", "true")
	if err := state.validateScope(scope(), true); err == nil {
		t.Fatal("changed verification accepted")
	}
	flags.Set("verify", "false")
	if err := os.WriteFile(custom, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := state.validateScope(scope(), true); err == nil {
		t.Fatal("changed custom file accepted")
	}
	if err := (&scanJobState{}).validateScope(original, true); err == nil {
		t.Fatal("legacy state accepted")
	}
	if err := state.validateScope(scope(), false); err != nil {
		t.Fatal(err)
	}
	if len(state.Targets) != 0 {
		t.Fatal("fresh configuration retained completed targets")
	}
}
