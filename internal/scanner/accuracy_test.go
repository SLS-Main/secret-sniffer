package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"secret-sniffer/internal/detectors"
)

// The corpus checks exact extraction and attribution as well as false positives,
// misses and duplicate findings. All credentials here are synthetic.
func TestAccuracyCorpus(t *testing.T) {
	type expected struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	var corpus []struct {
		Name  string
		Input string
		Want  []expected
	}
	b, err := os.ReadFile("testdata/accuracy.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	registry := detectors.DefaultRegistry()
	for _, tc := range corpus {
		t.Run(tc.Name, func(t *testing.T) {
			for _, encoded := range []bool{false, true} {
				input := tc.Input
				if encoded {
					input = base64.StdEncoding.EncodeToString([]byte(input))
				}
				s := New(Config{}, registry)
				findings := s.ScanContent(context.Background(), "fixture.txt", []byte(input))
				got := make([]expected, 0, len(findings))
				for _, f := range findings {
					got = append(got, expected{f.DetectorID, f.Secret})
					if encoded && (f.Provenance == nil || !reflect.DeepEqual(f.Provenance.DecoderChain, []string{"base64"})) {
						t.Errorf("missing decoded provenance: %+v", f.Provenance)
					}
				}
				sort.Slice(got, func(i, j int) bool { return got[i].ID+got[i].Secret < got[j].ID+got[j].Secret })
				sort.Slice(tc.Want, func(i, j int) bool { return tc.Want[i].ID+tc.Want[i].Secret < tc.Want[j].ID+tc.Want[j].Secret })
				if !reflect.DeepEqual(got, tc.Want) {
					t.Errorf("encoded=%v: got %+v, want %+v", encoded, got, tc.Want)
				}
			}
		})
	}
}

func TestConsolidationPreservesOtherOccurrences(t *testing.T) {
	value := "v9K2pQ7mX4rT8nW3"
	registry := []detectors.Detector{
		detectors.AssignedSecretDetector{},
		detectors.NewRegex("specific", "Specific", "high", nil, `provider password=([A-Za-z0-9]+)`, 1, nil),
	}
	s := New(Config{}, registry)
	input := "provider password=" + value + "\npassword=" + value
	got := s.ScanContent(context.Background(), "fixture.env", []byte(input))
	if len(got) != 2 {
		t.Fatalf("expected provider and separate generic occurrence, got %+v", got)
	}
	for _, f := range got {
		if f.DetectorID == "generic-assigned-secret" && f.Line != 2 {
			t.Fatal("generic consolidated at wrong occurrence")
		}
		if f.DetectorID == "specific" && f.Line != 1 {
			t.Fatal("provider location changed")
		}
	}
}
