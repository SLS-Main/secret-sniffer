package pathfilter

import "testing"

func TestRecursiveGlobAndRegexFiltering(t *testing.T) {
	filter, err := New([]string{"src/**", "*.env"}, []string{"**/vendor/**"}, nil, []string{`(^|/)generated_[^/]+\.go$`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"src/deep/config.json":  true,
		"nested/production.env": true,
		"src/vendor/key.txt":    false,
		"src/generated_api.go":  false,
		"docs/readme.md":        false,
	}
	for name, want := range cases {
		if got := filter.Allowed(name); got != want {
			t.Fatalf("Allowed(%q)=%v, want %v", name, got, want)
		}
	}
}

func TestInvalidPatternsReturnErrors(t *testing.T) {
	if _, err := New([]string{"[broken"}, nil, nil, nil); err == nil {
		t.Fatal("expected invalid glob error")
	}
	if _, err := New(nil, nil, []string{"("}, nil); err == nil {
		t.Fatal("expected invalid regex error")
	}
}
