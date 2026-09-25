package detectors

import (
	"strings"
	"testing"
)

func TestStructuredAssignmentValuesAndSpans(t *testing.T) {
	cases := []struct{ name, input, secret, source string }{
		{"YAML BOM", "\xef\xbb\xbfpassword: \"v9K2pQ7mX4rT8nW3\"", "v9K2pQ7mX4rT8nW3", "v9K2pQ7mX4rT8nW3"},
		{"JSON unicode", `{"label":"café 🔒","password":"v9K2pQ7mX4rT8nW3\u0021tail"}`, "v9K2pQ7mX4rT8nW3!tail", `v9K2pQ7mX4rT8nW3\u0021tail`},
		{"JSON surrogate pair", `{"password":"long-secret-phrase\uD83D\uDD12"}`, "long-secret-phrase🔒", `long-secret-phrase\uD83D\uDD12`},
		{"YAML unicode column", `label: {note: café, password: "v9K2pQ7mX4rT8nW3!tail"}`, "v9K2pQ7mX4rT8nW3!tail", "v9K2pQ7mX4rT8nW3!tail"},
		{"YAML single quotes", `password: 'it''s a real long password'`, "it's a real long password", "it''s a real long password"},
		{"YAML anchor", "password: &credential \"v9K2pQ7mX4rT8nW3\"\ncopy: *credential", "v9K2pQ7mX4rT8nW3", "v9K2pQ7mX4rT8nW3"},
		{"YAML scalar alias", "value: &credential \"v9K2pQ7mX4rT8nW3\"\npassword: *credential", "v9K2pQ7mX4rT8nW3", "v9K2pQ7mX4rT8nW3"},
		{"YAML string tag", `password: !!str "v9K2pQ7mX4rT8nW3"`, "v9K2pQ7mX4rT8nW3", "v9K2pQ7mX4rT8nW3"},
		{"YAML sequence block", "- password: |-\n    first-password-line\n    second-password-line\n  next: unrelated\n", "first-password-line\nsecond-password-line", "|-\n    first-password-line\n    second-password-line\n"},
		{"YAML CRLF block", "password: |-\r\n  first-password-line\r\n  second-password-line\r\nnext: unrelated\r\n", "first-password-line\nsecond-password-line", "|-\r\n  first-password-line\r\n  second-password-line\r\n"},
	}
	d := AssignedSecretDetector{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Detect([]byte(tc.input))
			if len(got) != 1 {
				t.Fatalf("got %d candidates: %+v", len(got), got)
			}
			c := got[0]
			if c.Secret != tc.secret {
				t.Errorf("got %q, want %q", c.Secret, tc.secret)
			}
			if c.Start < 0 || c.End < c.Start || c.End > len(tc.input) {
				t.Fatalf("invalid span: %+v", c)
			}
			if source := tc.input[c.Start:c.End]; source != tc.source {
				t.Errorf("source %q, want %q", source, tc.source)
			}
			if c.Start != strings.Index(tc.input, tc.source) {
				t.Errorf("incorrect source occurrence: %d", c.Start)
			}
		})
	}
}

func TestStructuredAssignmentsPreserveSiblingFields(t *testing.T) {
	input := `{"description":"password=not-an-assignment","nested":[{"password":"first-real-password!"}],"password":"second-real-password!"}`
	got := (AssignedSecretDetector{}).Detect([]byte(input))
	if len(got) != 2 || got[0].Secret != "first-real-password!" || got[1].Secret != "second-real-password!" {
		t.Fatalf("unexpected extraction: %+v", got)
	}
}

func TestStructuredAliasesDoNotExpandContainers(t *testing.T) {
	input := "recursive: &recursive\n  secret: *recursive\npassword: *recursive\n"
	if got := (AssignedSecretDetector{}).Detect([]byte(input)); len(got) != 0 {
		t.Fatalf("container alias became a secret: %+v", got)
	}
}

func FuzzStructuredAssignmentSpans(f *testing.F) {
	for _, seed := range []string{
		`{"password":"long-secret-phrase\uD83D\uDD12"}`,
		"password: |-\n  first-password-line\n  second-password-line\n",
		"value: &credential \"v9K2pQ7mX4rT8nW3\"\npassword: *credential",
		"recursive: &recursive\n  secret: *recursive\n",
		`password="unterminated-secret-value`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		for _, c := range (AssignedSecretDetector{}).Detect(input) {
			if c.Start < 0 || c.End < c.Start || c.End > len(input) {
				t.Fatalf("invalid source span [%d,%d) for %d bytes", c.Start, c.End, len(input))
			}
		}
	})
}
