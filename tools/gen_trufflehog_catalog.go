//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fatalf("usage: go run ./tools/gen_trufflehog_catalog.go <trufflehog-repo> <output>")
	}
	repo := os.Args[1]
	out := os.Args[2]

	commitOut, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		fatalf("read commit: %v", err)
	}
	commit := strings.TrimSpace(string(commitOut))

	listOut, err := exec.Command("git", "-C", repo, "ls-tree", "-d", "--name-only", "HEAD:pkg/detectors").Output()
	if err != nil {
		fatalf("list detectors: %v", err)
	}
	names := strings.Fields(string(listOut))
	sort.Strings(names)

	var b bytes.Buffer
	fmt.Fprintf(&b, "package parity\n\n")
	fmt.Fprintf(&b, "const GeneratedSnapshotCommit = %q\n\n", commit)
	fmt.Fprintf(&b, "var TruffleHogCatalog = []string{\n")
	for _, name := range names {
		fmt.Fprintf(&b, "\t%q,\n", name)
	}
	fmt.Fprintf(&b, "}\n")

	if err := os.WriteFile(out, b.Bytes(), 0o644); err != nil {
		fatalf("write output: %v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
