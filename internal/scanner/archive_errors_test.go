package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGzipChecksumFailures(t *testing.T) {
	var tarBytes bytes.Buffer
	tw := tar.NewWriter(&tarBytes)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name string
		data []byte
	}{
		{"file.gz", []byte("plain text")}, {"file.tar.gz", tarBytes.Bytes()},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write(fixture.data); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			data := buf.Bytes()
			data[len(data)-8] ^= 1
			s := New(Config{ScanArchives: true}, nil)
			if _, err := s.ScanContentWithError(context.Background(), fixture.name, data); err == nil {
				t.Fatal("checksum failure ignored")
			}
		})
	}
}

func TestArchiveFailuresAndPartialFindings(t *testing.T) {
	for _, name := range []string{"broken.zip", "broken.tar", "broken.gz", "broken.tar.gz", "broken.xz", "broken.bz2", "broken.7z"} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(file, []byte("invalid archive"), 0600); err != nil {
				t.Fatal(err)
			}
			s := New(Config{Target: file, Workers: 1, ScanArchives: true}, nil)
			if _, err := s.Scan(context.Background()); err == nil {
				t.Fatal("corrupt archive scan succeeded")
			}
		})
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, content string }{
		{"key.env", "GITHUB_TOKEN=ghp_" + strings.Repeat("A", 36)},
		{"nested.zip", "invalid archive"},
	} {
		w, err := z.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	s := New(Config{ScanArchives: true}, regressionRegistry("github-token"))
	fs, err := s.ScanContentWithError(context.Background(), "outer.zip", buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "outer.zip!/nested.zip") || len(fs) != 1 {
		t.Fatalf("findings=%d error=%v", len(fs), err)
	}
	s = New(Config{ScanArchives: true, MaxExpandedFileBytes: 1}, nil)
	if _, err := s.ScanContentWithError(context.Background(), "outer.zip", buf.Bytes()); err != nil {
		t.Fatalf("size exclusion became failure: %v", err)
	}
}
