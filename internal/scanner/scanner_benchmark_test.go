package scanner

import (
	"bytes"
	"context"
	"testing"

	"secret-sniffer/internal/detectors"
)

func BenchmarkScanBytesClean(b *testing.B) {
	s := New(Config{Workers: 1, MaxFileBytes: 1024 * 1024}, detectors.DefaultRegistry())
	content := bytes.Repeat([]byte("ordinary application source without credentials\n"), 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.scanBytes(context.Background(), "source.txt", "", content)
	}
}

func BenchmarkScanBytesWithKeywords(b *testing.B) {
	s := New(Config{Workers: 1, MaxFileBytes: 1024 * 1024}, detectors.DefaultRegistry())
	content := bytes.Repeat([]byte("github stripe slack openai password token api_key ordinary source\n"), 1000)
	b.ReportAllocs()
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.scanBytes(context.Background(), "source.txt", "", content)
	}
}

func BenchmarkLineIndexLocation(b *testing.B) {
	content := bytes.Repeat([]byte("line content\n"), 10000)
	lines := newLineIndex(content)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lines.location((i * 97) % len(content))
	}
}
