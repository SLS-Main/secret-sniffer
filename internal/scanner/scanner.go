package scanner

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"secret-sniffer/internal/detectors"
)

var base64CandidateRe = regexp.MustCompile(`\b[A-Za-z0-9+/_-]{20,}={0,2}\b`)

const maxBase64CandidateBytes = 8192

type Config struct {
	Target       string
	Workers      int
	MaxFileBytes int64
	GitHistory   bool
	Verify       bool
	Include      []string
	Exclude      []string
	GitHubToken  string

	ScanArchives         bool
	MaxArchiveDepth      int
	MaxArchiveEntries    int
	MaxArchiveBytes      int64
	MaxExpandedFileBytes int64
}

type Scanner struct {
	cfg       Config
	detectors []detectors.Detector
}

func New(cfg Config, ds []detectors.Detector) *Scanner { return &Scanner{cfg: cfg, detectors: ds} }

func (s *Scanner) Scan(ctx context.Context) ([]detectors.Finding, error) {
	target := s.cfg.Target
	cleanup := func() {}
	if isGitHubURL(target) {
		dir, err := os.MkdirTemp("", "secret-sniffer-*")
		if err != nil {
			return nil, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		defer cleanup()
		cmd := exec.CommandContext(ctx, "git", "clone", "--quiet", githubCloneURL(target, s.cfg.GitHubToken), dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git clone failed for %s: %w: %s", target, err, string(out))
		}
		target = dir
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return s.scanFiles(ctx, []string{target})
	}

	var findings []detectors.Finding
	if s.cfg.GitHistory && isGitRepo(target) {
		gitFindings, err := s.scanGitHistory(ctx, target)
		if err != nil {
			return nil, err
		}
		findings = append(findings, gitFindings...)
	}
	files, err := s.collectFiles(target)
	if err != nil {
		return nil, err
	}
	worktreeFindings, err := s.scanFiles(ctx, files)
	if err != nil {
		return nil, err
	}
	findings = append(findings, worktreeFindings...)
	return dedupe(findings), nil
}

func (s *Scanner) collectFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > s.cfg.MaxFileBytes {
			return nil
		}
		if !s.allowedPath(root, path) {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, err
}

func (s *Scanner) allowedPath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)

	if len(s.cfg.Include) > 0 && !matchAny(s.cfg.Include, rel, base) {
		return false
	}
	defaultExcludes := []string{"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.pdf", "*.7z", "*.exe", "*.dll", "*.so", "*.dylib"}
	if !s.cfg.ScanArchives {
		defaultExcludes = append(defaultExcludes, "*.zip", "*.tar", "*.gz", "*.tgz")
	}
	if matchAny(defaultExcludes, rel, base) || matchAny(s.cfg.Exclude, rel, base) {
		return false
	}
	return true
}

func (s *Scanner) scanFiles(ctx context.Context, files []string) ([]detectors.Finding, error) {
	jobs := make(chan string)
	out := make(chan []detectors.Finding)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				b, err := os.ReadFile(path)
				if err == nil {
					out <- s.scanBlob(ctx, path, "", b, 0)
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	go func() {
		defer close(jobs)
		for _, f := range files {
			select {
			case <-ctx.Done():
				return
			case jobs <- f:
			}
		}
	}()

	var findings []detectors.Finding
	for fs := range out {
		findings = append(findings, fs...)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return dedupe(findings), nil
}

func (s *Scanner) scanBytes(file, commit string, b []byte) []detectors.Finding {
	seen := map[string]struct{}{}
	var findings []detectors.Finding
	findings = append(findings, s.scanByteView(file, commit, b, b, seen)...)
	findings = append(findings, s.scanDecodedBase64(file, commit, b, seen)...)
	return findings
}

func (s *Scanner) scanByteView(file, commit string, source, view []byte, seen map[string]struct{}) []detectors.Finding {
	var findings []detectors.Finding
	for _, d := range s.detectors {
		for _, c := range d.Detect(view) {
			f := detectors.ToFinding(c, file, commit, source, s.cfg.Verify)
			key := f.DetectorID + "\x00" + f.Secret + "\x00" + f.File + "\x00" + f.Commit
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, f)
		}
	}
	return findings
}

func (s *Scanner) scanDecodedBase64(file, commit string, b []byte, seen map[string]struct{}) []detectors.Finding {
	matches := base64CandidateRe.FindAllIndex(b, -1)
	decodedSeen := map[string]struct{}{}
	var findings []detectors.Finding
	for _, m := range matches {
		encoded := b[m[0]:m[1]]
		if len(encoded) > maxBase64CandidateBytes || !plausibleBase64Candidate(encoded) {
			continue
		}
		decoded, ok := decodeBase64Candidate(encoded)
		if !ok || len(decoded) < 8 || isBinary(decoded) {
			continue
		}
		decodedKey := string(decoded)
		if _, ok := decodedSeen[decodedKey]; ok {
			continue
		}
		decodedSeen[decodedKey] = struct{}{}
		for _, d := range s.detectors {
			for _, c := range d.Detect(decoded) {
				// Report the source line/column of the encoded blob while preserving
				// the decoded secret value for remediation.
				c.Start = m[0]
				c.End = m[1]
				f := detectors.ToFinding(c, file, commit, b, s.cfg.Verify)
				key := f.DetectorID + "\x00" + f.Secret + "\x00" + f.File + "\x00" + f.Commit
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, f)
			}
		}
	}
	return findings
}

func plausibleBase64Candidate(b []byte) bool {
	if len(b)%4 == 1 {
		return false
	}
	if bytes.Count(b, []byte("-"))+bytes.Count(b, []byte("_")) > 0 && bytes.Count(b, []byte("+"))+bytes.Count(b, []byte("/")) > 0 {
		return false
	}
	return true
}

func decodeBase64Candidate(b []byte) ([]byte, bool) {
	s := string(b)
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(s)
		if err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}
	return nil, false
}

func (s *Scanner) scanGitHistory(ctx context.Context, repo string) ([]detectors.Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "rev-list", "--objects", "--all")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	type obj struct{ hash, path string }
	jobs := make(chan obj)
	out := make(chan []detectors.Finding)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range jobs {
				if o.path == "" {
					continue
				}
				b, err := gitBlob(ctx, repo, o.hash, s.cfg.MaxFileBytes)
				if err == nil {
					out <- s.scanBlob(ctx, o.path, o.hash, b, 0)
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()

	scan := bufio.NewScanner(stdout)
	seenObjects := map[string]struct{}{}
	go func() {
		defer close(jobs)
		for scan.Scan() {
			line := scan.Text()
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				if _, ok := seenObjects[parts[0]]; ok {
					continue
				}
				seenObjects[parts[0]] = struct{}{}
				select {
				case <-ctx.Done():
					return
				case jobs <- obj{parts[0], parts[1]}:
				}
			}
		}
	}()

	var findings []detectors.Finding
	for fs := range out {
		findings = append(findings, fs...)
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	if scan.Err() != nil {
		return nil, scan.Err()
	}
	return dedupe(findings), nil
}

func gitBlob(ctx context.Context, repo, hash string, max int64) ([]byte, error) {
	typeCmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "-t", hash)
	t, err := typeCmd.Output()
	if err != nil || strings.TrimSpace(string(t)) != "blob" {
		return nil, errors.New("not blob")
	}
	sizeCmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "-s", hash)
	szOut, err := sizeCmd.Output()
	if err != nil {
		return nil, err
	}
	var size int64
	_, _ = fmt.Sscanf(string(szOut), "%d", &size)
	if size > max {
		return nil, errors.New("blob too large")
	}
	cat := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "-p", hash)
	return cat.Output()
}

func (s *Scanner) scanBlob(ctx context.Context, file, commit string, b []byte, depth int) []detectors.Finding {
	if ctx.Err() != nil {
		return nil
	}
	if s.cfg.ScanArchives && depth <= s.maxArchiveDepth() && archiveKind(file) != "" {
		return s.scanArchiveBytes(ctx, file, commit, b, depth)
	}
	if isBinary(b) {
		return nil
	}
	return s.scanBytes(file, commit, b)
}

func (s *Scanner) scanArchiveBytes(ctx context.Context, file, commit string, b []byte, depth int) []detectors.Finding {
	switch archiveKind(file) {
	case "zip":
		return s.scanZip(ctx, file, commit, b, depth)
	case "tar":
		return s.scanTar(ctx, file, commit, bytes.NewReader(b), depth)
	case "targz":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		defer zr.Close()
		return s.scanTar(ctx, file, commit, zr, depth)
	case "gz":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		defer zr.Close()
		name := strings.TrimSuffix(file, ".gz")
		if name == file {
			name = file + "!/decompressed"
		} else {
			name = file + "!/" + path.Base(name)
		}
		entry, ok := readLimited(zr, s.maxExpandedFileBytes())
		if !ok {
			return nil
		}
		return s.scanBlob(ctx, name, commit, entry, depth+1)
	}
	return nil
}

func (s *Scanner) scanZip(ctx context.Context, file, commit string, b []byte, depth int) []detectors.Finding {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}
	var findings []detectors.Finding
	var expanded int64
	entries := 0
	for _, entry := range zr.File {
		if ctx.Err() != nil || entries >= s.maxArchiveEntries() || expanded >= s.maxArchiveBytes() {
			break
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		name, ok := safeArchivePath(entry.Name)
		if !ok {
			continue
		}
		if entry.UncompressedSize64 > uint64(s.maxExpandedFileBytes()) {
			continue
		}
		r, err := entry.Open()
		if err != nil {
			continue
		}
		content, ok := readLimited(r, s.maxExpandedFileBytes())
		_ = r.Close()
		if !ok {
			continue
		}
		if expanded+int64(len(content)) > s.maxArchiveBytes() {
			break
		}
		expanded += int64(len(content))
		entries++
		findings = append(findings, s.scanBlob(ctx, file+"!/"+name, commit, content, depth+1)...)
	}
	return findings
}

func (s *Scanner) scanTar(ctx context.Context, file, commit string, r io.Reader, depth int) []detectors.Finding {
	tr := tar.NewReader(r)
	var findings []detectors.Finding
	var expanded int64
	entries := 0
	for {
		if ctx.Err() != nil || entries >= s.maxArchiveEntries() || expanded >= s.maxArchiveBytes() {
			break
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		name, ok := safeArchivePath(h.Name)
		if !ok || h.Size > s.maxExpandedFileBytes() {
			continue
		}
		content, ok := readLimited(tr, s.maxExpandedFileBytes())
		if !ok {
			continue
		}
		if expanded+int64(len(content)) > s.maxArchiveBytes() {
			break
		}
		expanded += int64(len(content))
		entries++
		findings = append(findings, s.scanBlob(ctx, file+"!/"+name, commit, content, depth+1)...)
	}
	return findings
}

func archiveKind(file string) string {
	file = strings.ToLower(file)
	switch {
	case strings.HasSuffix(file, ".zip"):
		return "zip"
	case strings.HasSuffix(file, ".tar"):
		return "tar"
	case strings.HasSuffix(file, ".tar.gz") || strings.HasSuffix(file, ".tgz"):
		return "targz"
	case strings.HasSuffix(file, ".gz"):
		return "gz"
	default:
		return ""
	}
}

func safeArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.HasPrefix(name, "/") {
		return "", false
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", false
	}
	return clean, true
}

func readLimited(r io.Reader, max int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}

func (s *Scanner) maxArchiveDepth() int {
	if s.cfg.MaxArchiveDepth <= 0 {
		return 2
	}
	return s.cfg.MaxArchiveDepth
}

func (s *Scanner) maxArchiveEntries() int {
	if s.cfg.MaxArchiveEntries <= 0 {
		return 10000
	}
	return s.cfg.MaxArchiveEntries
}

func (s *Scanner) maxArchiveBytes() int64 {
	if s.cfg.MaxArchiveBytes <= 0 {
		return 250 * 1024 * 1024
	}
	return s.cfg.MaxArchiveBytes
}

func (s *Scanner) maxExpandedFileBytes() int64 {
	if s.cfg.MaxExpandedFileBytes > 0 {
		return s.cfg.MaxExpandedFileBytes
	}
	if s.cfg.MaxFileBytes > 0 {
		return s.cfg.MaxFileBytes
	}
	return 25 * 1024 * 1024
}

func isGitRepo(path string) bool { _, err := os.Stat(filepath.Join(path, ".git")); return err == nil }

func isGitHubURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	h := strings.ToLower(u.Host)
	return h == "github.com" || h == "www.github.com"
}

func githubCloneURL(raw, token string) string {
	if token == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	if strings.ToLower(u.Host) != "github.com" && strings.ToLower(u.Host) != "www.github.com" {
		return raw
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String()
}

func isBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0
}

func dedupe(in []detectors.Finding) []detectors.Finding {
	seen := map[string]struct{}{}
	out := make([]detectors.Finding, 0, len(in))
	for _, f := range in {
		if _, ok := seen[f.Fingerprint]; ok {
			continue
		}
		seen[f.Fingerprint] = struct{}{}
		out = append(out, f)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func matchAny(patterns []string, rel, base string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	return false
}
