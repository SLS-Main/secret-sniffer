package scanner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"secret-sniffer/internal/detectors"
)

type Config struct {
	Target       string
	Workers      int
	MaxFileBytes int64
	GitHistory   bool
	Verify       bool
	Include      []string
	Exclude      []string
	GitHubToken  string
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
	defaultExcludes := []string{"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.pdf", "*.zip", "*.tar", "*.gz", "*.7z", "*.exe", "*.dll", "*.so", "*.dylib"}
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
				if err == nil && !isBinary(b) {
					out <- s.scanBytes(path, "", b)
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
	for _, d := range s.detectors {
		for _, c := range d.Detect(b) {
			f := detectors.ToFinding(c, file, commit, b, s.cfg.Verify)
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
				if err == nil && !isBinary(b) {
					out <- s.scanBytes(o.path, o.hash, b)
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
