package scanner

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bodgit/sevenzip"
	"github.com/ulikunitz/xz"

	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/pathfilter"
	"secret-sniffer/internal/progress"
)

var base64CandidateRe = regexp.MustCompile(`\b[A-Za-z0-9+/_-]{20,}={0,2}\b`)

const maxBase64CandidateBytes = 8192

type Config struct {
	Target                 string
	Workers                int
	MaxFileBytes           int64
	GitHistory             bool
	GitMaxDepth            int
	GitSinceCommit         string
	GitRanges              []string
	GitRefs                []string
	GitBranches            []string
	GitAdditionalRefs      string
	GitAuthorizationHeader string
	Verify                 bool
	Include                []string
	Exclude                []string
	ExcludeExtensions      []string
	IncludeRegex           []string
	ExcludeRegex           []string
	GitHubToken            string
	Progress               progress.ProgressReporter
	FindingCallback        func([]detectors.Finding) error

	ScanArchives         bool
	MaxArchiveDepth      int
	MaxArchiveEntries    int
	MaxArchiveBytes      int64
	MaxExpandedFileBytes int64
}

type Scanner struct {
	cfg          Config
	plan         detectorPlan
	verification *verificationCache
	instanceID   uint64
	pathFilter   *pathfilter.Filter
	configErr    error
	emitMu       sync.Mutex
	emitted      map[string]struct{}
	remoteRoot   string
	remoteTarget string
}

var nextScannerID atomic.Uint64

func New(cfg Config, ds []detectors.Detector) *Scanner {
	filter, err := newPathFilter(cfg)
	return &Scanner{cfg: cfg, plan: newDetectorPlan(ds), verification: newVerificationCache(), instanceID: nextScannerID.Add(1), pathFilter: filter, configErr: err, emitted: map[string]struct{}{}}
}

func (s *Scanner) emitFindings(findings []detectors.Finding) error {
	if s.cfg.FindingCallback == nil || len(findings) == 0 {
		return nil
	}
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	unique := make([]detectors.Finding, 0, len(findings))
	for _, finding := range findings {
		if _, exists := s.emitted[finding.Fingerprint]; exists {
			continue
		}
		s.emitted[finding.Fingerprint] = struct{}{}
		unique = append(unique, finding)
	}
	if len(unique) == 0 {
		return nil
	}
	return s.cfg.FindingCallback(unique)
}

func ValidateConfig(cfg Config) error {
	_, err := newPathFilter(cfg)
	return err
}

func newPathFilter(cfg Config) (*pathfilter.Filter, error) {
	exclude := append([]string{}, cfg.Exclude...)
	exclude = append(exclude, "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.exe", "*.dll", "*.so", "*.dylib")
	if !cfg.ScanArchives {
		exclude = append(exclude, "*.zip", "*.tar", "*.gz", "*.tgz", "*.7z", "*.xz", "*.bz2", "*.jar", "*.war", "*.ear", "*.whl", "*.nupkg", "*.apk")
	}
	return pathfilter.New(cfg.Include, exclude, cfg.IncludeRegex, cfg.ExcludeRegex)
}

// ScanContent applies the configured detector pipeline to content from a remote source.
func (s *Scanner) ScanContent(ctx context.Context, name string, content []byte) []detectors.Finding {
	return dedupe(s.scanBlob(ctx, name, "", content, 0))
}

// AllowsRemotePath reports whether a remote object key passes the configured path filters.
func (s *Scanner) AllowsRemotePath(name string) bool {
	return s.allowedRelPath(name)
}

func (s *Scanner) RemotePathSkipReason(name string) string {
	extension := strings.TrimPrefix(strings.ToLower(path.Ext(name)), ".")
	if slices.Contains(s.cfg.ExcludeExtensions, extension) {
		return "extension_excluded"
	}
	if !s.allowedRelPath(name) {
		return "path_excluded"
	}
	return ""
}

type plannedDetector struct {
	detector detectors.Detector
	id       string
	filtered bool
}

type detectorPlan struct {
	detectors []plannedDetector
	always    []int
	keyword   map[string][]int
}

func newDetectorPlan(ds []detectors.Detector) detectorPlan {
	plan := detectorPlan{keyword: map[string][]int{}}
	for _, d := range ds {
		info := d.Info()
		index := len(plan.detectors)
		plan.detectors = append(plan.detectors, plannedDetector{detector: d, id: info.ID, filtered: len(info.Keywords) > 0})
		if len(info.Keywords) == 0 {
			plan.always = append(plan.always, index)
			continue
		}
		seenKeywords := map[string]struct{}{}
		for _, kw := range info.Keywords {
			kw = strings.ToLower(strings.TrimSpace(kw))
			if kw == "" {
				continue
			}
			if _, ok := seenKeywords[kw]; ok {
				continue
			}
			seenKeywords[kw] = struct{}{}
			plan.keyword[kw] = append(plan.keyword[kw], index)
		}
		if len(seenKeywords) == 0 {
			plan.detectors[index].filtered = false
			plan.always = append(plan.always, index)
		}
	}
	return plan
}

func (p detectorPlan) selectDetectors(b []byte) []plannedDetector {
	if len(p.keyword) == 0 {
		return p.detectors
	}
	low := strings.ToLower(string(b))
	out := make([]plannedDetector, 0, len(p.always)+8)
	seen := make([]bool, len(p.detectors))
	for _, index := range p.always {
		seen[index] = true
		out = append(out, p.detectors[index])
	}
	for kw, indexes := range p.keyword {
		if !strings.Contains(low, kw) {
			continue
		}
		for _, index := range indexes {
			if seen[index] {
				continue
			}
			seen[index] = true
			out = append(out, p.detectors[index])
		}
	}
	return out
}

func detectPlanned(d plannedDetector, b []byte) []detectors.Candidate {
	if d.filtered {
		if prefiltered, ok := d.detector.(detectors.PrefilteredDetector); ok {
			return prefiltered.DetectPrefiltered(b)
		}
	}
	return d.detector.Detect(b)
}

type verificationCache struct {
	mu      sync.Mutex
	entries map[string]*verificationEntry
}

type verificationEntry struct {
	result detectors.VerificationResult
	ready  chan struct{}
}

func newVerificationCache() *verificationCache {
	return &verificationCache{entries: map[string]*verificationEntry{}}
}

func (c *verificationCache) verify(ctx context.Context, candidate detectors.Candidate) detectors.VerificationResult {
	if candidate.Verifier == nil {
		return detectors.VerificationResult{Status: detectors.VerificationUnsupported}
	}
	verifierID := reflect.ValueOf(candidate.Verifier).Pointer()
	key := candidate.DetectorID + "\x00" + candidate.Secret + "\x00" + strconv.FormatUint(uint64(verifierID), 16)
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return detectors.VerificationResult{Status: detectors.VerificationUnknown, ErrorCategory: "cancelled", Message: "verification cancelled"}
		case <-entry.ready:
			return entry.result
		}
	}
	entry := &verificationEntry{ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	verifyCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	entry.result = candidate.Verifier(verifyCtx, candidate.Secret)
	cancel()
	close(entry.ready)
	if entry.result.Status == detectors.VerificationUnknown {
		c.mu.Lock()
		if c.entries[key] == entry {
			delete(c.entries, key)
		}
		c.mu.Unlock()
	}
	return entry.result
}

func (s *Scanner) Scan(ctx context.Context) ([]detectors.Finding, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	target := s.cfg.Target
	cleanup := func() {}
	if isGitRemote(target) {
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseCloning)
		}
		dir, err := os.MkdirTemp("", "secret-sniffer-*")
		if err != nil {
			return nil, err
		}
		cleanup = func() { _ = os.RemoveAll(dir) }
		defer cleanup()
		if err := cloneGit(ctx, target, s.cfg, dir); err != nil {
			return nil, err
		}
		s.remoteRoot, s.remoteTarget = dir, target
		target = dir
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseScanningWorktree)
		}
		return s.scanFiles(ctx, []string{target})
	}

	bare := isBareGitRepo(target)
	var findings []detectors.Finding
	if (s.cfg.GitHistory || bare) && isGitRepo(target) {
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseScanningHistory)
		}
		gitFindings, err := s.scanGitHistory(ctx, target)
		findings = append(findings, gitFindings...)
		if err != nil {
			return dedupe(findings), err
		}
	}
	if bare {
		return dedupe(findings), nil
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.SetPhase(progress.PhaseDiscovering)
	}
	files, err := s.collectFiles(target)
	if err != nil {
		return nil, err
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.SetPhase(progress.PhaseScanningWorktree)
	}
	worktreeFindings, err := s.scanFiles(ctx, files)
	findings = append(findings, worktreeFindings...)
	if err != nil {
		return dedupe(findings), err
	}
	return dedupe(findings), nil
}

func cloneGit(ctx context.Context, target string, cfg Config, dir string) error {
	cloneURL, err := validatedGitRemote(target)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 1; attempt <= 4; attempt++ {
		if attempt > 1 {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
		}
		args := []string{"clone", "--quiet"}
		if cfg.GitMaxDepth > 0 {
			args = append(args, "--depth", strconv.Itoa(cfg.GitMaxDepth))
		}
		if len(cfg.GitBranches) == 1 {
			args = append(args, "--branch", cfg.GitBranches[0])
		}
		args = append(args, "--", cloneURL, dir)
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = gitCommandEnv(cloneURL, cfg)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("git clone failed for %s: %w: %s", sanitizedGitRemote(target), err, sanitizeGitError(string(out), cfg))
		if attempt == 4 || !retryableGitCloneError(string(out)) {
			break
		}
		if err := sleepContext(ctx, time.Duration(attempt*attempt)*time.Second); err != nil {
			return err
		}
	}
	return lastErr
}

func gitCommandEnv(target string, cfg Config) []string {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	header := cfg.GitAuthorizationHeader
	if header == "" && cfg.GitHubToken != "" && isGitHubHTTPURL(target) {
		header = "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+cfg.GitHubToken))
	}
	if header != "" && isHTTPGitURL(target) {
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0="+header)
	}
	return env
}

func sanitizeGitError(message string, cfg Config) string {
	for _, secret := range []string{cfg.GitHubToken, cfg.GitAuthorizationHeader} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return strings.TrimSpace(message)
}

func retryableGitCloneError(output string) bool {
	low := strings.ToLower(output)
	transient := []string{
		"failed to connect",
		"could not connect to server",
		"connection refused",
		"connection reset",
		"connection timed out",
		"operation timed out",
		"the requested url returned error: 502",
		"the requested url returned error: 503",
		"the requested url returned error: 504",
		"gnutls recv error",
		"early eof",
		"remote end hung up unexpectedly",
	}
	for _, needle := range transient {
		if strings.Contains(low, needle) {
			return true
		}
	}
	return false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
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
	return s.allowedRelPath(rel)
}

func (s *Scanner) allowedRelPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	extension := strings.TrimPrefix(strings.ToLower(path.Ext(base)), ".")
	if slices.Contains(s.cfg.ExcludeExtensions, extension) {
		return false
	}
	if slices.Contains([]string{"png", "jpg", "jpeg", "gif", "webp", "ico", "exe", "dll", "so", "dylib"}, extension) {
		return false
	}
	if !s.cfg.ScanArchives && slices.Contains([]string{"zip", "tar", "gz", "tgz", "7z", "xz", "bz2", "jar", "war", "ear", "whl", "nupkg", "apk"}, extension) {
		return false
	}

	return s.pathFilter == nil || s.pathFilter.Allowed(rel)
}

func (s *Scanner) scanFiles(ctx context.Context, files []string) ([]detectors.Finding, error) {
	type result struct {
		findings []detectors.Finding
		err      error
	}
	jobs := make(chan string, s.cfg.Workers)
	out := make(chan result)
	var wg sync.WaitGroup
	if s.cfg.Progress != nil {
		s.cfg.Progress.DiscoverItems(int64(len(files)))
	}
	for i := 0; i < s.cfg.Workers; i++ {
		slot := fmt.Sprintf("file-%d-%02d", s.instanceID, i+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range jobs {
				item := progress.Item{Stage: progress.StageScanning, Path: filePath}
				if info, err := os.Stat(filePath); err == nil {
					item.BytesTotal = info.Size()
				}
				if s.cfg.Progress != nil {
					s.cfg.Progress.StartItem(slot, item)
				}
				b, err := os.ReadFile(filePath)
				if err == nil {
					itemCtx := progress.WithSlot(ctx, slot)
					findings := s.scanBlob(itemCtx, filePath, "", b, 0)
					findings = s.reidentifyRemoteWorktree(findings, filePath)
					emitErr := s.emitFindings(findings)
					if s.cfg.Progress != nil {
						s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageScanning, ClearArchive: true, BytesRead: int64(len(b)), BytesTotal: int64(len(b))})
						s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageCompleted, BytesRead: int64(len(b))})
					}
					out <- result{findings: findings, err: emitErr}
				} else {
					if s.cfg.Progress != nil {
						s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageFailed, Reason: "read_error", Error: err.Error()})
					}
					out <- result{err: fmt.Errorf("read %s: %w", filePath, err)}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	go func() {
		defer close(jobs)
		for _, f := range files {
			if s.cfg.Progress != nil {
				s.cfg.Progress.QueueItems(1)
			}
			select {
			case <-ctx.Done():
				if s.cfg.Progress != nil {
					s.cfg.Progress.QueueItems(-1)
				}
				return
			case jobs <- f:
			}
		}
	}()

	var findings []detectors.Finding
	var scanErr error
	for result := range out {
		findings = append(findings, result.findings...)
		scanErr = errors.Join(scanErr, result.err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if scanErr != nil {
		return dedupe(findings), scanErr
	}
	return dedupe(findings), nil
}

func (s *Scanner) reidentifyRemoteWorktree(findings []detectors.Finding, filePath string) []detectors.Finding {
	if s.remoteRoot == "" {
		return findings
	}
	rel, err := filepath.Rel(s.remoteRoot, filePath)
	if err != nil {
		return findings
	}
	rel = filepath.ToSlash(rel)
	for i := range findings {
		display := rel
		if suffix, ok := strings.CutPrefix(findings[i].File, filePath); ok {
			display += suffix
		}
		findings[i] = detectors.ReidentifyFinding(findings[i], display, findings[i].Commit)
		if findings[i].Provenance != nil {
			findings[i].Provenance.Provider = "git"
			findings[i].Provenance.Repository = sanitizedGitRemote(s.remoteTarget)
		}
	}
	return findings
}

func (s *Scanner) scanBytes(ctx context.Context, file, commit string, b []byte) []detectors.Finding {
	seen := map[string]struct{}{}
	lines := newLineIndex(b)
	var findings []detectors.Finding
	findings = append(findings, s.scanByteView(ctx, file, commit, b, lines, seen)...)
	findings = append(findings, s.scanDecodedBase64(ctx, file, commit, b, lines, seen)...)
	return findings
}

type lineIndex []int

func newLineIndex(b []byte) lineIndex {
	lines := make(lineIndex, 0, bytes.Count(b, []byte{'\n'}))
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, i)
		}
	}
	return lines
}

func (l lineIndex) location(pos int) (int, int) {
	line := sort.Search(len(l), func(i int) bool { return l[i] >= pos })
	lastNewline := -1
	if line > 0 {
		lastNewline = l[line-1]
	}
	return line + 1, pos - lastNewline
}

func (s *Scanner) scanByteView(ctx context.Context, file, commit string, view []byte, lines lineIndex, seen map[string]struct{}) []detectors.Finding {
	var findings []detectors.Finding
	for _, d := range s.plan.selectDetectors(view) {
		for _, c := range detectPlanned(d, view) {
			line, col := lines.location(c.Start)
			f := detectors.ToFindingAt(c, file, commit, line, col, false)
			s.enrichFindingSource(&f)
			if s.cfg.Verify {
				f.Verification = s.verification.verify(ctx, c)
				f.Verified = f.Verification.Status == detectors.VerificationVerified
			}
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

func (s *Scanner) scanDecodedBase64(ctx context.Context, file, commit string, b []byte, lines lineIndex, seen map[string]struct{}) []detectors.Finding {
	decodedSeen := map[[32]byte]struct{}{}
	var findings []detectors.Finding
	for offset := 0; offset < len(b); {
		match := base64CandidateRe.FindIndex(b[offset:])
		if match == nil {
			break
		}
		start, end := offset+match[0], offset+match[1]
		offset = end
		encoded := b[start:end]
		if len(encoded) > maxBase64CandidateBytes || !plausibleBase64Candidate(encoded) {
			continue
		}
		decoded, ok := decodeBase64Candidate(encoded)
		if !ok || len(decoded) < 8 || isBinary(decoded) {
			continue
		}
		decodedKey := sha256.Sum256(decoded)
		if _, ok := decodedSeen[decodedKey]; ok {
			continue
		}
		decodedSeen[decodedKey] = struct{}{}
		for _, d := range s.plan.selectDetectors(decoded) {
			for _, c := range detectPlanned(d, decoded) {
				// Report the source line/column of the encoded blob while preserving
				// the decoded secret value for remediation.
				c.Start = start
				c.End = end
				line, col := lines.location(c.Start)
				f := detectors.ToFindingAt(c, file, commit, line, col, false)
				s.enrichFindingSource(&f)
				if f.Provenance != nil {
					f.Provenance.DecoderChain = append(f.Provenance.DecoderChain, "base64")
				}
				if s.cfg.Verify {
					f.Verification = s.verification.verify(ctx, c)
					f.Verified = f.Verification.Status == detectors.VerificationVerified
				}
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
	hasURL, hasStandard := false, false
	for _, c := range b {
		switch c {
		case '-', '_':
			hasURL = true
		case '+', '/':
			hasStandard = true
		}
		if hasURL && hasStandard {
			return false
		}
	}
	return true
}

func decodeBase64Candidate(b []byte) ([]byte, bool) {
	urlAlphabet := bytes.IndexAny(b, "-_") >= 0
	padded := len(b) > 0 && b[len(b)-1] == '='
	var encoding *base64.Encoding
	switch {
	case urlAlphabet && padded:
		encoding = base64.URLEncoding
	case urlAlphabet:
		encoding = base64.RawURLEncoding
	case padded:
		encoding = base64.StdEncoding
	default:
		encoding = base64.RawStdEncoding
	}
	decoded := make([]byte, encoding.DecodedLen(len(b)))
	n, err := encoding.Decode(decoded, b)
	if err != nil || n == 0 {
		return nil, false
	}
	return decoded[:n], true
}

func (s *Scanner) scanGitHistory(ctx context.Context, repo string) ([]detectors.Finding, error) {
	args, err := s.gitHistoryArgs(repo)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	type changedFile struct{ commit, path string }
	type result struct {
		findings []detectors.Finding
		err      error
	}
	jobs := make(chan changedFile)
	out := make(chan result)
	cache := newHistoryBlobCache()
	batches := make([]*gitBatchReader, 0, s.cfg.Workers)
	for range s.cfg.Workers {
		batch, err := newGitBatchReader(ctx, repo)
		if err != nil {
			for _, opened := range batches {
				opened.close()
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("start git history object reader: %w", err)
		}
		batches = append(batches, batch)
	}
	var wg sync.WaitGroup
	for i, batch := range batches {
		slot := fmt.Sprintf("git-%d-%02d", s.instanceID, i+1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer batch.close()
			for f := range jobs {
				if f.commit == "" || f.path == "" {
					continue
				}
				if s.cfg.Progress != nil {
					s.cfg.Progress.StartItem(slot, progress.Item{Stage: progress.StageScanning, Path: f.path, Commit: f.commit})
				}
				var b []byte
				var oid string
				var err error
				if strings.ContainsAny(f.path, "\r\n") {
					b, oid, err = gitBlobByRevision(ctx, repo, f.commit+":"+f.path, s.cfg.MaxFileBytes)
				} else {
					b, oid, err = batch.blob(f.commit+":"+f.path, s.cfg.MaxFileBytes)
				}
				if err == nil {
					if s.cfg.Progress != nil {
						s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageScanning, BytesRead: int64(len(b)), BytesTotal: int64(len(b))})
					}
					cacheKey := oid
					if s.cfg.ScanArchives {
						cacheKey += "\x00" + archiveKind(f.path)
					}
					findings := cache.findings(ctx, cacheKey, f.path, f.commit, func() []detectors.Finding {
						return s.scanBlob(progress.WithSlot(ctx, slot), f.path, f.commit, b, 0)
					})
					s.enrichGitCommitMetadata(repo, findings)
					emitErr := s.emitFindings(findings)
					if s.cfg.Progress != nil {
						s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageScanning, ClearArchive: true, BytesRead: int64(len(b)), BytesTotal: int64(len(b))})
						s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageCompleted, BytesRead: int64(len(b))})
					}
					out <- result{findings: findings, err: emitErr}
				} else {
					stage, reason := progress.StageFailed, "read_error"
					if err.Error() == "blob too large" {
						stage, reason = progress.StageSkipped, "object_too_large"
					}
					if s.cfg.Progress != nil {
						s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: stage, Reason: reason, Error: err.Error()})
					}
					if stage == progress.StageFailed {
						out <- result{err: fmt.Errorf("read git blob %s:%s: %w", f.commit, f.path, err)}
					}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()

	scan := bufio.NewScanner(stdout)
	scan.Split(splitNUL)
	seen := map[string]struct{}{}
	go func() {
		defer close(jobs)
		commit := ""
		for scan.Scan() {
			parsedCommit, file, ok := parseGitHistoryRecord(scan.Text(), commit)
			if parsedCommit != "" {
				commit = parsedCommit
			}
			if !ok {
				continue
			}
			if !s.allowedRelPath(file) {
				continue
			}
			key := commit + "\x00" + file
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			if s.cfg.Progress != nil {
				s.cfg.Progress.DiscoverItems(1)
				s.cfg.Progress.QueueItems(1)
			}
			select {
			case <-ctx.Done():
				if s.cfg.Progress != nil {
					s.cfg.Progress.QueueItems(-1)
				}
				return
			case jobs <- changedFile{commit: commit, path: file}:
			}
		}
	}()

	var findings []detectors.Finding
	var scanErr error
	for result := range out {
		findings = append(findings, result.findings...)
		scanErr = errors.Join(scanErr, result.err)
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if scan.Err() != nil {
		return nil, scan.Err()
	}
	findings = dedupe(findings)
	s.enrichGitCommitMetadata(repo, findings)
	if scanErr != nil {
		return findings, scanErr
	}
	return findings, nil
}

func gitBlobByRevision(ctx context.Context, repo, revision string, maxBytes int64) ([]byte, string, error) {
	oidOutput, err := exec.CommandContext(ctx, "git", "-C", repo, "rev-parse", "--verify", revision).Output()
	if err != nil {
		return nil, "", err
	}
	oid := strings.TrimSpace(string(oidOutput))
	sizeOutput, err := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "-s", oid).Output()
	if err != nil {
		return nil, "", err
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64)
	if err != nil {
		return nil, "", err
	}
	if size > maxBytes {
		return nil, "", errors.New("blob too large")
	}
	content, err := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "blob", oid).Output()
	return content, oid, err
}

func (s *Scanner) enrichFindingSource(finding *detectors.Finding) {
	if finding.Provenance == nil {
		return
	}
	if finding.Commit != "" || isGitRemote(s.cfg.Target) {
		finding.Provenance.Repository = sanitizedGitRemote(s.cfg.Target)
		refs := append(append([]string{}, s.cfg.GitBranches...), s.cfg.GitRefs...)
		if len(refs) > 0 {
			finding.Provenance.Ref = strings.Join(refs, ",")
		}
	}
}

func (s *Scanner) enrichGitCommitMetadata(repo string, findings []detectors.Finding) {
	type metadata struct {
		author, email string
		timestamp     time.Time
	}
	cache := map[string]metadata{}
	for i := range findings {
		if findings[i].Commit == "" || findings[i].Provenance == nil {
			continue
		}
		meta, ok := cache[findings[i].Commit]
		if !ok {
			cmd := exec.Command("git", "-C", repo, "show", "-s", "--format=%an%x00%ae%x00%cI", findings[i].Commit, "--")
			out, err := cmd.Output()
			if err == nil {
				parts := strings.Split(strings.TrimSpace(string(out)), "\x00")
				if len(parts) == 3 {
					meta.author, meta.email = parts[0], parts[1]
					meta.timestamp, _ = time.Parse(time.RFC3339, parts[2])
				}
			}
			cache[findings[i].Commit] = meta
		}
		findings[i].Provenance.CommitAuthor = meta.author
		findings[i].Provenance.CommitEmail = meta.email
		findings[i].Provenance.CommitTimestamp = meta.timestamp
	}
}

func (s *Scanner) gitHistoryArgs(repo string) ([]string, error) {
	args := []string{"log", "--root", "-z", "--format=commit:%H", "--name-only", "--diff-filter=AMR"}
	if s.cfg.GitMaxDepth > 0 {
		args = append(args, "--max-count", strconv.Itoa(s.cfg.GitMaxDepth))
	}
	policy := s.cfg.GitAdditionalRefs
	if policy == "" {
		policy = "all"
	}
	if policy != "all" && policy != "default" && policy != "selected" && policy != "none" {
		return nil, fmt.Errorf("invalid additional-ref policy %q", policy)
	}
	var revisions []string
	for _, revision := range append(append([]string{}, s.cfg.GitRanges...), s.cfg.GitRefs...) {
		if err := validateGitRevision(revision); err != nil {
			return nil, err
		}
		revisions = append(revisions, revision)
	}
	for _, branch := range s.cfg.GitBranches {
		if err := validateGitRevision(branch); err != nil {
			return nil, err
		}
		revision := branch
		if exec.Command("git", "-C", repo, "rev-parse", "--verify", branch+"^{commit}").Run() != nil {
			remoteBranch := "refs/remotes/origin/" + branch
			if exec.Command("git", "-C", repo, "rev-parse", "--verify", remoteBranch+"^{commit}").Run() == nil {
				revision = remoteBranch
			}
		}
		revisions = append(revisions, revision)
	}
	hasSelectors := len(revisions) > 0
	if s.cfg.GitSinceCommit != "" {
		if err := validateGitRevision(s.cfg.GitSinceCommit); err != nil {
			return nil, err
		}
		if !hasSelectors && policy != "all" {
			revisions = append(revisions, "HEAD")
		}
		revisions = append(revisions, "^"+s.cfg.GitSinceCommit)
	}
	switch {
	case policy == "all":
		args = append(args, "--all")
	case policy == "default":
		revisions = append(revisions, "HEAD")
	case len(revisions) == 0 && policy == "none":
		revisions = append(revisions, "HEAD")
	case policy == "selected" && len(revisions) == 0:
		return nil, errors.New("additional-ref policy selected requires --git-ref, --branch, or --commit-range")
	}
	args = append(args, revisions...)
	args = append(args, "--")
	return args, nil
}

func validateGitRevision(revision string) error {
	if revision == "" || strings.HasPrefix(revision, "-") || strings.ContainsAny(revision, "\x00\r\n\t ") {
		return fmt.Errorf("invalid git revision %q", revision)
	}
	return nil
}

func splitNUL(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseGitHistoryRecord(record, currentCommit string) (string, string, bool) {
	record = strings.TrimPrefix(record, "\n")
	if strings.HasPrefix(record, "commit:") {
		return strings.TrimPrefix(record, "commit:"), "", false
	}
	if currentCommit == "" || record == "" {
		return "", "", false
	}
	return "", record, true
}

type historyBlobCache struct {
	mu      sync.Mutex
	entries map[string]*historyBlobCacheEntry
}

type historyBlobCacheEntry struct {
	root     string
	findings []detectors.Finding
	ready    chan struct{}
}

func newHistoryBlobCache() *historyBlobCache {
	return &historyBlobCache{entries: map[string]*historyBlobCacheEntry{}}
}

func (c *historyBlobCache) findings(ctx context.Context, key, file, commit string, scan func() []detectors.Finding) []detectors.Finding {
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-entry.ready:
			return reidentifyHistoryFindings(entry.findings, entry.root, file, commit)
		}
	}
	entry := &historyBlobCacheEntry{root: file, ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	entry.findings = scan()
	close(entry.ready)
	return entry.findings
}

func reidentifyHistoryFindings(findings []detectors.Finding, oldRoot, newRoot, commit string) []detectors.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]detectors.Finding, 0, len(findings))
	for _, finding := range findings {
		file := newRoot
		if suffix, ok := strings.CutPrefix(finding.File, oldRoot); ok {
			file += suffix
		}
		out = append(out, detectors.ReidentifyFinding(finding, file, commit))
	}
	return out
}

type gitBatchReader struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func newGitBatchReader(ctx context.Context, repo string) (*gitBatchReader, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, err
	}
	return &gitBatchReader{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}, nil
}

func (r *gitBatchReader) blob(rev string, max int64) ([]byte, string, error) {
	if _, err := fmt.Fprintln(r.stdin, rev); err != nil {
		return nil, "", err
	}
	header, err := r.stdout.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	fields := strings.Fields(strings.TrimSpace(header))
	if len(fields) == 2 && fields[1] == "missing" {
		return nil, "", errors.New("missing object")
	}
	if len(fields) != 3 {
		return nil, "", fmt.Errorf("unexpected cat-file header: %s", strings.TrimSpace(header))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, "", err
	}
	if fields[1] != "blob" {
		if err := discardBatchObject(r.stdout, size); err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("not blob")
	}
	if size > max {
		if err := discardBatchObject(r.stdout, size); err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("blob too large")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r.stdout, b); err != nil {
		return nil, "", err
	}
	if err := discardBatchObject(r.stdout, 0); err != nil {
		return nil, "", err
	}
	return b, fields[0], nil
}

func discardBatchObject(r *bufio.Reader, size int64) error {
	if size > 0 {
		if _, err := io.CopyN(io.Discard, r, size); err != nil {
			return err
		}
	}
	_, err := r.ReadByte()
	return err
}

func (r *gitBatchReader) close() {
	_ = r.stdin.Close()
	_ = r.cmd.Wait()
}

func (s *Scanner) scanBlob(ctx context.Context, file, commit string, b []byte, depth int) []detectors.Finding {
	if ctx.Err() != nil {
		return nil
	}
	if s.cfg.ScanArchives && depth <= s.maxArchiveDepth() && archiveKind(file) != "" {
		return s.scanArchiveBytes(ctx, file, commit, b, depth)
	}
	if text, ok := extractDocumentText(file, b, s.maxExpandedFileBytes()); ok {
		return s.scanBytes(ctx, file, commit, text)
	}
	if isBinary(b) {
		return nil
	}
	return s.scanBytes(ctx, file, commit, b)
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
		entryName := path.Base(name)
		if name == file {
			name = file + "!/decompressed"
			entryName = "decompressed"
		} else {
			name = file + "!/" + entryName
		}
		if !s.allowedArchivePath(name, entryName) {
			return nil
		}
		s.updateArchiveProgress(ctx, progress.StageExtracting, entryName, depth+1, 0)
		limit := s.maxExpandedFileBytes()
		if s.maxArchiveBytes() < limit {
			limit = s.maxArchiveBytes()
		}
		entry, ok := readLimited(zr, limit)
		if !ok {
			return nil
		}
		s.updateArchiveProgress(ctx, progress.StageScanning, entryName, depth+1, int64(len(entry)))
		return s.scanBlob(ctx, name, commit, entry, depth+1)
	case "xz":
		r, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		return s.scanCompressed(ctx, file, commit, r, ".xz", depth)
	case "bz2":
		return s.scanCompressed(ctx, file, commit, bzip2.NewReader(bytes.NewReader(b)), ".bz2", depth)
	case "7z":
		return s.scan7z(ctx, file, commit, b, depth)
	}
	return nil
}

func (s *Scanner) scanCompressed(ctx context.Context, file, commit string, reader io.Reader, suffix string, depth int) []detectors.Finding {
	entryName := path.Base(strings.TrimSuffix(file, suffix))
	name := file + "!/" + entryName
	if !s.allowedArchivePath(name, entryName) {
		return nil
	}
	s.updateArchiveProgress(ctx, progress.StageExtracting, entryName, depth+1, 0)
	limit := s.maxExpandedFileBytes()
	if s.maxArchiveBytes() < limit {
		limit = s.maxArchiveBytes()
	}
	entry, ok := readLimited(reader, limit)
	if !ok {
		return nil
	}
	s.updateArchiveProgress(ctx, progress.StageScanning, entryName, depth+1, int64(len(entry)))
	return s.scanBlob(ctx, name, commit, entry, depth+1)
}

func (s *Scanner) scan7z(ctx context.Context, file, commit string, b []byte, depth int) []detectors.Finding {
	reader, err := sevenzip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil
	}
	var findings []detectors.Finding
	var expanded int64
	entries := 0
	for _, entry := range reader.File {
		if ctx.Err() != nil || entries >= s.maxArchiveEntries() || expanded >= s.maxArchiveBytes() {
			break
		}
		entries++
		name, ok := safeArchivePath(entry.Name)
		if !ok || entry.FileInfo().IsDir() || !s.allowedArchivePath(file+"!/"+name, name) || entry.UncompressedSize > uint64(s.maxExpandedFileBytes()) {
			continue
		}
		s.updateArchiveProgress(ctx, progress.StageExtracting, name, depth+1, int64(entry.UncompressedSize))
		r, err := entry.Open()
		if err != nil {
			continue
		}
		limit := s.maxExpandedFileBytes()
		if remaining := s.maxArchiveBytes() - expanded; remaining < limit {
			limit = remaining
		}
		content, ok := readLimited(r, limit)
		_ = r.Close()
		if !ok || expanded+int64(len(content)) > s.maxArchiveBytes() {
			continue
		}
		expanded += int64(len(content))
		s.updateArchiveProgress(ctx, progress.StageScanning, name, depth+1, int64(len(content)))
		findings = append(findings, s.scanBlob(ctx, file+"!/"+name, commit, content, depth+1)...)
	}
	return findings
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
		entries++
		if entry.FileInfo().IsDir() {
			continue
		}
		name, ok := safeArchivePath(entry.Name)
		if !ok {
			continue
		}
		if !s.allowedArchivePath(file+"!/"+name, name) {
			continue
		}
		if entry.UncompressedSize64 > uint64(s.maxExpandedFileBytes()) {
			continue
		}
		s.updateArchiveProgress(ctx, progress.StageExtracting, name, depth+1, int64(entry.UncompressedSize64))
		r, err := entry.Open()
		if err != nil {
			continue
		}
		limit := s.maxExpandedFileBytes()
		if remaining := s.maxArchiveBytes() - expanded; remaining < limit {
			limit = remaining
		}
		content, ok := readLimited(r, limit)
		_ = r.Close()
		if !ok {
			continue
		}
		if expanded+int64(len(content)) > s.maxArchiveBytes() {
			break
		}
		expanded += int64(len(content))
		s.updateArchiveProgress(ctx, progress.StageScanning, name, depth+1, int64(len(content)))
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
		entries++
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		name, ok := safeArchivePath(h.Name)
		if !ok || !s.allowedArchivePath(file+"!/"+name, name) || h.Size > s.maxExpandedFileBytes() {
			continue
		}
		s.updateArchiveProgress(ctx, progress.StageExtracting, name, depth+1, h.Size)
		limit := s.maxExpandedFileBytes()
		if remaining := s.maxArchiveBytes() - expanded; remaining < limit {
			limit = remaining
		}
		content, ok := readLimited(tr, limit)
		if !ok {
			continue
		}
		if expanded+int64(len(content)) > s.maxArchiveBytes() {
			break
		}
		expanded += int64(len(content))
		s.updateArchiveProgress(ctx, progress.StageScanning, name, depth+1, int64(len(content)))
		findings = append(findings, s.scanBlob(ctx, file+"!/"+name, commit, content, depth+1)...)
	}
	return findings
}

func (s *Scanner) updateArchiveProgress(ctx context.Context, stage, entry string, depth int, size int64) {
	if s.cfg.Progress == nil {
		return
	}
	if slot := progress.Slot(ctx); slot != "" {
		update := progress.ItemUpdate{Stage: stage, ArchiveEntry: entry, ArchiveDepth: depth, BytesTotal: size}
		if stage == progress.StageExtracting {
			update.ResetBytes = true
			update.DisableByteCounting = true
		} else if stage == progress.StageScanning {
			update.BytesRead = size
		}
		s.cfg.Progress.UpdateItem(slot, update)
	}
}

func (s *Scanner) allowedArchivePath(virtualPath, entry string) bool {
	if len(s.cfg.Include) > 0 || len(s.cfg.IncludeRegex) > 0 {
		return (s.pathFilter == nil || s.pathFilter.Allowed(virtualPath)) || (s.pathFilter == nil || s.pathFilter.Allowed(entry))
	}
	return s.pathFilter == nil || s.pathFilter.Allowed(virtualPath)
}

func archiveKind(file string) string {
	file = strings.ToLower(file)
	switch {
	case strings.HasSuffix(file, ".zip"), strings.HasSuffix(file, ".jar"), strings.HasSuffix(file, ".war"), strings.HasSuffix(file, ".ear"), strings.HasSuffix(file, ".whl"), strings.HasSuffix(file, ".nupkg"), strings.HasSuffix(file, ".apk"):
		return "zip"
	case strings.HasSuffix(file, ".tar"):
		return "tar"
	case strings.HasSuffix(file, ".tar.gz") || strings.HasSuffix(file, ".tgz"):
		return "targz"
	case strings.HasSuffix(file, ".gz"):
		return "gz"
	case strings.HasSuffix(file, ".xz"):
		return "xz"
	case strings.HasSuffix(file, ".bz2"):
		return "bz2"
	case strings.HasSuffix(file, ".7z"):
		return "7z"
	default:
		return ""
	}
}

func extractDocumentText(file string, b []byte, maxBytes int64) ([]byte, bool) {
	ext := documentExt(file)
	switch ext {
	case ".pdf":
		return extractPDFText(b), true
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp":
		text, ok := extractZipDocumentText(b, maxBytes)
		return text, ok
	case ".doc", ".xls", ".ppt":
		var text bytes.Buffer
		appendPrintableRuns(&text, b)
		return text.Bytes(), true
	case ".rtf":
		return extractRTFText(b), true
	default:
		return nil, false
	}
}

func documentExt(file string) string {
	if i := strings.LastIndex(file, "!/"); i >= 0 {
		file = file[i+2:]
	}
	return strings.ToLower(filepath.Ext(file))
}

func extractZipDocumentText(b []byte, maxBytes int64) ([]byte, bool) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, false
	}
	var out bytes.Buffer
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || !documentXMLPath(entry.Name) || entry.UncompressedSize64 > uint64(maxBytes) {
			continue
		}
		r, err := entry.Open()
		if err != nil {
			continue
		}
		content, ok := readLimited(r, maxBytes)
		_ = r.Close()
		if !ok {
			continue
		}
		appendXMLText(&out, content)
		if int64(out.Len()) > maxBytes {
			break
		}
	}
	return out.Bytes(), out.Len() > 0
}

func documentXMLPath(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	if !strings.HasSuffix(name, ".xml") {
		return false
	}
	return strings.HasPrefix(name, "word/") || strings.HasPrefix(name, "xl/") || strings.HasPrefix(name, "ppt/") || name == "content.xml"
}

func appendXMLText(out *bytes.Buffer, b []byte) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if chars, ok := tok.(xml.CharData); ok {
			text := strings.TrimSpace(string(chars))
			if text != "" {
				out.WriteString(text)
				out.WriteByte('\n')
			}
		}
	}
}

func extractPDFText(b []byte) []byte {
	var out bytes.Buffer
	appendPDFLiteralStrings(&out, b)
	appendPDFHexStrings(&out, b)
	appendPDFStreams(&out, b)
	appendPrintableRuns(&out, b)
	return out.Bytes()
}

func appendPDFStreams(out *bytes.Buffer, b []byte) {
	for offset := 0; offset < len(b); {
		streamAt := bytes.Index(b[offset:], []byte("stream"))
		if streamAt < 0 {
			return
		}
		streamAt += offset
		contentStart := streamAt + len("stream")
		if contentStart < len(b) && b[contentStart] == '\r' {
			contentStart++
		}
		if contentStart < len(b) && b[contentStart] == '\n' {
			contentStart++
		}
		endRel := bytes.Index(b[contentStart:], []byte("endstream"))
		if endRel < 0 {
			return
		}
		contentEnd := contentStart + endRel
		stream := bytes.TrimRight(b[contentStart:contentEnd], "\r\n")
		if bytes.Contains(b[max(0, streamAt-256):streamAt], []byte("/FlateDecode")) {
			zr, err := zlib.NewReader(bytes.NewReader(stream))
			if err == nil {
				decoded, readOK := readLimited(zr, int64(len(b))*8+1)
				_ = zr.Close()
				if readOK {
					appendPDFLiteralStrings(out, decoded)
					appendPDFHexStrings(out, decoded)
					appendPrintableRuns(out, decoded)
				}
			}
		} else {
			appendPrintableRuns(out, stream)
		}
		offset = contentEnd + len("endstream")
	}
}

func appendPDFLiteralStrings(out *bytes.Buffer, b []byte) {
	for i := 0; i < len(b); i++ {
		if b[i] != '(' {
			continue
		}
		var text bytes.Buffer
		escaped := false
		depth := 1
		for j := i + 1; j < len(b); j++ {
			c := b[j]
			if escaped {
				switch c {
				case 'n':
					text.WriteByte('\n')
				case 'r':
					text.WriteByte('\r')
				case 't':
					text.WriteByte('\t')
				case 'b':
					text.WriteByte('\b')
				case 'f':
					text.WriteByte('\f')
				default:
					text.WriteByte(c)
				}
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
				if depth == 0 {
					if text.Len() > 0 {
						out.Write(text.Bytes())
						out.WriteByte('\n')
					}
					i = j
					break
				}
			}
			text.WriteByte(c)
		}
	}
}

func appendPDFHexStrings(out *bytes.Buffer, b []byte) {
	for i := 0; i < len(b); i++ {
		if b[i] != '<' || i+1 < len(b) && b[i+1] == '<' {
			continue
		}
		end := bytes.IndexByte(b[i+1:], '>')
		if end < 0 {
			continue
		}
		raw := b[i+1 : i+1+end]
		compact := make([]byte, 0, len(raw))
		for _, c := range raw {
			if isHexByte(c) {
				compact = append(compact, c)
			} else if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
				compact = compact[:0]
				break
			}
		}
		if len(compact) >= 2 {
			if len(compact)%2 == 1 {
				compact = append(compact, '0')
			}
			decoded := make([]byte, hex.DecodedLen(len(compact)))
			if _, err := hex.Decode(decoded, compact); err == nil && !isBinary(decoded) {
				out.Write(decoded)
				out.WriteByte('\n')
			}
		}
		i += end + 1
	}
}

func appendPrintableRuns(out *bytes.Buffer, b []byte) {
	start := -1
	for i, c := range b {
		printable := c == '\n' || c == '\r' || c == '\t' || c >= 32 && c <= 126
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 8 {
			out.Write(b[start:i])
			out.WriteByte('\n')
		}
		start = -1
	}
	if start >= 0 && len(b)-start >= 8 {
		out.Write(b[start:])
		out.WriteByte('\n')
	}
}

func extractRTFText(b []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '{', '}':
			out.WriteByte(' ')
		case '\\':
			i++
			if i >= len(b) {
				break
			}
			if b[i] == '\\' || b[i] == '{' || b[i] == '}' {
				out.WriteByte(b[i])
				continue
			}
			for i < len(b) && (b[i] >= 'a' && b[i] <= 'z' || b[i] >= 'A' && b[i] <= 'Z' || b[i] == '-' || b[i] >= '0' && b[i] <= '9') {
				i++
			}
			if i < len(b) && b[i] != ' ' {
				i--
			}
		case '\r', '\n':
			out.WriteByte('\n')
		default:
			out.WriteByte(b[i])
		}
	}
	return out.Bytes()
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
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

func isGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func isBareGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--is-bare-repository")
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func isGitRemote(s string) bool {
	if isSCPGitRemote(s) {
		return true
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ssh", "git", "file":
		return u.Host != "" || u.Scheme == "file"
	default:
		return false
	}
}

func validatedGitRemote(raw string) (string, error) {
	if isSCPGitRemote(raw) {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil || !isGitRemote(raw) {
		return "", fmt.Errorf("invalid git remote %q", sanitizedGitRemote(raw))
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return "", errors.New("git remote URLs must not contain embedded passwords or tokens")
		}
	}
	return raw, nil
}

func isSCPGitRemote(raw string) bool {
	at := strings.IndexByte(raw, '@')
	colon := strings.IndexByte(raw, ':')
	return at > 0 && colon > at+1 && !strings.Contains(raw[:colon], "/")
}

func sanitizedGitRemote(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

func isHTTPGitURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isGitHubHTTPURL(raw string) bool {
	if !isHTTPGitURL(raw) {
		return false
	}
	u, _ := url.Parse(raw)
	host := strings.ToLower(u.Hostname())
	return host == "github.com" || host == "www.github.com"
}

func isGitHubURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	h := strings.ToLower(u.Host)
	return h == "github.com" || h == "www.github.com"
}

func githubCloneURL(raw, token string) string {
	return raw
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
