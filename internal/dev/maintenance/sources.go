package maintenance

import (
	"context"
	"crypto/sha1" //nolint:gosec // Git blob identities use SHA-1 by definition, independently of the SHA-256 content check.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/skarm/scout/internal/dev/provenance"
)

const maxSourceBytes = 8 << 20

type sourceArtifact struct {
	Path, URL, SHA256 string
	Bytes             int
	GitBlobSHA1       string `json:"git_blob_sha1"`
}
type pinnedSource struct {
	ID, Repository, Revision string
	Artifacts                []sourceArtifact
}

// ScannerRuntimeFiles binds product evidence to both build variants and embeds.
// Developer command changes cannot invalidate the product dependency closure.
func ScannerRuntimeFiles(ctx context.Context, root string) ([]string, error) {
	return provenance.ScannerRuntimeFiles(ctx, root)
}

// DeveloperRuntimeFiles contains the additional developer executable closure.
// Shared product dependencies are recorded once, by ScannerRuntimeFiles.
func DeveloperRuntimeFiles(ctx context.Context, root string) ([]string, error) {
	return provenance.DeveloperRuntimeFiles(ctx, root)
}

func verifyKnowledgeSources(ctx context.Context, o options, w io.Writer) error {
	if err := o.require("cache"); err != nil {
		return err
	}

	var sources []pinnedSource
	if err := readJSON(filepath.Join(o.root, "knowledge/data/review_sources.json"), &sources); err != nil {
		return err
	}

	if *o.download {
		if err := os.MkdirAll(o.get("cache"), 0o700); err != nil {
			return err
		}
	}

	count := 0

	for _, source := range sources {
		n, err := verifySource(ctx, source, o.get("cache"), *o.download)
		if err != nil {
			return err
		}

		count += n
	}

	_, err := fmt.Fprintf(w, "verified %d source files from %d pinned repositories; no upstream code executed\n", count, len(sources))

	return err
}

func verifySource(ctx context.Context, s pinnedSource, cache string, download bool) (int, error) {
	repository, err := pinnedRepository(s)
	if err != nil {
		return 0, err
	}

	for _, item := range s.Artifacts {
		if err = verifyArtifactURL(repository, s.Revision, item); err != nil {
			return 0, err
		}

		if err := verifyCachedArtifact(ctx, s.ID, cache, item, download); err != nil {
			return 0, err
		}
	}

	return len(s.Artifacts), nil
}

func verifyArtifactURL(repository *url.URL, revision string, item sourceArtifact) error {
	u, err := url.Parse(item.URL)
	if err != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" || u.User != nil || u.Path != repository.Path+"/"+revision+"/"+item.Path || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("source URL does not match pinned repository/path")
	}

	return validateSourceArtifact(item)
}

func validateSourceArtifact(item sourceArtifact) error {
	if !hexLength(item.SHA256, 64) || item.Bytes <= 0 || item.Bytes > maxSourceBytes {
		return errors.New("invalid source digest or byte count")
	}

	return nil
}

func hexLength(s string, n int) bool {
	if len(s) != n {
		return false
	}

	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}

	return true
}

func downloadSource(ctx context.Context, address string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "scout-knowledge-verifier")

	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("source redirects are not permitted") },
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source HTTP status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes+1))
}

func verifySourceBytes(data []byte, item sourceArtifact) error {
	if len(data) != item.Bytes || digest(data) != item.SHA256 {
		return errors.New("source bytes differ")
	}

	blob := append(fmt.Appendf(nil, "blob %d\x00", len(data)), data...)

	sum := sha1.Sum(blob) //nolint:gosec // G401: mandated Git blob identity; content is also checked with SHA-256 above.
	if hex.EncodeToString(sum[:]) != item.GitBlobSHA1 {
		return errors.New("git blob differs")
	}

	return nil
}

func pinnedRepository(s pinnedSource) (*url.URL, error) {
	repository, err := url.Parse(s.Repository)
	if err != nil || repository.Scheme != "https" || repository.Host != "github.com" || repository.User != nil || !hexLength(s.Revision, 40) {
		return nil, errors.New("invalid pinned source repository or revision")
	}

	return repository, nil
}

func verifyCachedArtifact(ctx context.Context, id, cache string, item sourceArtifact, download bool) error {
	path := filepath.Join(cache, item.SHA256)
	data, readErr := os.ReadFile(path) //nolint:gosec // G304: the filename is a validated SHA-256 inside the explicitly selected cache.

	missing := errors.Is(readErr, os.ErrNotExist)
	if missing && download {
		data, readErr = downloadSource(ctx, item.URL)
	}

	if readErr != nil {
		return readErr
	}

	if err := verifySourceBytes(data, item); err != nil {
		return fmt.Errorf("%s/%s: %w", id, item.Path, err)
	}

	if missing && download {
		if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: validated hexadecimal digest fixes the cache-relative filename.
			return err
		}
	}

	return nil
}
