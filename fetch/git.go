package fetch

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/skarm/scout/internal/netpolicy"
)

const (
	// KindGitTree identifies a pinned Git tree packaged as a deterministic ZIP.
	KindGitTree     = "git-tree"
	gitRequestLimit = 8
	gitRequestBytes = 64 << 10
)

func fetchGitTree(ctx context.Context, target Target, o Options) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fail("git_not_available")
	}

	dir, err := os.MkdirTemp("", "scout-git-*")
	if err != nil {
		return nil, fail("git_workspace_failed")
	}
	defer func() { _ = os.RemoveAll(dir) }()

	repo := gitWorkspace{git: git, dir: dir}
	if err := repo.command(ctx, "init", "--bare", "--quiet", "--template=", "--object-format=sha1").Run(); err != nil {
		return nil, gitFailure(ctx, "git_workspace_failed")
	}

	if err := repo.download(ctx, target, o); err != nil {
		return nil, err
	}

	return repo.archive(ctx, target.Revision, o.MaxBytes)
}

type gitWorkspace struct{ git, dir string }

func (r gitWorkspace) command(ctx context.Context, args ...string) *exec.Cmd {
	// The executable comes from the operator's PATH. Commands and arguments
	// use a private workspace, a random loopback URL and validated object IDs.
	command := exec.CommandContext(ctx, r.git, args...) //nolint:gosec // No shell or source-controlled executable or options.
	command.Dir = r.dir
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "LANG=C", "LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=http", "GIT_NO_REPLACE_OBJECTS=1",
	}

	return command
}

func (r gitWorkspace) download(ctx context.Context, target Target, o Options) error {
	remote, err := url.Parse(target.URL)
	if err != nil {
		return fail("invalid_git_url")
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return gitFailure(ctx, "git_transport_unavailable")
	}

	client, transport := newClient(o)
	defer transport.CloseIdleConnections()

	proxy := &gitHTTPBridge{remote: *remote, client: client, route: "/" + rand.Text(), remaining: o.MaxBytes}
	server := &http.Server{
		Handler: proxy, ReadHeaderTimeout: o.Timeout, ReadTimeout: o.Timeout, WriteTimeout: o.Timeout,
		BaseContext: func(net.Listener) context.Context { return ctx }, MaxHeaderBytes: 16 << 10,
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)

		_ = server.Serve(listener)
	}()

	defer func() {
		_ = listener.Close()
		_ = server.Close()

		<-stopped
	}()

	local := "http://" + listener.Addr().String() + proxy.route

	command := r.command(ctx, "-c", "http.followRedirects=false", "-c", "credential.helper=", "-c", "fetch.unpackLimit=1",
		"-c", "fetch.fsckObjects=true", "-c", "core.hooksPath="+os.DevNull, "-c", "fetch.writeCommitGraph=false",
		"fetch", "--quiet", "--no-auto-maintenance", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "--depth=1", "--", local, target.Revision)
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		proxy.mu.Lock()
		defer proxy.mu.Unlock()

		if proxy.failure != nil {
			return proxy.failure
		}

		return fail("git_fetch_failed")
	}

	return nil
}

// Git only talks to this loopback bridge. The bridge forwards Smart HTTP
// discovery and fetch to the explicitly validated URL through Scout's transport.
type gitHTTPBridge struct {
	mu        sync.Mutex
	remote    url.URL
	client    *http.Client
	route     string
	remaining int64
	requests  int
	failure   error
}

func (p *gitHTTPBridge) ServeHTTP(w http.ResponseWriter, incoming *http.Request) {
	suffix, mimeType, ok := p.routeRequest(incoming)
	if !ok {
		http.NotFound(w, incoming)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := p.forward(incoming, suffix, mimeType)
	if err != nil {
		p.failure = err

		w.WriteHeader(http.StatusBadGateway)

		return
	}

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data) //nolint:gosec // A private Git bridge returns only binary Git protocol media types.
}

func (p *gitHTTPBridge) routeRequest(r *http.Request) (string, string, bool) {
	const discovery, service = "/info/refs", "/git-upload-pack"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == p.route+discovery && r.URL.RawQuery == "service=git-upload-pack":
		return discovery, "application/x-git-upload-pack-advertisement", true
	case r.Method == http.MethodPost && r.URL.Path == p.route+service && r.URL.RawQuery == "" &&
		r.Header.Get("Content-Type") == "application/x-git-upload-pack-request":
		return service, "application/x-git-upload-pack-result", true
	default:
		return "", "", false
	}
}

func (p *gitHTTPBridge) forward(r *http.Request, suffix, mimeType string) ([]byte, error) {
	if p.remaining <= 0 {
		return nil, fail("byte_limit")
	}

	if p.requests >= gitRequestLimit {
		return nil, fail("git_transport_limit")
	}

	p.requests++
	remote := p.remote

	remote.Path = strings.TrimRight(remote.Path, "/") + suffix
	if remote.RawPath != "" {
		remote.RawPath = strings.TrimRight(remote.RawPath, "/") + suffix
	}

	remote.RawQuery = r.URL.RawQuery

	body, err := io.ReadAll(io.LimitReader(r.Body, gitRequestBytes+1))
	if err != nil || len(body) > gitRequestBytes {
		return nil, fail("git_request_limit")
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, remote.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fail("invalid_request")
	}

	req.Header.Set("User-Agent", downloadUserAgent)
	req.Header.Set(netpolicy.HeaderAcceptEncoding, netpolicy.IdentityEncoding)

	for _, header := range []string{"Content-Type", "Content-Encoding", "Git-Protocol"} {
		if value := r.Header.Get(header); value != "" {
			req.Header.Set(header, value)
		}
	}

	resp, err := p.client.Do(req) //nolint:gosec // The target is operator-selected and the shared transport validates IPs and refuses redirects.
	if err != nil {
		return nil, requestFailure(r.Context(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := validateResponseHeaders(resp, p.remaining); err != nil {
		return nil, err
	}

	actual, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || actual != mimeType {
		return nil, fail("git_smart_http_required")
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, p.remaining+1))
	if err != nil {
		return nil, gitFailure(r.Context(), "body_read_failed")
	}

	if int64(len(data)) > p.remaining {
		return nil, fail("byte_limit")
	}

	p.remaining -= int64(len(data))

	return data, nil
}

func gitFailure(ctx context.Context, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return fail(code)
}
