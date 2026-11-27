package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/mcp"
	"github.com/skarm/scout/policy"
)

const (
	maxTargetMappings     = 64
	httpReadHeaderTimeout = 3 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteGracePeriod  = 5 * time.Second
	httpIdleTimeout       = 30 * time.Second
	maxHTTPHeaderBytes    = 8192
	httpShutdownTimeout   = 5 * time.Second
)

type repeated []string

type mcpInvocation struct {
	options                     mcp.Options
	request                     request
	transport, listen, tokenEnv string
	targets, origins            repeated
}

func (r *repeated) String() string { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error {
	if len(*r) >= maxTargetMappings {
		return errors.New("repeated argument limit")
	}

	*r = append(*r, v)

	return nil
}

func (c *mcpInvocation) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.transport, "transport", c.transport, "stdio or authenticated loopback HTTP")
	fs.StringVar(&c.listen, "listen", c.listen, "numeric loopback bind for HTTP /mcp")
	fs.StringVar(&c.tokenEnv, "token-env", c.tokenEnv, "explicit environment variable with HTTP bearer token (>=32 bytes)")
	fs.DurationVar(&c.options.Timeout, "tool-timeout", c.options.Timeout, "maximum duration of each tool call")
	fs.IntVar(&c.options.MaxConcurrent, "concurrency", c.options.MaxConcurrent, "concurrent scans across all sessions (1..8)")
	fs.Var(&c.targets, "target", "operator-authorized name=local-path; repeatable; no target means upload-only")
	fs.Var(&c.origins, "origin", "explicit allowed HTTP Origin; repeatable")
}

func (c *mcpInvocation) prepareTransport() error {
	if c.transport == "http" {
		return c.prepareHTTP()
	}

	if c.transport != "stdio" || c.tokenEnv != "" || len(c.origins) > 0 {
		return errors.New("invalid MCP transport/options")
	}

	return nil
}

func (c *mcpInvocation) prepareHTTP() error {
	host, _, err := net.SplitHostPort(c.listen)

	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return errors.New("HTTP CLI binds numeric loopback only; use a secured reverse proxy for remote access")
	}

	if c.tokenEnv == "" {
		return errors.New("HTTP requires --token-env")
	}

	c.options.HTTPToken = os.Getenv(c.tokenEnv)
	if c.options.HTTPToken == "" {
		return errors.New("explicit HTTP token is empty or unavailable")
	}

	return nil
}

func parseMCPInvocation(ctx context.Context, args []string, stderr io.Writer) (mcpInvocation, error) {
	c := mcpInvocation{options: mcp.DefaultOptions(), transport: "stdio", listen: "127.0.0.1:8837"}

	r, err := resolveRequest("mcp", args, stderr, c.bind)
	if err != nil {
		return c, err
	}

	c.request = r
	if len(r.targets) != 0 || ctx == nil {
		return c, errors.New("mcp has no positional arguments")
	}

	for _, pair := range c.targets {
		key, path, ok := strings.Cut(pair, "=")

		_, duplicate := c.options.Targets[key]
		if !ok || key == "" || path == "" || duplicate {
			return c, errors.New("target requires a unique name and a nonempty path (name=path)")
		}

		c.options.Targets[key] = path
		c.request.targets = append(c.request.targets, path)
	}

	if err := c.request.loadTrusted(ctx); err != nil {
		return c, err
	}

	c.options.AllowedOrigins = c.origins

	return c, c.prepareTransport()
}

func serveMCP(ctx context.Context, args []string, input io.ReadCloser, stdout, stderr io.Writer) int {
	invocation, err := parseMCPInvocation(ctx, args, stderr)
	if err != nil {
		return requestError(err, stderr)
	}

	r, o := invocation.request, invocation.options
	transport, listen := invocation.transport, invocation.listen

	gate, e := policy.New(r.settings.Policy)
	if e != nil {
		return usageError(stderr, e.Error())
	}

	scanner, e := scout.New(ctx, r.settings.Scanner)
	if e != nil {
		return usageError(stderr, e.Error())
	}

	// Scanner.Close currently releases owned resources without returning errors.
	defer func() { _ = scanner.Close() }()

	server, e := mcp.New(scanner, gate, o)
	if e != nil {
		return usageError(stderr, e.Error())
	}

	if transport == "stdio" {
		if e = server.Serve(ctx, input, stdout); e != nil && !errors.Is(e, context.Canceled) {
			_, _ = fmt.Fprintln(stderr, "MCP stdio transport failed")
			return 2
		}

		return 0
	}

	return serveMCPHTTP(ctx, server, listen, o.Timeout, stderr)
}

func serveMCPHTTP(ctx context.Context, server *mcp.Server, address string, timeout time.Duration, stderr io.Writer) int {
	handler, e := server.HTTPHandler()
	if e != nil {
		return usageError(stderr, e.Error())
	}

	listener, e := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if e != nil {
		_, _ = fmt.Fprintln(stderr, "MCP listen failed")
		return 2
	}
	defer func() { _ = listener.Close() }()

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      timeout + httpWriteGracePeriod,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}

	_, _ = fmt.Fprintln(stderr, "Authenticated MCP HTTP server listening on loopback /mcp")

	return runMCPHTTPServer(ctx, httpServer, listener)
}

func runMCPHTTPServer(ctx context.Context, server *http.Server, listener net.Listener) int {
	servingDone, shutdownDone := make(chan struct{}), make(chan struct{})
	defer func() {
		close(servingDone)
		// Serve returns when Shutdown closes the listener, before active
		// handlers finish and before the CLI can safely release the scanner.
		<-shutdownDone
	}()

	go func() {
		defer close(shutdownDone)

		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpShutdownTimeout)
			defer cancel()

			if err := server.Shutdown(c); err != nil {
				_ = server.Close()
			}
		case <-servingDone:
		}
	}()

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_ = server.Close()

		return 2
	}

	return 0
}
