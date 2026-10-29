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

type repeated []string

type mcpInvocation struct {
	options                     mcp.Options
	request                     request
	transport, listen, tokenEnv string
	targets, origins            repeated
}

func (r *repeated) String() string { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error {
	if len(*r) >= 64 {
		return errors.New("repeated argument limit")
	}

	*r = append(*r, v)

	return nil
}

func (c *mcpInvocation) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.transport, "transport", c.transport, "stdio or authenticated loopback HTTP")
	fs.StringVar(&c.listen, "listen", c.listen, "numeric loopback bind for HTTP /mcp")
	fs.StringVar(&c.tokenEnv, "auth-token-env", c.tokenEnv, "explicit environment variable with HTTP bearer token (>=32 bytes)")
	fs.DurationVar(&c.options.Timeout, "scan-timeout", c.options.Timeout, "maximum duration of each tool call")
	fs.IntVar(&c.options.MaxConcurrent, "max-concurrent", c.options.MaxConcurrent, "concurrent scans across all sessions (1..8)")
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
		return errors.New("HTTP requires --auth-token-env")
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
		if !ok || c.options.Targets[key] != "" {
			return c, errors.New("target must be a unique name=path")
		}

		c.options.Targets[key] = path
		c.request.targets = append(c.request.targets, path)
	}

	if err := c.request.loadTrusted(); err != nil {
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
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      timeout + 5*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(c); err != nil {
				_ = httpServer.Close()
			}
		case <-done:
		}
	}()

	_, _ = fmt.Fprintln(stderr, "Authenticated MCP HTTP server listening on loopback /mcp")

	if e = httpServer.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
		return 2
	}

	return 0
}
