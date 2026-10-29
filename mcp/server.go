// Package mcp exposes the scanner through bounded JSON-RPC tools over stdio or authenticated HTTP.
package mcp

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/policy"
)

const (
	// ProtocolVersion is the supported MCP protocol revision.
	ProtocolVersion = "2025-06-18"
	// MaxMessageBytes bounds one incoming JSON-RPC message in bytes.
	MaxMessageBytes = 256 << 10
	// MaxResponseBytes bounds one serialized MCP response in bytes.
	MaxResponseBytes = 8 << 20
	// MaxUploadBytes bounds the source bytes accepted by the upload tool.
	MaxUploadBytes = 128 << 10
)

// Options bounds MCP requests and authorizes named local targets independently
// of tool arguments.
type Options struct {
	// Targets are explicitly authorized by the operator. Tool arguments select an
	// opaque key, never an arbitrary path, URI, glob or scanner configuration.
	Targets map[string]string
	// Timeout bounds an admitted MCP operation. Calls above MaxConcurrent are
	// rejected rather than queued.
	Timeout time.Duration
	// MaxConcurrent bounds simultaneously executing MCP tool calls.
	MaxConcurrent int
	// HTTP needs a bearer secret even on loopback. It is never put in a report.
	HTTPToken string
	// AllowedOrigins lists browser origins accepted by the HTTP handler. An empty
	// list denies browser origins.
	AllowedOrigins []string
}

// Server serves bounded MCP requests through an operator-supplied Scanner and
// policy Gate. The caller retains ownership of both.
type Server struct {
	scanner  *scout.Scanner
	gate     *policy.Gate
	options  Options
	slots    chan struct{}
	mu       sync.Mutex
	sessions map[string]*session
}
type session struct {
	mu                 sync.Mutex
	initialized, ready bool
	protocol           string
	pending            map[requestKey]context.CancelFunc
	created            time.Time
}

// DefaultOptions returns bounded MCP settings with no authorized targets or
// HTTP bearer secret.
func DefaultOptions() Options {
	return Options{Targets: map[string]string{}, Timeout: time.Minute, MaxConcurrent: 2}
}

// New validates and copies authorized targets and transport settings. It
// borrows scanner and gate without taking ownership.
func New(scanner *scout.Scanner, gate *policy.Gate, o Options) (*Server, error) {
	if scanner == nil || gate == nil {
		return nil, errors.New("invalid MCP server configuration")
	}

	if err := o.validate(); err != nil {
		return nil, err
	}

	copied, err := authorizedTargets(o.Targets)
	if err != nil {
		return nil, err
	}

	o.Targets = copied
	o.AllowedOrigins = append([]string(nil), o.AllowedOrigins...)

	return &Server{
		scanner:  scanner,
		gate:     gate,
		options:  o,
		slots:    make(chan struct{}, o.MaxConcurrent),
		sessions: map[string]*session{},
	}, nil
}

func (o Options) validate() error {
	if o.Timeout <= 0 || o.Timeout > 10*time.Minute || o.MaxConcurrent < 1 || o.MaxConcurrent > 8 || len(o.Targets) > 64 {
		return errors.New("invalid MCP server configuration")
	}

	if o.HTTPToken != "" && !validHTTPToken(o.HTTPToken) {
		return errors.New("HTTP bearer secret must contain 32..512 non-whitespace bytes")
	}

	return nil
}

func authorizedTargets(targets map[string]string) (map[string]string, error) {
	copied := map[string]string{}

	for k, p := range targets {
		if !(textmatch.Token(k, 64, "_.-") && textmatch.Alnum(k[0])) || p == "" || strings.Contains(p, "://") {
			return nil, errors.New("invalid authorized MCP target")
		}

		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, errors.New("invalid target path")
		}

		copied[k] = abs
	}

	return copied, nil
}

func newSession() *session {
	return &session{pending: map[requestKey]context.CancelFunc{}, created: time.Now()}
}

func validHTTPToken(token string) bool {
	return len(token) >= 32 && len(token) <= 512 && !strings.ContainsAny(token, "\r\n\t ")
}
