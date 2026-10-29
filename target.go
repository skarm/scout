package scout

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
)

type targetKind uint8

const (
	pathTarget targetKind = iota + 1
	readerTarget
	remoteTarget
)

// Target is a caller-selected input. Reader targets are single-use.
type Target struct {
	// kind records the constructor used to select capture behavior.
	kind targetKind
	// name retains the caller's local path, reader label or explicit remote
	// address.
	name string
	// input is a borrowed, single-use stream that the Scanner must not close.
	input ContextReader
	// pin holds operator-supplied remote constraints independently of target
	// content.
	pin RemotePin
}

// RemotePin records operator-supplied revision and checksum constraints for a
// remote input.
type RemotePin struct {
	// Revision pins a GitHub repository to a full commit SHA.
	Revision string
	// SHA256 optionally pins complete downloaded bytes, not the captured inventory
	// digest.
	SHA256 string
}

// ContextReader supplies cancellable input without transferring ownership.
// ReadContext must stop promptly when ctx is cancelled, retaining any bytes
// already read in its returned count. Scout never closes the reader.
type ContextReader interface {
	// ReadContext reads into the supplied buffer and must stop promptly when its
	// context is cancelled. The caller retains ownership of the stream.
	ReadContext(context.Context, []byte) (int, error)
}

// Adapt the legacy Read contract once, at construction. The capture boundary
// checks context before and after each call; this adapter cannot interrupt Read.
type borrowedReader struct{ input io.Reader }

// Path selects a local file or directory. The path is validated when the
// operation starts.
func Path(path string) Target { return Target{kind: pathTarget, name: path} }

// Reader borrows a single-use reader. An offered ContextReader is preferred.
// Otherwise cancellation is cooperative between Read calls: the caller must
// ensure each Read returns. Use ReaderContext for blocking streams.
func Reader(name string, input io.Reader) Target {
	if input == nil {
		return ReaderContext(name, nil)
	}

	if cancellable, ok := input.(ContextReader); ok {
		return ReaderContext(name, cancellable)
	}

	return ReaderContext(name, borrowedReader{input: input})
}

// ReaderContext borrows a single-use stream that participates in cancellation.
func ReaderContext(name string, input ContextReader) Target {
	return Target{kind: readerTarget, name: name, input: input}
}

// Remote validates an explicit HTTP(S) target without downloading it. A scan
// also requires enabled download options.
func Remote(address string, pin RemotePin) (Target, error) {
	u, err := url.Parse(address)
	if err != nil || !remoteURL(u) {
		return Target{}, errors.New("invalid explicit remote target")
	}

	if err := remoteCharacters(address); err != nil {
		return Target{}, err
	}

	return Target{kind: remoteTarget, name: address, pin: pin}, nil
}

// Label returns the caller-supplied target name or address.
func (t Target) Label() string { return t.name }

// IsLocal reports whether the target was constructed from a local path.
func (t Target) IsLocal() bool { return t.kind == pathTarget }

func (t Target) validate() error {
	if t.name == "" || strings.IndexByte(t.name, 0) >= 0 {
		return errors.New("target name is required")
	}

	switch t.kind {
	case pathTarget:
		if strings.Contains(t.name, "://") {
			return errors.New("use Remote for URLs")
		}
	case readerTarget:
		if t.input == nil {
			return errors.New("input reader is required")
		}
	case remoteTarget:
	default:
		return errors.New("target constructor is required")
	}

	return nil
}

func (r borrowedReader) ReadContext(_ context.Context, p []byte) (int, error) {
	return r.input.Read(p)
}

func remoteURL(u *url.URL) bool {
	return u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Scheme == "https" || u.Scheme == "http")
}

func remoteCharacters(address string) error {
	for _, c := range address {
		if c < 32 || c == 127 {
			return errors.New("invalid remote target")
		}
	}

	return nil
}
