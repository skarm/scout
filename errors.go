package scout

import "errors"

var (
	// ErrIncomplete indicates that selected work did not finish. A returned run
	// still retains available observations.
	ErrIncomplete = errors.New("inspection incomplete")
	// ErrClosed indicates that the Scanner no longer accepts operations.
	ErrClosed = errors.New("scanner is closed")
	// ErrInvalidInput identifies a target or operation request rejected before
	// inspection.
	ErrInvalidInput = errors.New("invalid scan input")
	// ErrInvalidOptions identifies an invalid Scanner configuration.
	ErrInvalidOptions = errors.New("invalid scanner options")
)

// Error wraps a stable error code and a cause that callers can inspect with
// errors.Is or errors.As.
type Error struct {
	// Code is a stable machine-readable condition identifier.
	Code string
	// Cause is the wrapped error available through Unwrap.
	Cause error
}

// Error returns the stable Scout error code without the underlying cause text.
func (e *Error) Error() string { return "scout: " + e.Code }

// Unwrap returns the underlying cause for errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Cause }
