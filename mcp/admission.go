package mcp

import (
	"context"
)

// accept runs in input order before a worker is started. It bounds goroutine
// count and registers cancellation before the next notification can arrive.
func (s *Server) accept(ctx context.Context, sess *session, r request) (context.Context, func(), *response) {
	ret := func(msg string) (context.Context, func(), *response) {
		x := failure(r.ID, -32000, msg)
		return nil, nil, &x
	}

	select {
	case s.slots <- struct{}{}:
	default:
		return ret("Concurrent scan limit")
	}

	callCtx, cancel := context.WithTimeout(ctx, s.options.Timeout)

	sess.mu.Lock()

	k := r.key
	if sess.pending[k] != nil {
		sess.mu.Unlock()
		cancel()
		<-s.slots

		return ret("Duplicate active request ID")
	}

	sess.pending[k] = cancel
	sess.mu.Unlock()

	cleanup := func() { cancel(); sess.mu.Lock(); delete(sess.pending, k); sess.mu.Unlock(); <-s.slots }

	return callCtx, cleanup, nil
}
