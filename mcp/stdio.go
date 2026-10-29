package mcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"
)

// A stream has one serialized writer and owns all accepted call lifetimes.
// Lifecycle notifications are processed in input order while calls can finish
// concurrently, allowing cancellation notifications to interrupt them.
type stdioStream struct {
	server   *Server
	session  *session
	output   io.Writer
	writers  sync.Mutex
	calls    sync.WaitGroup
	writeErr error
}

// Serve owns input: it closes it when the context is cancelled. A caller-provided
// ReadCloser must unblock Read on Close. Only JSON-RPC messages are written out.
func (s *Server) Serve(ctx context.Context, input io.ReadCloser, output io.Writer) error {
	if ctx == nil || input == nil || output == nil {
		return errors.New("invalid stdio streams")
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = input.Close()
		case <-done:
		}
	}()

	stream := stdioStream{server: s, session: newSession(), output: output}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), MaxMessageBytes)

	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}

		stream.receive(ctx, scanner.Bytes())
	}
	// EOF closes the session but lets already accepted bounded calls finish.
	stream.calls.Wait()

	if stream.writeErr != nil {
		return stream.writeErr
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return scanner.Err()
}

func (s *stdioStream) send(r *response) {
	if r == nil {
		return
	}

	s.writers.Lock()
	defer s.writers.Unlock()

	if s.writeErr == nil {
		_, s.writeErr = s.output.Write(encodeResponse(r))
	}
}

func (s *stdioStream) receive(ctx context.Context, data []byte) {
	r, err := parseRequest(append([]byte(nil), data...))
	if err != nil {
		s.send(rpcFailure(nil, -32700, "Invalid JSON-RPC message"))
		return
	}

	if r.Method != "tools/call" || len(r.ID) == 0 {
		s.send(s.server.dispatch(ctx, s.session, r))
		return
	}

	call, callCtx, cleanup, rejected := s.server.prepareCall(ctx, s.session, r)
	if rejected != nil {
		s.send(rejected)
		return
	}

	s.calls.Go(func() {
		defer cleanup()

		s.send(s.server.executeToolCall(callCtx, call))
	})
}
