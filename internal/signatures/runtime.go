package signatures

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// ErrClosed means a native runtime no longer accepts new checks.
var errClosed = errors.New("YARA-X runtime is closed")

// Runtime owns compiled rules and a bounded set of independent native scanners.
// A Check has exclusive use of one scanner; runs never share mutable native
// scan state. Close waits for admitted checks, including checks awaiting a slot.
type Runtime struct {
	options    Options
	parent     compiledEngine
	sessions   []compiledEngine
	available  chan compiledEngine
	mu         sync.Mutex
	closed     bool
	active     sync.WaitGroup
	closedDone chan struct{}
}

// Open validates and compiles trusted rules once. The constructor context is
// used only during initialization and is never retained for later checks.
func Open(ctx context.Context, options Options, workers int) (*Runtime, error) {
	if err := validateRuntime(ctx, options, workers); err != nil {
		return nil, err
	}

	options.ExtraRules = slices.Clone(options.ExtraRules)
	parent, err := compileRules(ctx, builtinRules+"\n"+string(options.ExtraRules))

	parent, err = checkedEngine(parent, err, "YARA-X compiler returned no engine")
	if err != nil {
		return nil, err
	}

	runtime := &Runtime{
		options: options, parent: parent,
		available:  make(chan compiledEngine, workers),
		closedDone: make(chan struct{}),
	}
	if err := runtime.prepareSessions(ctx, workers); err != nil {
		_ = runtime.Close() // Release compiled sessions; preserve the initialization error.
		return nil, err
	}

	return runtime, nil
}

// Check borrows one scanner for the entire bounded input plan. Cancellation
// while waiting preserves cancelled outcomes for every selected input.
func (r *Runtime) Check(ctx context.Context, inputs []Input) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("nil YARA-X check context")
	}

	if err := r.admit(); err != nil {
		return Report{}, err
	}
	defer r.active.Done()

	select {
	case <-ctx.Done():
		return checkCompiled(ctx, inputs, r.options, nil)
	case session := <-r.available:
		defer func() { r.available <- session }()
		return checkCompiled(ctx, inputs, r.options, session)
	}
}

// Close prevents new checks, drains admitted checks and destroys all scanners
// before the compiled rules they borrow. Concurrent and repeated calls wait for
// the same teardown and return successfully.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	if r.closedDone == nil {
		r.closed = true
		r.mu.Unlock()

		return nil
	}

	if r.closed {
		done := r.closedDone
		r.mu.Unlock()
		<-done

		return nil
	}

	r.closed = true
	r.mu.Unlock()
	r.active.Wait()

	for _, session := range r.sessions {
		session.close()
	}

	if r.parent != nil {
		r.parent.close()
	}

	close(r.closedDone)

	return nil
}

func (r *Runtime) prepareSessions(ctx context.Context, workers int) error {
	for range workers {
		if err := r.addSession(ctx); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func (r *Runtime) addSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	session, err := r.parent.fork()

	session, err = checkedEngine(session, err, "YARA-X fork returned no scanner")
	if err != nil {
		return err
	}

	r.sessions = append(r.sessions, session)
	r.available <- session

	return nil
}

func (r *Runtime) admit() error {
	if r == nil {
		return errClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.available == nil || r.parent == nil {
		return errClosed
	}

	r.active.Add(1)

	return nil
}

// checkedEngine transfers a successful acquisition to its caller. A producer
// error closes any returned resource, so no failed acquisition remains owned.
func checkedEngine(engine compiledEngine, err error, missing string) (compiledEngine, error) {
	if err != nil {
		if engine != nil {
			engine.close()
		}

		return nil, err
	}

	if engine == nil {
		return nil, errors.New(missing)
	}

	return engine, nil
}

func validateRuntime(ctx context.Context, options Options, workers int) error {
	if ctx == nil {
		return errors.New("nil YARA-X runtime context")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := options.Validate(); err != nil {
		return err
	}

	if !options.Enabled {
		return errors.New("YARA-X runtime requires enabled signatures")
	}

	if workers < 1 || workers > 32 {
		return errors.New("YARA-X runtime workers must be in 1..32")
	}

	if !Backend().Available {
		return errors.New("YARA-X native backend is unavailable")
	}

	return nil
}
