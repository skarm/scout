//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func readStdinFile(ctx context.Context, file *os.File, p []byte) (int, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var descriptor int32

	if err := raw.Control(func(fd uintptr) {
		//nolint:gosec // G115: stdin is a borrowed OS descriptor; Unix file descriptors have signed int32 range.
		descriptor = int32(fd)
	}); err != nil {
		return 0, err
	}

	for {
		wait := 50
		if deadline, ok := ctx.Deadline(); ok {
			wait = max(1, min(wait, int(time.Until(deadline).Milliseconds())+1))
		}

		fds := []unix.PollFd{{Fd: descriptor, Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, wait)
		// The bounded wait also bounds cancellation latency. Observe cancellation
		// before either consuming readiness or retrying an interrupted wait.
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		if errors.Is(err, unix.EINTR) {
			continue
		}

		if err != nil {
			return 0, err
		}

		if ready != 0 {
			return file.Read(p)
		}
	}
}
