package cli

import (
	"context"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

func readStdinFile(ctx context.Context, file *os.File, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if info, err := file.Stat(); err == nil && info.Mode().IsRegular() {
		return file.Read(p)
	}

	raw, err := file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var handle windows.Handle

	if err := raw.Control(func(fd uintptr) { handle = windows.Handle(fd) }); err != nil {
		return 0, err
	}

	cancelIO := windows.NewLazySystemDLL("kernel32.dll").NewProc("CancelSynchronousIo")
	if err := cancelIO.Find(); err != nil {
		return 0, err
	}

	// CancelSynchronousIo targets the OS thread issuing ReadFile/ReadConsole.
	// Keep it pinned until both the read and its cancellation callback finish.
	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(thread) }()

	readDone, cancelDone := make(chan struct{}), make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(cancelDone)

		cancelStdinRead(handle, thread, cancelIO, readDone)
	})

	defer func() {
		close(readDone)

		if !stop() {
			<-cancelDone
		}
	}()

	n, err := file.Read(p)
	if ctx.Err() != nil {
		return n, ctx.Err()
	}

	return n, err
}

func cancelStdinRead(handle, thread windows.Handle, cancelIO *windows.LazyProc, done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		default:
		}
		// Cover synchronous console/pipe handles and overlapped caller handles.
		// Retry when cancellation wins the race with dispatching the read.
		_, _, _ = cancelIO.Call(uintptr(thread))
		_ = windows.CancelIoEx(handle, nil)

		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}
