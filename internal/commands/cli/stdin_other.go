//go:build !linux && !darwin

package cli

import (
	"context"
	"os"
	"time"
)

func readStdinFile(ctx context.Context, file *os.File, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	if info, err := file.Stat(); err == nil && info.Mode().IsRegular() {
		return file.Read(p)
	}

	if err := file.SetReadDeadline(time.Time{}); err != nil {
		return 0, err
	}

	done := make(chan struct{})

	stop := context.AfterFunc(ctx, func() {
		_ = file.SetReadDeadline(time.Now()) // The cancellation callback cannot return an error.

		close(done)
	})
	defer func() {
		if !stop() {
			<-done
		}

		_ = file.SetReadDeadline(time.Time{}) // Cleanup must preserve the read result.
	}()

	return file.Read(p)
}
