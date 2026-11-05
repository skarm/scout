//go:build unix

package provenance

import "syscall"

const evidenceReadFlags = syscall.O_NONBLOCK
