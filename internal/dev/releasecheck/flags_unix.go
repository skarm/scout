//go:build unix

package releasecheck

import "syscall"

const binaryReadFlags = syscall.O_NONBLOCK
