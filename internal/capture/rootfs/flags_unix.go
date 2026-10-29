//go:build !linux && go1.24 && (freebsd || openbsd || netbsd || dragonfly)

package rootfs

import "syscall"

const readFlags = syscall.O_NONBLOCK | syscall.O_NOFOLLOW
