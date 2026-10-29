//go:build !linux && go1.24 && !(darwin || freebsd || openbsd || netbsd || dragonfly)

package rootfs

const readFlags = 0
