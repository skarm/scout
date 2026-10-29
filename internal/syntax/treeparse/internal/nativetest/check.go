//go:build !coreonly && cgo

// Package nativetest exercises the native adapter without adding hooks to Scout.
package nativetest

/*
#cgo CFLAGS: -std=c11 -D_POSIX_C_SOURCE=200112L -I${SRCDIR}/../..
#include "check.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	_ "github.com/tree-sitter/go-tree-sitter" // Link the official engine for the C regression check.
)

// CheckProgress interrupts at a native log event and checks interruption and reuse.
func CheckProgress(language unsafe.Pointer, text, event string, deadline bool) error {
	input := C.CString(text)
	defer C.free(unsafe.Pointer(input))

	checkpoint := C.CString(event)
	defer C.free(unsafe.Pointer(checkpoint))

	message := C.scout_test_progress((*C.TSLanguage)(language), input, C.size_t(len(text)), checkpoint, C.bool(deadline))
	if message != nil {
		return errors.New(C.GoString(message))
	}

	return nil
}
