package report

import "sync"

const (
	maxCanonicalBufferCapacity = 16 << 20
)

//nolint:gochecknoglobals // Scratch buffers contain no DTO references and are exclusively borrowed.
var canonicalBuffers sync.Pool

func borrowCanonicalBuffer() *[]byte {
	if cached := canonicalBuffers.Get(); cached != nil {
		return cached.(*[]byte) //nolint:forcetypeassert // This private pool stores only byte-slice pointers.
	}

	return new([]byte)
}

func releaseCanonicalBuffer(buffer *[]byte) {
	// Large one-off reports must not enlarge the idle working set indefinitely.
	if cap(*buffer) > maxCanonicalBufferCapacity {
		return
	}

	*buffer = (*buffer)[:0]
	canonicalBuffers.Put(buffer)
}
