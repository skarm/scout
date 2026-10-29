package extract

import (
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"strings"

	"github.com/skarm/scout/report"
)

type noTailReader struct {
	r    io.Reader
	tail *strings.Reader
}

// PNG Latin-1 text must be converted before UTF-8 analysis, without guessing
// encodings for arbitrary binary input. Small fixed buffers bound expansion.
type latinStream struct {
	r       io.Reader
	pending []byte
	err     error
	buf     [2048]byte
}

type pngChunk struct {
	kind string
	size uint64
	end  int
}

func (r *noTailReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	if e == io.EOF && r.tail.Len() != 0 {
		return n, errFormat
	}

	return n, e
}

func (r *latinStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(r.pending) == 0 && r.err == nil {
		n, e := r.r.Read(r.buf[:])
		r.err = e
		r.pending = append(r.pending[:0], []byte(stringLatin1(r.buf[:n]))...)
	}

	n := copy(p, r.pending)

	r.pending = r.pending[n:]
	if len(r.pending) == 0 {
		return n, r.err
	}

	return n, nil
}

// extractPNG validates chunk framing and CRCs but does not decode image pixels,
// execute profiles or claim full PNG validation or steganalysis.
func extractPNG(o *operation) error {
	data := o.parent.file.Content()
	if !strings.HasPrefix(data, "\x89PNG\r\n\x1a\n") {
		return errFormat
	}

	at := 8
	first := true

	for at < len(data) {
		if err := o.entry(); err != nil {
			return err
		}

		chunk, err := readPNGChunk(data, at, first)
		if err != nil {
			return err
		}

		end := chunk.end

		first = false

		done, err := chunk.extract(o, data, at)
		if err != nil {
			return err
		}

		if done {
			return nil
		}

		at = end + 4
	}

	return errFormat
}

func readPNGChunk(data string, at int, first bool) (pngChunk, error) {
	if len(data)-at < 12 {
		return pngChunk{}, errFormat
	}

	size := uint64(binary.BigEndian.Uint32([]byte(data[at : at+4])))
	if size > math.MaxInt || size > uint64(max(0, len(data)-at-12)) {
		return pngChunk{}, errFormat
	}

	end := at + 8 + int(size)

	typ := data[at+4 : at+8]
	if crc32.ChecksumIEEE([]byte(data[at+4:end])) != binary.BigEndian.Uint32([]byte(data[end:end+4])) {
		return pngChunk{}, errFormat
	}

	if first && (typ != "IHDR" || size != 13) {
		return pngChunk{}, errFormat
	}

	return pngChunk{kind: typ, size: size, end: end}, nil
}

func (c pngChunk) extract(o *operation, data string, at int) (bool, error) {
	span := &report.ByteRange{Start: at + 8, End: c.end}
	chunk := data[at+8 : c.end]

	var err error

	switch c.kind {
	case "tEXt", "zTXt", "iTXt":
		err = pngText(o, c.kind, chunk, span)
	case "eXIf":
		err = o.text("metadata.exif", chunk, span)
	case "IEND":
		if c.size != 0 || c.end+4 != len(data) {
			return false, errFormat
		}

		return true, nil
	}

	if err != nil {
		return false, err
	}

	return false, nil
}

func pngText(o *operation, typ, data string, span *report.ByteRange) error {
	separator := strings.IndexByte(data, 0)
	if separator < 1 || separator > 79 {
		return errFormat
	}

	rest := data[separator+1:]

	switch typ {
	case "tEXt":
		return o.emit("png-text.txt", &latinStream{r: strings.NewReader(rest)}, -1, false, span)
	case "zTXt":
		if len(rest) < 1 || rest[0] != 0 {
			return errFormat
		}

		return pngCompressed(o, rest[1:], true, span)
	case "iTXt":
		return pngInternationalText(o, rest, span)
	}

	return errFormat
}

func pngInternationalText(o *operation, rest string, span *report.ByteRange) error {
	if len(rest) < 2 || rest[0] > 1 || rest[1] != 0 {
		return errFormat
	}

	compressed := rest[0] == 1
	rest = rest[2:]
	// Language and translated keyword are metadata; source bytes remain checked.
	lang := strings.IndexByte(rest, 0)
	if lang < 0 {
		return errFormat
	}

	rest = rest[lang+1:]

	translated := strings.IndexByte(rest, 0)
	if translated < 0 {
		return errFormat
	}

	rest = rest[translated+1:]
	if compressed {
		return pngCompressed(o, rest, false, span)
	}

	return o.text("png-itext.txt", rest, span)
}

func pngCompressed(o *operation, data string, latin bool, span *report.ByteRange) error {
	input := strings.NewReader(data)

	zr, err := zlib.NewReader(contextByteReader{ctx: o.b.ctx, r: input})
	if err != nil {
		return err
	}

	var r io.Reader = &noTailReader{r: zr, tail: input}
	if latin {
		r = &latinStream{r: r}
	}

	err = o.emit("png-text.txt", r, -1, false, span)
	closed := zr.Close()

	if err != nil {
		return err
	}

	return closed
}

func stringLatin1(b []byte) string {
	var s strings.Builder
	s.Grow(len(b) * 2)

	for _, c := range b {
		s.WriteRune(rune(c))
	}

	return s.String()
}
