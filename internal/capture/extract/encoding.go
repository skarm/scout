package extract

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only format dispatch and encoding grammar shared by extraction runs.
var dataURINames = map[string]string{
	"text/plain":             "content.txt",
	"text/x-python":          "content.py",
	"application/x-python":   "content.py",
	"text/x-shellscript":     "content.sh",
	"application/x-sh":       "content.sh",
	"application/javascript": "content.js",
	"text/javascript":        "content.js",
	"application/json":       "content.json",
	"application/zip":        "content.zip",
	"application/gzip":       "content.gz",
	"application/x-gzip":     "content.gz",
	"image/png":              "content.png",
}

// Strict streaming decoder: malformed surrogate pairs are errors, never silently
// replaced. This retains the original object and discards incomplete children.
type utf16Reader struct {
	data    string
	order   binary.ByteOrder
	pending [4]byte
	n, at   int
}

func (r *utf16Reader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.at < r.n {
			k := copy(p[n:], r.pending[r.at:r.n])
			r.at += k
			n += k

			continue
		}

		ch, err := r.nextRune()
		if err != nil {
			return n, err
		}

		r.n = utf8.EncodeRune(r.pending[:], ch)
		r.at = 0
	}

	return n, nil
}

func (r *utf16Reader) nextRune() (rune, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}

	if len(r.data) < 2 {
		return 0, errFormat
	}

	u := r.order.Uint16([]byte(r.data[:2]))
	r.data = r.data[2:]

	ch := rune(u)
	if utf16.IsSurrogate(ch) {
		if u >= 0xdc00 {
			return 0, errFormat
		}

		if len(r.data) < 2 {
			return 0, errFormat
		}

		low := r.order.Uint16([]byte(r.data[:2]))
		r.data = r.data[2:]

		if low < 0xdc00 || low > 0xdfff {
			return 0, errFormat
		}

		ch = utf16.DecodeRune(rune(u), rune(low))
	}

	return ch, nil
}

func extractUTF16(o *operation) error {
	if err := o.entry(); err != nil {
		return err
	}

	data := o.parent.file.Content()
	if len(data) < 2 || (len(data)-2)%2 != 0 || strings.HasPrefix(data, "\xff\xfe\x00\x00") {
		return errFormat
	}

	var order binary.ByteOrder = binary.LittleEndian
	if strings.HasPrefix(data, "\xfe\xff") {
		order = binary.BigEndian
	}

	r := &utf16Reader{data: data[2:], order: order}

	return o.emit(inheritedName(o.parent.file.Metadata().Path, ""), r, -1, false, &report.ByteRange{
		Start: 0,
		End:   len(data),
	})
}

func base64Candidate(name, data string) bool {
	ext := strings.ToLower(path.Ext(name))
	return ext == ".b64" || ext == ".base64" || strings.Contains(data, ";base64,") || wholeBase64(data)
}

func base64Byte(c byte) bool {
	return strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=", rune(c))
}
func asciiSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func wholeBase64(data string) bool {
	data = strings.TrimSpace(data)
	if strings.ContainsAny(data, " \t") {
		return false
	}

	count := 0

	for i := 0; i < len(data); i++ {
		c := data[i]
		if asciiSpace(c) {
			continue
		}

		if !base64Byte(c) {
			return false
		}

		count++
	}
	// Short identifiers and ordinary words should not become decoding candidates.
	return count >= 48
}

func extractBase64(o *operation) error {
	data := o.parent.file.Content()

	ext := strings.ToLower(path.Ext(o.parent.file.Metadata().Path))
	if ext == ".b64" || ext == ".base64" || wholeBase64(data) {
		if err := o.entry(); err != nil {
			return err
		}

		name := inheritedName(o.parent.file.Metadata().Path, ext)
		if ext != ".b64" && ext != ".base64" {
			name = "decoded-" + inheritedName(o.parent.file.Metadata().Path, "")
		}

		return decodeBase64(o, name, data, &report.ByteRange{Start: 0, End: len(data)})
	}

	return extractDataURIs(o, data)
}

func extractDataURIs(o *operation, data string) error {
	for at := 0; at < len(data); {
		if err := o.b.ctx.Err(); err != nil {
			return err
		}

		i := strings.Index(data[at:], "data:")
		if i < 0 {
			break
		}

		i += at

		header, start, end, valid := dataURIRange(data, i)
		if !valid {
			at = i + 5
			continue
		}

		at = end

		if err := o.entry(); err != nil {
			return err
		}

		mime, _, _ := strings.Cut(header, ";")

		name := dataURINames[strings.ToLower(mime)]
		if name == "" {
			name = "content.bin"
		}

		if end == start {
			return errFormat
		}

		if err := decodeBase64(o, name, data[start:end], &report.ByteRange{Start: start, End: end}); err != nil {
			return err
		}
	}

	return nil
}

func dataURIRange(data string, i int) (header string, start, end int, valid bool) {
	endHeader := min(len(data), i+1024)

	j := strings.Index(data[i:endHeader], ";base64,")
	if j < 0 {
		return "", 0, 0, false
	}

	j += i

	header = data[i+5 : j]
	if !validDataHeader(header) {
		return "", 0, 0, false
	}

	start = j + 8

	end = start
	for end < len(data) && base64Byte(data[end]) {
		end++
	}

	return header, start, end, true
}

func validDataHeader(header string) bool {
	for i := 0; i < len(header); i++ {
		c := header[i]
		if c <= 32 || c >= 127 || strings.ContainsRune("\"'<>:", rune(c)) {
			return false
		}
	}

	return true
}

func decodeBase64(o *operation, name, data string, span *report.ByteRange) error {
	// Filtering is bounded by the already-captured source length. Decode itself
	// is streaming and shares the same output budget as archive decompression.
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}

		return r
	}, data)
	if compact == "" {
		return errFormat
	}

	encoding := base64.StdEncoding
	if strings.ContainsAny(compact, "-_") {
		encoding = base64.URLEncoding
	}

	if !strings.Contains(compact, "=") {
		encoding = encoding.WithPadding(base64.NoPadding)
	}

	return o.emit(name, base64.NewDecoder(encoding.Strict(), strings.NewReader(compact)), -1, false, span)
}
