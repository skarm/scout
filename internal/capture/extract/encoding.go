package extract

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skarm/scout/report"
)

const (
	maxDataURIHeaderBytes = 1024
	minBase64Characters   = 48
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

	var (
		last     [4]byte
		count    int
		padding  int
		standard bool
		url      bool
	)

	for i := 0; i < len(data); i++ {
		c := data[i]
		if asciiSpace(c) {
			continue
		}

		if !base64Byte(c) {
			return false
		}

		if c == '=' {
			padding++
		} else if padding != 0 {
			return false
		}

		standard = standard || c == '+' || c == '/'
		url = url || c == '-' || c == '_'
		last[count%len(last)] = c
		count++
	}

	// Short identifiers and ordinary words should not become decoding candidates.
	if count < minBase64Characters || padding > 2 || standard && url {
		return false
	}

	// Validate the last quantum strictly. All preceding quanta have a
	// single alphabet and no padding. An explicit .b64 file or data URI
	// still reports malformed content as an extraction failure.
	size := count % len(last)
	if size == 0 {
		size = len(last)
	}

	var decoded [3]byte

	_, err := base64Encoding(url, padding > 0).Decode(decoded[:], last[:size])

	return err == nil
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
	var invalid error

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

		if err := decodeDataURI(o, header, data, start, end); err != nil {
			if !errors.Is(err, errFormat) {
				return err
			}

			// A malformed payload has no effect on later independent URIs.
			invalid = err
		}
	}

	return invalid
}

func decodeDataURI(o *operation, header, data string, start, end int) error {
	mime, _, _ := strings.Cut(header, ";")

	name := dataURINames[strings.ToLower(mime)]
	if name == "" {
		name = fallbackObjectName
	}

	payload, err := url.PathUnescape(data[start:end])
	if err != nil || !validDataBase64(payload) {
		return errFormat
	}

	err = decodeBase64(o, name, payload, &report.ByteRange{Start: start, End: end})
	if _, corrupt := errors.AsType[base64.CorruptInputError](err); corrupt || errors.Is(err, io.ErrUnexpectedEOF) {
		return errFormat
	}

	return err
}

func dataURIRange(data string, i int) (header string, start, end int, valid bool) {
	endHeader := min(len(data), i+maxDataURIHeaderBytes)

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
	for end < len(data) && (base64Byte(data[end]) || data[end] == '%') {
		end++
	}

	return header, start, end, true
}

func validDataBase64(payload string) bool {
	if payload == "" {
		return false
	}

	for i := range len(payload) {
		if !base64Byte(payload[i]) {
			return false
		}
	}

	return true
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

	encoding := base64Encoding(strings.ContainsAny(compact, "-_"), strings.Contains(compact, "="))

	return o.emit(name, base64.NewDecoder(encoding, strings.NewReader(compact)), -1, false, span)
}

func base64Encoding(url, padded bool) *base64.Encoding {
	encoding := base64.StdEncoding
	if url {
		encoding = base64.URLEncoding
	}

	if !padded {
		encoding = encoding.WithPadding(base64.NoPadding)
	}

	return encoding.Strict()
}
