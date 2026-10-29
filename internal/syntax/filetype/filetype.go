// Package filetype provides bounded, conservative content hints. Neither a
// suffix nor a magic signature proves a type, safety, or absence of a polyglot.
package filetype

import (
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Read-only format equivalence metadata shared by detectors.
var formatEquivalents = map[string][]string{
	"jpg":      {"jpeg"},
	"tif":      {"tiff"},
	"gz":       {"gzip"},
	"tgz":      {"gzip"},
	"bz2":      {"bzip2"},
	"zst":      {"zstd"},
	"exe":      {"pe-candidate"},
	"dll":      {"pe-candidate"},
	"so":       {"elf"},
	"dylib":    {"mach-o", "fat-mach-o", "java-or-fat-mach-o"},
	"class":    {"java-or-fat-mach-o"},
	"jar":      {"zip"},
	"whl":      {"zip"},
	"nupkg":    {"zip"},
	"doc":      {"ole-container"},
	"xls":      {"ole-container"},
	"ppt":      {"ole-container"},
	"database": {"sqlite"},
}

type Description = report.Classification

func Inspect(name, data string, executable bool) Description {
	d := Description{
		Format:    "unknown",
		Category:  "unknown",
		Encoding:  "bytes",
		Basis:     "unrecognized",
		Languages: language.Detect(name, data),
	}
	d.Encoding = encodingOf(data)

	namedFormat, namedCategory := named(strings.ToLower(path.Ext(name)))
	if namedFormat != "" {
		d.Format, d.Category, d.Basis = namedFormat, namedCategory, "extension"
	}

	magicFormat, magicCategory := magic(data)
	if magicFormat != "" {
		d.Conflict = conflictingFormat(namedFormat, namedCategory, magicFormat, magicCategory)

		d.Format, d.Category, d.Basis = magicFormat, magicCategory, "signature"
	}

	applyLanguages(&d)

	d.Executable = namedCategory == "executable" || magicCategory == "executable" || (executable && d.Encoding != "utf-8")

	applyLanguageFormat(&d)

	// A misleading .txt or SKILL.md name cannot exempt a recognized binary.
	if magicFormat != "" && len(d.Languages) > 0 {
		d.Conflict = true
	}

	if executable || strings.HasPrefix(strings.TrimPrefix(data, "\ufeff"), "#!") {
		d.Structured = true
	}

	return d
}

func conflictingFormat(namedFormat, namedCategory, magicFormat, magicCategory string) bool {
	// OOXML and OpenDocument are containers by design.
	if magicCategory == "archive" && namedCategory == "document" && (namedFormat == "ooxml" || namedFormat == "opendocument") {
		return false
	}

	if namedCategory == magicCategory && namedFormat != "" && !equivalent(namedFormat, magicFormat) {
		return true
	}

	return namedCategory != "" && namedCategory != magicCategory
}

func equivalent(named, detected string) bool {
	if named == detected {
		return true
	}

	return slices.Contains(formatEquivalents[named], detected)
}

func named(ext string) (string, string) {
	switch ext {
	case ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".zst", ".jar", ".whl", ".nupkg":
		return strings.TrimPrefix(ext, "."), "archive"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".heic", ".avif":
		return strings.TrimPrefix(ext, "."), "image"
	case ".pdf", ".rtf", ".doc", ".xls", ".ppt":
		return strings.TrimPrefix(ext, "."), "document"
	case ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm":
		return "ooxml", "document"
	case ".odt", ".ods", ".odp":
		return "opendocument", "document"
	case ".exe", ".dll", ".so", ".dylib", ".wasm", ".pyc", ".pyo", ".class", ".o", ".a":
		return strings.TrimPrefix(ext, "."), "executable"
	case ".db", ".sqlite", ".sqlite3":
		return "database", "database"
	case ".mp3", ".wav", ".mp4", ".mov", ".ogg", ".flac":
		return strings.TrimPrefix(ext, "."), "media"
	}

	return "", ""
}

func magic(s string) (string, string) {
	for _, sig := range []struct{ prefix, format, category string }{
		{prefix: "\x7fELF", format: "elf", category: "executable"},
		{prefix: "MZ", format: "pe-candidate", category: "executable"},
		{prefix: "\x00asm", format: "wasm", category: "executable"},
		{prefix: "\xfe\xed\xfa\xce", format: "mach-o", category: "executable"},
		{prefix: "\xce\xfa\xed\xfe", format: "mach-o", category: "executable"},
		{prefix: "\xfe\xed\xfa\xcf", format: "mach-o", category: "executable"},
		{prefix: "\xcf\xfa\xed\xfe", format: "mach-o", category: "executable"},
		{prefix: "\xca\xfe\xba\xbe", format: "java-or-fat-mach-o", category: "executable"},
		{prefix: "\xbe\xba\xfe\xca", format: "fat-mach-o", category: "executable"},
		{prefix: "PK\x03\x04", format: "zip", category: "archive"},
		{prefix: "PK\x05\x06", format: "zip", category: "archive"},
		{prefix: "PK\x07\x08", format: "zip", category: "archive"},
		{prefix: "\x1f\x8b", format: "gzip", category: "archive"},
		{prefix: "BZh", format: "bzip2", category: "archive"},
		{prefix: "\xfd7zXZ\x00", format: "xz", category: "archive"},
		{prefix: "7z\xbc\xaf\x27\x1c", format: "7z", category: "archive"},
		{prefix: "Rar!\x1a\x07", format: "rar", category: "archive"},
		{prefix: "\x28\xb5\x2f\xfd", format: "zstd", category: "archive"},
		{prefix: "\x89PNG\r\n\x1a\n", format: "png", category: "image"},
		{prefix: "\xff\xd8\xff", format: "jpeg", category: "image"},
		{prefix: "GIF87a", format: "gif", category: "image"},
		{prefix: "GIF89a", format: "gif", category: "image"},
		{prefix: "II\x2a\x00", format: "tiff", category: "image"},
		{prefix: "MM\x00\x2a", format: "tiff", category: "image"},
		{prefix: "%PDF-", format: "pdf", category: "document"},
		{prefix: "{\\rtf", format: "rtf", category: "document"},
		{prefix: "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", format: "ole-container", category: "document"},
		{prefix: "SQLite format 3\x00", format: "sqlite", category: "database"},
	} {
		if strings.HasPrefix(s, sig.prefix) {
			return sig.format, sig.category
		}
	}

	if len(s) >= 12 && s[:4] == "RIFF" && s[8:12] == "WEBP" {
		return "webp", "image"
	}

	if len(s) >= 262 && s[257:262] == "ustar" {
		return "tar", "archive"
	}

	return "", ""
}

func encodingOf(data string) string {
	encoding := "bytes"
	if utf8.ValidString(data) && !strings.ContainsRune(data, 0) {
		encoding = "utf-8"
	}

	if strings.HasPrefix(data, "\xff\xfe") {
		encoding = "utf-16le-or-utf-32le"
	}

	if strings.HasPrefix(data, "\xfe\xff") {
		encoding = "utf-16be"
	}

	if strings.HasPrefix(data, "\x00\x00\xfe\xff") {
		encoding = "utf-32be"
	}

	return encoding
}

func applyLanguages(d *Description) {
	first := ""
	for _, h := range d.Languages {
		if first != "" && h.Language != first {
			d.Conflict = true
		}

		first = h.Language
		if language.Structured(h.Language) {
			d.Structured = true
		}
	}
}

func applyLanguageFormat(d *Description) {
	if d.Format == "unknown" && len(d.Languages) > 0 && d.Encoding == "utf-8" {
		d.Format, d.Category, d.Basis = "text", "text", "language-hint"
		if d.Structured {
			d.Category = "source-or-config"
		}
	}
}
