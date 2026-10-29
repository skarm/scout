package extract

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/skarm/scout/internal/capture/archiveutil"
	"github.com/skarm/scout/report"
)

// contextByteReader preserves exact gzip member boundaries while making reads
// cooperative. It is deliberately not a shell, filesystem or network adapter.
type contextByteReader struct {
	ctx interface{ Err() error }
	r   *strings.Reader
}

type metadataValue struct{ name, value string }

func (r contextByteReader) Read(p []byte) (int, error) {
	return (contextReader{ctx: r.ctx, r: r.r}).Read(p)
}

func (r contextByteReader) ReadByte() (byte, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}

	return r.r.ReadByte()
}

func extractZIP(o *operation) error {
	o.role = "archive_member"
	remaining := o.b.limits.MaxEntries - o.b.result.Report.EntriesVisited

	zr, err := archiveutil.OpenZIPWithBudget(o.b.ctx, []byte(o.parent.file.Content()), remaining, 1024, 32, o.entry)
	if err != nil {
		return err
	}
	// Central-directory order is retained in provenance. Even empty directories
	// consume the scan-wide entry budget; metadata objects consume object budgets.
	for _, entry := range zr.File {
		if err = o.b.ctx.Err(); err != nil {
			return err
		}

		if err := extractZIPMember(o, entry); err != nil {
			return err
		}
	}

	return extractZIPMetadata(o, zr)
}

func extractZIPMember(o *operation, entry *zip.File) error {
	if entry.FileInfo().IsDir() {
		return nil
	}

	if o.b.limits.MaxObjectBytes < 0 || entry.UncompressedSize64 > uint64(o.b.limits.MaxObjectBytes) {
		size := int64(math.MaxInt64)
		if entry.UncompressedSize64 <= math.MaxInt64 {
			size = int64(entry.UncompressedSize64)
		}

		o.skipMember(entry.Name, "object_byte_limit", size)
		o.issue("extraction_object_limit", "An archive member exceeds the per-object budget; its prefix is not analyzed as a complete member.")
		o.b.result.Report.Steps[o.step].Status = report.OutcomePartial

		return nil
	}

	if entry.UncompressedSize64 > math.MaxInt64 {
		return errFormat
	}

	r, e := entry.Open()
	if e != nil {
		return e
	}

	e = o.emit(entry.Name, r, int64(entry.UncompressedSize64), entry.Mode()&0o111 != 0, nil)
	closeErr := r.Close()

	if e != nil {
		return e
	}

	if closeErr != nil {
		return closeErr
	}

	return nil
}

func emitMetadata(o *operation, values ...metadataValue) error {
	for _, field := range values {
		if field.value == "" {
			continue
		}

		if err := o.entry(); err != nil {
			return err
		}

		if err := o.text(field.name, field.value, nil); err != nil {
			return err
		}
	}

	return nil
}

func extractZIPMetadata(o *operation, zr *zip.Reader) error {
	o.role = "metadata"
	if err := emitMetadata(o, metadataValue{name: "archive-comment.txt", value: zr.Comment}); err != nil {
		return err
	}

	for _, entry := range zr.File {
		if err := emitMetadata(o, metadataValue{name: "member-comment.txt", value: entry.Comment}, metadataValue{
			name:  "zip-extra.bin",
			value: string(entry.Extra),
		}); err != nil {
			return err
		}
	}

	return nil
}

func extractGZIP(o *operation) error {
	data := o.parent.file.Content()
	reader := strings.NewReader(data)
	stream := 0

	for reader.Len() > 0 {
		if err := o.entry(); err != nil {
			return err
		}

		if err := extractGZIPMember(o, data, reader); err != nil {
			return err
		}

		stream++
	}

	if stream == 0 {
		return errFormat
	}

	return nil
}

func extractGZIPMember(o *operation, data string, reader *strings.Reader) error {
	start := len(data) - reader.Len()

	gz, err := gzip.NewReader(contextByteReader{ctx: o.b.ctx, r: reader})
	if err != nil {
		return err
	}

	gz.Multistream(false)

	name := gzipMemberName(o, gz)
	comment := gz.Comment
	extra := append([]byte(nil), gz.Extra...)
	err = o.emit(name, gz, -1, false, nil)
	closeErr := gz.Close()

	if err != nil {
		return err
	}

	if closeErr != nil {
		return closeErr
	}

	if reader.Len() >= len(data)-start {
		return errFormat
	}
	// ByteReader prevents gzip read-ahead from swallowing the next member.
	child := &o.b.result.Report.Objects[len(o.b.result.Report.Objects)-1]
	child.ParentRange = &report.ByteRange{Start: start, End: len(data) - reader.Len()}

	if err = extractGZIPMetadata(o, comment, extra); err != nil {
		return err
	}

	return nil
}

func gzipMemberName(o *operation, gz *gzip.Reader) string {
	name := inheritedName(o.parent.file.Metadata().Path, ".gz")
	if strings.HasSuffix(strings.ToLower(name), ".tgz") {
		name = name[:len(name)-4] + ".tar"
	}

	if gz.Name != "" {
		if err := archiveutil.ValidatePath(gz.Name, 1024, 32); err != nil {
			o.issue("gzip_name_untrusted", "Gzip filename is unsafe or ambiguous; a synthetic name was used.")
		} else {
			name = gz.Name
		}
	}

	return name
}

func extractGZIPMetadata(o *operation, comment string, extra []byte) error {
	return emitMetadata(o, metadataValue{name: "gzip-comment.txt", value: comment}, metadataValue{
		name:  "gzip-extra.bin",
		value: string(extra),
	})
}

// TAR support intentionally excludes PAX/GNU/sparse/link records. Inspect each
// raw header before tar.Reader can consume hidden metadata pseudo-entries. The
// raw container stays available for rules even when this narrow profile fails.
func extractTAR(o *operation) error {
	o.role = "archive_member"
	data := o.parent.file.Content()
	names := archiveutil.Namespace{MaxNodes: o.b.limits.MaxEntries - o.b.result.Report.EntriesVisited}

	at := 0
	for at < len(data) {
		next, done, err := extractTARMember(o, &names, data, at)
		if err != nil {
			return err
		}

		if done {
			return nil
		}

		at = next
	}
	// Two end blocks are required by this narrow profile.
	return io.ErrUnexpectedEOF
}

func extractTARMember(o *operation, names *archiveutil.Namespace, data string, at int) (int, bool, error) {
	if err := o.entry(); err != nil {
		return at, false, err
	}

	done, err := tarEndMarker(data, at)
	if err != nil || done {
		return at, done, err
	}

	hdr, tr, err := readTARHeader(data[at:])
	if err != nil {
		return at, false, err
	}

	name := strings.TrimSuffix(hdr.Name, "/")
	if err := archiveutil.ValidatePath(name, 1024, 32); err != nil {
		return at, false, err
	}

	directory := hdr.Typeflag == tar.TypeDir
	if err := names.Add(name, directory); err != nil {
		return at, false, err
	}

	padded, err := tarPayloadLayout(hdr, directory, len(data)-at-512)
	if err != nil {
		return at, false, err
	}

	if err := emitTARMember(o, tr, hdr, name, at); err != nil {
		return at, false, err
	}

	return at + 512 + int(padded), false, nil
}

func tarEndMarker(data string, at int) (bool, error) {
	if len(data)-at < 512 {
		return false, errFormat
	}

	if strings.Trim(data[at:at+512], "\x00") != "" {
		return false, nil
	}

	if len(data)-at < 1024 || strings.Trim(data[at:], "\x00") != "" {
		return false, errFormat
	}

	return true, nil
}

func readTARHeader(data string) (*tar.Header, *tar.Reader, error) {
	typ := data[156]
	if !slices.Contains([]byte{tar.TypeReg, 0, tar.TypeDir}, typ) {
		return nil, nil, errFormat
	}

	tr := tar.NewReader(strings.NewReader(data))

	hdr, err := tr.Next()
	if err != nil {
		return nil, nil, err
	}

	if !slices.Contains([]tar.Format{tar.FormatUSTAR, tar.FormatUnknown}, hdr.Format) {
		return nil, nil, errFormat
	}

	if len(hdr.PAXRecords) > 0 || hdr.Linkname != "" || hdr.Size < 0 {
		return nil, nil, errFormat
	}

	return hdr, tr, nil
}

func tarPayloadLayout(hdr *tar.Header, directory bool, available int) (int64, error) {
	if directory && hdr.Size != 0 {
		return 0, errFormat
	}
	// Bound the declared expansion before arithmetic and allocation.
	if hdr.Size > int64(available) {
		return 0, errFormat
	}

	padded := (hdr.Size + 511) / 512 * 512
	if padded > int64(available) {
		return 0, errFormat
	}

	return padded, nil
}

func emitTARMember(o *operation, tr *tar.Reader, hdr *tar.Header, name string, at int) error {
	if hdr.Typeflag == tar.TypeDir {
		return nil
	}

	if hdr.Size > o.b.limits.MaxObjectBytes {
		o.skipMember(name, "object_byte_limit", hdr.Size)
		o.issue("extraction_object_limit", "A TAR member exceeds the object budget; its prefix is not accepted.")
		o.b.result.Report.Steps[o.step].Status = report.OutcomePartial

		return nil
	}

	return o.emit(name, tr, hdr.Size, hdr.Mode&0o111 != 0, &report.ByteRange{
		Start: at + 512,
		End:   at + 512 + int(hdr.Size),
	})
}
