package archiveutil

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"
)

type zipDirectoryHeader struct {
	count, end int
	offset     uint32
}

type zipExtent struct{ start, end int64 }

type zipRecords struct {
	data        []byte
	offset      uint32
	end, cursor int
	extents     []zipExtent
}

// OpenZIP accepts only bounded, single-disk ZIP32 with an unambiguous namespace.
// The central-directory envelope is inspected BEFORE archive/zip may allocate
// its entry inventory. No member contents are decompressed by this function.
func OpenZIP(ctx context.Context, data []byte, maxEntries, maxPath, maxDepth int) (*zip.Reader, error) {
	return OpenZIPWithBudget(ctx, data, maxEntries, maxPath, maxDepth, nil)
}

// OpenZIPWithBudget charges entries during envelope validation, including an
// entry that later fails validation. The callback is trusted scanner code.
func OpenZIPWithBudget(ctx context.Context, data []byte, maxEntries, maxPath, maxDepth int, visit func() error) (*zip.Reader, error) {
	if err := validateZIPArguments(ctx, maxEntries, maxPath, maxDepth); err != nil {
		return nil, err
	}

	if err := zipEnvelope(ctx, data, maxEntries, visit); err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	names := Namespace{MaxNodes: maxEntries}

	for _, entry := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := validateZIPEntry(entry, &names, maxPath, maxDepth); err != nil {
			return nil, err
		}
	}

	return zr, nil
}

func validateZIPArguments(ctx context.Context, maxEntries, maxPath, maxDepth int) error {
	if ctx == nil {
		return errors.New("invalid ZIP validation arguments")
	}

	for _, bound := range []struct{ value, minimum, maximum int }{{value: maxEntries, minimum: 0, maximum: 100000}, {
		value:   maxPath,
		minimum: 1,
		maximum: 4096,
	}, {
		value:   maxDepth,
		minimum: 1,
		maximum: 128,
	}} {
		if bound.value < bound.minimum || bound.value > bound.maximum {
			return errors.New("invalid ZIP validation arguments")
		}
	}

	return nil
}

func validateZIPEntry(entry *zip.File, names *Namespace, maxPath, maxDepth int) error {
	name := strings.TrimSuffix(entry.Name, "/")
	if err := ValidatePath(name, maxPath, maxDepth); err != nil {
		return errors.New("unsafe ZIP path")
	}

	directory := strings.HasSuffix(entry.Name, "/")
	if err := names.Add(name, directory); err != nil {
		return err
	}

	mode := entry.Mode()
	if directory != mode.IsDir() || (!mode.IsRegular() && !mode.IsDir()) {
		return errors.New("ZIP link, special file or inconsistent directory")
	}

	return validateZIPEncoding(entry, directory)
}

func validateZIPEncoding(entry *zip.File, directory bool) error {
	if entry.Flags&(1|64) != 0 {
		return errors.New("encrypted ZIP entry")
	}

	if entry.Method != zip.Store && entry.Method != zip.Deflate {
		return errors.New("unsupported ZIP compression")
	}

	if directory && entry.UncompressedSize64 != 0 {
		return errors.New("directory payload")
	}

	return nil
}

func zipEnvelope(ctx context.Context, data []byte, maxEntries int, visit func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	header, err := readZIPDirectoryHeader(data, maxEntries)
	if err != nil {
		return err
	}

	records := zipRecords{
		data:    data,
		offset:  header.offset,
		end:     header.end,
		cursor:  int(header.offset),
		extents: make([]zipExtent, 0, header.count),
	}
	for range header.count {
		if visit != nil {
			if err := visit(); err != nil {
				return err
			}
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if err := records.readRecord(); err != nil {
			return err
		}
	}

	if records.cursor != header.end {
		return errors.New("ZIP entry count does not match central directory")
	}

	return validateZIPLayout(records.extents)
}

func readZIPDirectoryHeader(data []byte, maxEntries int) (zipDirectoryHeader, error) {
	end := findZIPEnd(data)
	if end < 0 {
		return zipDirectoryHeader{}, errors.New("invalid ZIP end record")
	}

	e := data[end:]
	count := int(binary.LittleEndian.Uint16(e[10:12]))
	size := uint64(binary.LittleEndian.Uint32(e[12:16]))

	offset := binary.LittleEndian.Uint32(e[16:20])
	if binary.LittleEndian.Uint32(e[4:8]) != 0 || int(binary.LittleEndian.Uint16(e[8:10])) != count {
		return zipDirectoryHeader{}, errors.New("multi-disk ZIP is unsupported")
	}

	if count == 0xffff || size == 0xffffffff || offset == 0xffffffff {
		return zipDirectoryHeader{}, errors.New("ZIP64 is not supported in this profile")
	}

	if count > maxEntries {
		return zipDirectoryHeader{}, errors.New("ZIP inventory exceeds entry budget")
	}

	if !zipDirectoryBounds(offset, size, end, len(data)) {
		return zipDirectoryHeader{}, errors.New("invalid or unsupported ZIP central directory")
	}

	return zipDirectoryHeader{count: count, end: end, offset: offset}, nil
}

func findZIPEnd(data []byte) int {
	// EOCD must end at EOF. Appended data and wrappers are outside this profile.
	for i := len(data) - 22; i >= max(0, len(data)-22-65535); i-- {
		if binary.LittleEndian.Uint32(data[i:i+4]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(data[i+20:i+22])) == len(data) {
			return i
		}
	}

	return -1
}

func validateZIPLayout(extents []zipExtent) error {
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })

	for i := 1; i < len(extents); i++ {
		if extents[i].start < extents[i-1].end {
			return errors.New("overlapping ZIP members")
		}
	}

	if len(extents) > 0 && extents[0].start != 0 {
		return errors.New("ZIP preambles are unsupported")
	}

	return nil
}

func (r *zipRecords) readRecord() error {
	data, offset, end, cursor := r.data, r.offset, r.end, r.cursor
	if cursor > end-46 || binary.LittleEndian.Uint32(data[cursor:cursor+4]) != 0x02014b50 {
		return errors.New("invalid ZIP central record")
	}

	record := data[cursor : cursor+46]
	// ZIP64 fields and split archives are rejected before parser expansion.
	if !zip32Record(record) {
		return errors.New("ZIP64 or split member is unsupported")
	}

	localOffset := int64(binary.LittleEndian.Uint32(record[42:46]))
	if localOffset+30 > int64(offset) || binary.LittleEndian.Uint32(data[localOffset:localOffset+4]) != 0x04034b50 {
		return errors.New("invalid ZIP local header")
	}

	nameLength := int(binary.LittleEndian.Uint16(record[28:30]))

	next := cursor + 46 + nameLength + int(binary.LittleEndian.Uint16(record[30:32])) + int(binary.LittleEndian.Uint16(record[32:34]))
	if next > end {
		return io.ErrUnexpectedEOF
	}

	recordEnd, err := validateZIPLocal(data, record, localOffset, int64(offset), cursor, nameLength)
	if err != nil {
		return err
	}

	r.extents = append(r.extents, zipExtent{start: localOffset, end: recordEnd})
	r.cursor = next

	return nil
}

func validateZIPLocal(data, record []byte, localOffset, offset int64, cursor, nameLength int) (int64, error) {
	local := data[localOffset : localOffset+30]
	localNameLength := int64(binary.LittleEndian.Uint16(local[26:28]))
	localExtraLength := int64(binary.LittleEndian.Uint16(local[28:30]))
	payloadStart := localOffset + 30 + localNameLength + localExtraLength

	payloadEnd := payloadStart + int64(binary.LittleEndian.Uint32(record[20:24]))
	if payloadEnd > offset {
		return 0, errors.New("ZIP member overlaps central directory")
	}

	if localNameLength != int64(nameLength) || !bytes.Equal(data[localOffset+30:localOffset+30+localNameLength], data[cursor+46:cursor+46+nameLength]) {
		return 0, errors.New("ZIP local and central names disagree")
	}

	if !bytes.Equal(local[6:10], record[8:12]) {
		return 0, errors.New("ZIP local and central flags/method disagree")
	}

	recordEnd := payloadEnd

	if binary.LittleEndian.Uint16(local[6:8])&8 == 0 {
		if !bytes.Equal(local[14:26], record[16:28]) {
			return 0, errors.New("ZIP local and central CRC/size disagree")
		}
	} else {
		return validateZIPDescriptor(data, record, local, payloadEnd, offset)
	}

	return recordEnd, nil
}

func validateZIPDescriptor(data, record, local []byte, payloadEnd, offset int64) (int64, error) {
	// A descriptor is 12 bytes, optionally preceded by its signature.
	// Bound it against the central directory before slicing it.
	dd := payloadEnd
	if dd+12 > offset {
		return 0, io.ErrUnexpectedEOF
	}

	if binary.LittleEndian.Uint32(data[dd:dd+4]) == 0x08074b50 {
		dd += 4
	}

	if dd+12 > offset {
		return 0, io.ErrUnexpectedEOF
	}

	if !bytes.Equal(data[dd:dd+12], record[16:28]) {
		return 0, errors.New("ZIP descriptor disagrees with directory")
	}

	for i := range 3 {
		value := binary.LittleEndian.Uint32(local[14+i*4 : 18+i*4])
		if value != 0 && value != binary.LittleEndian.Uint32(record[16+i*4:20+i*4]) {
			return 0, errors.New("ZIP descriptor-mode local field disagrees")
		}
	}

	return dd + 12, nil
}

func zipDirectoryBounds(offset uint32, size uint64, end, dataLength int) bool {
	return uint64(offset)+size == uint64(end) && uint64(offset) <= uint64(dataLength) && uint64(offset) <= uint64(^uint(0)>>1) //nolint:gosec // G115: end is an admitted slice index; dataLength is len(data), so both are nonnegative.
}

func zip32Record(record []byte) bool {
	return binary.LittleEndian.Uint16(record[34:36]) == 0 && binary.LittleEndian.Uint32(record[20:24]) != 0xffffffff && binary.LittleEndian.Uint32(record[24:28]) != 0xffffffff && binary.LittleEndian.Uint32(record[42:46]) != 0xffffffff
}
