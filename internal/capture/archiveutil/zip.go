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

	"github.com/skarm/scout/report"
)

const (
	zipEndDiskNumbersOffset            = 4
	zipEndDiskRecordCountOffset        = 8
	zipEndRecordCountOffset            = 10
	zipEndDirectorySizeOffset          = 12
	zipEndDirectoryOffset              = 16
	zipEndCommentLengthOffset          = 20
	zipDirectoryFlagsOffset            = 8
	zipDirectoryCRCOffset              = 16
	zipDirectoryCompressedSizeOffset   = 20
	zipDirectoryUncompressedSizeOffset = 24
	zipDirectoryNameLengthOffset       = 28
	zipDirectoryExtraLengthOffset      = 30
	zipDirectoryCommentLengthOffset    = 32
	zipDirectoryStartDiskOffset        = 34
	zipDirectoryMemberOffset           = 42
	zipLocalFlagsOffset                = 6
	zipLocalCRCOffset                  = 14
	zipLocalNameLengthOffset           = 26
	zipLocalExtraLengthOffset          = 28
	zipFlagsAndMethodBytes             = 4
	zipUint16Bytes                     = 2
	zipUint32Bytes                     = 4
	zipDescriptorFields                = 3
)

const (
	zipEndHeaderBytes       = 22
	zipDirectoryHeaderBytes = 46
	zipLocalHeaderBytes     = 30
	zipDescriptorBytes      = 12
	zipSignatureBytes       = 4
	zipEndSignature         = 0x06054b50
	zipDirectorySignature   = 0x02014b50
	zipLocalSignature       = 0x04034b50
	zipDescriptorSignature  = 0x08074b50
	zip64SizeSentinel       = 0xffffffff
	zip64CountSentinel      = 0xffff
	zipMaxCommentBytes      = 65535
	zipDescriptorFlag       = 8
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

	for _, bound := range []struct{ value, minimum, maximum int }{{value: maxEntries, minimum: 0, maximum: report.MaxArtifactEntries}, {
		value:   maxPath,
		minimum: 1,
		maximum: report.MaxArtifactPathBytes,
	}, {
		value:   maxDepth,
		minimum: 1,
		maximum: report.MaxArtifactPathDepth,
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
	count := int(binary.LittleEndian.Uint16(e[zipEndRecordCountOffset:zipEndDirectorySizeOffset]))
	size := uint64(binary.LittleEndian.Uint32(e[zipEndDirectorySizeOffset:zipEndDirectoryOffset]))

	offset := binary.LittleEndian.Uint32(e[zipEndDirectoryOffset:zipEndCommentLengthOffset])
	if binary.LittleEndian.Uint32(e[zipEndDiskNumbersOffset:zipEndDiskRecordCountOffset]) != 0 ||
		int(binary.LittleEndian.Uint16(e[zipEndDiskRecordCountOffset:zipEndRecordCountOffset])) != count {
		return zipDirectoryHeader{}, errors.New("multi-disk ZIP is unsupported")
	}

	if count == zip64CountSentinel || size == zip64SizeSentinel || offset == zip64SizeSentinel {
		return zipDirectoryHeader{}, errors.New("ZIP64 is not supported in this profile")
	}

	if count > maxEntries {
		return zipDirectoryHeader{}, errors.New("ZIP inventory exceeds entry budget")
	}

	if !zipDirectoryBounds(offset, size, end, len(data)) {
		return zipDirectoryHeader{}, errors.New("invalid or unsupported ZIP central directory")
	}

	// Empty inventories have no local extent for validateZIPLayout to inspect.
	if count == 0 && offset != 0 {
		return zipDirectoryHeader{}, errors.New("ZIP preambles are unsupported")
	}

	return zipDirectoryHeader{count: count, end: end, offset: offset}, nil
}

func findZIPEnd(data []byte) int {
	// EOCD must end at EOF. Appended data and wrappers are outside this profile.
	for i := len(data) - zipEndHeaderBytes; i >= max(0, len(data)-zipEndHeaderBytes-zipMaxCommentBytes); i-- {
		if binary.LittleEndian.Uint32(data[i:i+zipSignatureBytes]) == zipEndSignature &&
			i+zipEndHeaderBytes+int(binary.LittleEndian.Uint16(data[i+zipEndCommentLengthOffset:i+zipEndHeaderBytes])) == len(data) {
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
	if cursor > end-zipDirectoryHeaderBytes || binary.LittleEndian.Uint32(data[cursor:cursor+zipSignatureBytes]) != zipDirectorySignature {
		return errors.New("invalid ZIP central record")
	}

	record := data[cursor : cursor+zipDirectoryHeaderBytes]
	// ZIP64 fields and split archives are rejected before parser expansion.
	if !zip32Record(record) {
		return errors.New("ZIP64 or split member is unsupported")
	}

	localOffset := int64(binary.LittleEndian.Uint32(record[zipDirectoryMemberOffset:zipDirectoryHeaderBytes]))
	if localOffset+zipLocalHeaderBytes > int64(offset) || binary.LittleEndian.Uint32(data[localOffset:localOffset+zipSignatureBytes]) != zipLocalSignature {
		return errors.New("invalid ZIP local header")
	}

	nameLength := int(binary.LittleEndian.Uint16(record[zipDirectoryNameLengthOffset:zipDirectoryExtraLengthOffset]))

	next := cursor + zipDirectoryHeaderBytes + nameLength +
		int(binary.LittleEndian.Uint16(record[zipDirectoryExtraLengthOffset:zipDirectoryCommentLengthOffset])) +
		int(binary.LittleEndian.Uint16(record[zipDirectoryCommentLengthOffset:zipDirectoryStartDiskOffset]))
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
	local := data[localOffset : localOffset+zipLocalHeaderBytes]
	localNameLength := int64(binary.LittleEndian.Uint16(local[zipLocalNameLengthOffset:zipLocalExtraLengthOffset]))
	localExtraLength := int64(binary.LittleEndian.Uint16(local[zipLocalExtraLengthOffset:zipLocalHeaderBytes]))
	payloadStart := localOffset + zipLocalHeaderBytes + localNameLength + localExtraLength

	payloadEnd := payloadStart + int64(binary.LittleEndian.Uint32(record[zipDirectoryCompressedSizeOffset:zipDirectoryUncompressedSizeOffset]))
	if payloadEnd > offset {
		return 0, errors.New("ZIP member overlaps central directory")
	}

	if localNameLength != int64(nameLength) || !bytes.Equal(data[localOffset+zipLocalHeaderBytes:localOffset+zipLocalHeaderBytes+localNameLength], data[cursor+zipDirectoryHeaderBytes:cursor+zipDirectoryHeaderBytes+nameLength]) {
		return 0, errors.New("ZIP local and central names disagree")
	}

	if !bytes.Equal(local[zipLocalFlagsOffset:zipLocalFlagsOffset+zipFlagsAndMethodBytes], record[zipDirectoryFlagsOffset:zipDirectoryFlagsOffset+zipFlagsAndMethodBytes]) {
		return 0, errors.New("ZIP local and central flags/method disagree")
	}

	recordEnd := payloadEnd

	if binary.LittleEndian.Uint16(local[zipLocalFlagsOffset:zipLocalFlagsOffset+zipUint16Bytes])&zipDescriptorFlag == 0 {
		if !bytes.Equal(local[zipLocalCRCOffset:zipLocalNameLengthOffset], record[zipDirectoryCRCOffset:zipDirectoryNameLengthOffset]) {
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
	if dd+zipDescriptorBytes > offset {
		return 0, io.ErrUnexpectedEOF
	}

	if binary.LittleEndian.Uint32(data[dd:dd+zipSignatureBytes]) == zipDescriptorSignature {
		dd += zipSignatureBytes
	}

	if dd+zipDescriptorBytes > offset {
		return 0, io.ErrUnexpectedEOF
	}

	if !bytes.Equal(data[dd:dd+zipDescriptorBytes], record[zipDirectoryCRCOffset:zipDirectoryNameLengthOffset]) {
		return 0, errors.New("ZIP descriptor disagrees with directory")
	}

	for i := range zipDescriptorFields {
		value := binary.LittleEndian.Uint32(local[zipLocalCRCOffset+i*zipUint32Bytes : zipLocalCRCOffset+(i+1)*zipUint32Bytes])
		if value != 0 && value != binary.LittleEndian.Uint32(record[zipDirectoryCRCOffset+i*zipUint32Bytes:zipDirectoryCRCOffset+(i+1)*zipUint32Bytes]) {
			return 0, errors.New("ZIP descriptor-mode local field disagrees")
		}
	}

	return dd + zipDescriptorBytes, nil
}

func zipDirectoryBounds(offset uint32, size uint64, end, dataLength int) bool {
	return uint64(offset)+size == uint64(end) && uint64(offset) <= uint64(dataLength) && uint64(offset) <= uint64(^uint(0)>>1) //nolint:gosec // G115: end is an admitted slice index; dataLength is len(data), so both are nonnegative.
}

func zip32Record(record []byte) bool {
	return binary.LittleEndian.Uint16(record[zipDirectoryStartDiskOffset:zipDirectoryStartDiskOffset+zipUint16Bytes]) == 0 &&
		binary.LittleEndian.Uint32(record[zipDirectoryCompressedSizeOffset:zipDirectoryUncompressedSizeOffset]) != zip64SizeSentinel &&
		binary.LittleEndian.Uint32(record[zipDirectoryUncompressedSizeOffset:zipDirectoryNameLengthOffset]) != zip64SizeSentinel &&
		binary.LittleEndian.Uint32(record[zipDirectoryMemberOffset:zipDirectoryHeaderBytes]) != zip64SizeSentinel
}
