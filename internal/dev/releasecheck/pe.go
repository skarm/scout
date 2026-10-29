package releasecheck

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
)

func inspectPE(f *os.File, r *Report) error {
	file, err := pe.NewFile(f)
	if err != nil {
		return errors.New("invalid PE binary")
	}

	r.Format, r.OS = "pe", "windows"

	switch file.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		r.Arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		r.Arch = "arm64"
	default:
		r.Issues = append(r.Issues, "unsupported_architecture")
	}

	if file.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || file.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		r.Issues = append(r.Issues, "not_executable")
	}

	header, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return errors.New("release requires a PE32+ optional header")
	}

	if header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0 {
		r.Issues = append(r.Issues, "delay_imports_not_supported")
	}

	r.Libraries, err = peImports(file, header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT])

	return err
}

// debug/pe.ImportedLibraries is unimplemented. Read DLL descriptors directly,
// including ordinal-only imports and names stored in a different section.
func peImports(file *pe.File, directory pe.DataDirectory) ([]string, error) {
	libraries := make([]string, 0)
	if directory.VirtualAddress == 0 && directory.Size == 0 {
		return libraries, nil
	}

	if directory.VirtualAddress == 0 || directory.Size < 20 || directory.Size > 64<<10 {
		return nil, errors.New("invalid PE import directory")
	}

	data, err := peReadRVA(file, directory.VirtualAddress, directory.Size)
	if err != nil {
		return nil, err
	}

	for len(data) >= 20 {
		descriptor := data[:20]
		data = data[20:]

		if bytes.Equal(descriptor, make([]byte, 20)) {
			return libraries, nil
		}

		name, err := peLibraryName(file, binary.LittleEndian.Uint32(descriptor[12:16]))
		if err != nil {
			return nil, err
		}

		libraries = append(libraries, name)
	}

	return nil, errors.New("unterminated PE import directory")
}

func peLibraryName(file *pe.File, address uint32) (string, error) {
	var name strings.Builder

	for offset := range uint32(256) {
		if address == 0 || address+offset < address {
			break
		}

		data, err := peReadRVA(file, address+offset, 1)
		if err != nil {
			return "", err
		}

		if data[0] == 0 {
			if name.Len() > 0 {
				return name.String(), nil
			}

			break
		}

		name.WriteByte(data[0])
	}

	return "", errors.New("invalid PE import name")
}

func peReadRVA(file *pe.File, address, size uint32) ([]byte, error) {
	for _, section := range file.Sections {
		if address < section.VirtualAddress {
			continue
		}

		offset := address - section.VirtualAddress
		if offset > section.Size || size > section.Size-offset {
			continue
		}

		data := make([]byte, size)
		if _, err := io.ReadFull(io.NewSectionReader(section, int64(offset), int64(size)), data); err != nil {
			return nil, errors.New("truncated PE import data")
		}

		return data, nil
	}

	return nil, errors.New("PE import address outside file sections")
}
