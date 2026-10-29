//nolint:testpackage // Exercises private PE parsing with inert synthetic headers.
package releasecheck

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPEArchitectureAndImports(t *testing.T) {
	for _, tc := range []struct {
		name, issue string
		mutate      func([]byte)
		invalid     bool
	}{
		{name: "amd64", issue: "", mutate: func([]byte) {}, invalid: false},
		{
			name:    "arm64",
			issue:   "",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint16(raw[132:], pe.IMAGE_FILE_MACHINE_ARM64) },
			invalid: false,
		},
		{
			name:    "architecture",
			issue:   "unsupported_architecture",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint16(raw[132:], pe.IMAGE_FILE_MACHINE_I386) },
			invalid: false,
		},
		{name: "dll", issue: "not_executable", mutate: func(raw []byte) {
			binary.LittleEndian.PutUint16(raw[150:], pe.IMAGE_FILE_EXECUTABLE_IMAGE|pe.IMAGE_FILE_DLL)
		}, invalid: false},
		{
			name:    "object",
			issue:   "not_executable",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint16(raw[150:], 0) },
			invalid: false,
		},
		{
			name:    "delay-imports",
			issue:   "delay_imports_not_supported",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint32(raw[152+112+13*8:], 0x1200) },
			invalid: false,
		},
		{
			name:    "import-outside-sections",
			issue:   "",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint32(raw[152+112+8:], 0x9000) },
			invalid: true,
		},
		{
			name:    "unmapped-name",
			issue:   "",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint32(raw[512+12:], 0x9000) },
			invalid: true,
		},
		{
			name:    "unterminated-directory",
			issue:   "",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint32(raw[152+112+8+4:], 20) },
			invalid: true,
		},
		{
			name:    "oversized-directory",
			issue:   "",
			mutate:  func(raw []byte) { binary.LittleEndian.PutUint32(raw[152+112+8+4:], 1<<20) },
			invalid: true,
		},
		{
			name:    "unterminated-name",
			issue:   "",
			mutate:  func(raw []byte) { copy(raw[1024:], bytes.Repeat([]byte{'x'}, 256)) },
			invalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := peFixture(t)
			tc.mutate(raw)
			path := filepath.Join(t.TempDir(), "fixture.exe")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}

			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			}()
			r := newReport()
			err = inspectFormat(file, &r, [4]byte(raw[:4]))
			if (err != nil) != tc.invalid {
				t.Fatalf("report=%+v error=%v", r, err)
			}
			if tc.invalid {
				return
			}
			if r.OS != "windows" || r.Format != "pe" || !slices.Equal(r.Libraries, []string{"KERNEL32.dll"}) {
				t.Fatal(r)
			}
			if tc.issue != "" && !slices.Contains(r.Issues, tc.issue) || tc.issue == "" && len(r.Issues) != 0 {
				t.Fatal(r)
			}
		})
	}
}

// The import name lives in a different section, and OriginalFirstThunk is zero.
// Reading DLL descriptors still finds it, unlike debug/pe.ImportedSymbols.
func peFixture(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 1536)
	copy(raw, "MZ")
	binary.LittleEndian.PutUint32(raw[0x3c:], 128)
	copy(raw[128:], "PE\x00\x00")
	header := pe.FileHeader{
		Machine: pe.IMAGE_FILE_MACHINE_AMD64, NumberOfSections: 2,
		SizeOfOptionalHeader: 240, Characteristics: pe.IMAGE_FILE_EXECUTABLE_IMAGE,
	}
	optional := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16}
	optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: 0x1000, Size: 40}
	var fields bytes.Buffer
	for _, value := range []any{
		header, optional,
		pe.SectionHeader32{VirtualSize: 512, VirtualAddress: 0x1000, SizeOfRawData: 512, PointerToRawData: 512},
		pe.SectionHeader32{VirtualSize: 512, VirtualAddress: 0x2000, SizeOfRawData: 512, PointerToRawData: 1024},
	} {
		if err := binary.Write(&fields, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(raw[132:], fields.Bytes())
	binary.LittleEndian.PutUint32(raw[512+12:], 0x2000)
	binary.LittleEndian.PutUint32(raw[512+16:], 0x1100)
	copy(raw[1024:], "KERNEL32.dll\x00")

	return raw
}
