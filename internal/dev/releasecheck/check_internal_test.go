// Exercises private implementation details and package fixtures.
package releasecheck

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skarm/scout/internal/nativecontract"
)

// Minimal ELF headers exercise the format boundary on every host. These bytes
// are only inspected; no fixture executable or library is ever loaded or run.
func TestELFInterpreterAndExecutableAdmission(t *testing.T) {
	for _, tc := range []struct {
		name          string
		machine       elf.Machine
		typ           elf.Type
		loader, issue string
		oversized     bool
	}{
		{
			name:      "amd64",
			machine:   elf.EM_X86_64,
			typ:       elf.ET_EXEC,
			loader:    "/lib64/ld-linux-x86-64.so.2",
			issue:     "",
			oversized: false,
		},
		{
			name:      "arm64",
			machine:   elf.EM_AARCH64,
			typ:       elf.ET_DYN,
			loader:    "/lib/ld-linux-aarch64.so.1",
			issue:     "",
			oversized: false,
		},
		{
			name:      "foreign_loader",
			machine:   elf.EM_X86_64,
			typ:       elf.ET_EXEC,
			loader:    "/tmp/ld-custom.so",
			issue:     "non_system_interpreter",
			oversized: false,
		},
		{
			name:      "architecture",
			machine:   elf.EM_386,
			typ:       elf.ET_EXEC,
			loader:    "",
			issue:     "unsupported_architecture",
			oversized: false,
		},
		{name: "object", machine: elf.EM_X86_64, typ: elf.ET_REL, loader: "", issue: "not_executable", oversized: false},
		{name: "oversized_loader", machine: elf.EM_X86_64, typ: elf.ET_EXEC, loader: "x", issue: "", oversized: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := elf.Header64{
				Type:      uint16(tc.typ),
				Machine:   uint16(tc.machine),
				Version:   uint32(elf.EV_CURRENT),
				Ehsize:    64,
				Phentsize: 56,
			}
			copy(h.Ident[:], "\x7fELF")
			h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
			h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
			h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
			var raw bytes.Buffer
			if tc.loader != "" {
				h.Phoff, h.Phnum = 64, 1
			}
			if err := binary.Write(&raw, binary.LittleEndian, h); err != nil {
				t.Fatal(err)
			}
			if tc.loader != "" {
				prog := elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 120, Filesz: uint64(len(tc.loader) + 1)}
				if tc.oversized {
					prog.Filesz = 4097
				}
				if err := binary.Write(&raw, binary.LittleEndian, prog); err != nil {
					t.Fatal(err)
				}
				raw.WriteString(tc.loader + "\x00")
			}
			path := filepath.Join(t.TempDir(), "fixture.elf")
			if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
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
			err = inspectELF(file, &r)
			if tc.oversized {
				if err == nil {
					t.Fatal("oversized interpreter accepted")
				}
				return
			}
			if err != nil || r.OS != "linux" || r.Format != "elf" {
				t.Fatal(r, err)
			}
			if tc.issue == "" {
				if len(r.Issues) != 0 {
					t.Fatal(r)
				}
			} else if !slices.Contains(r.Issues, tc.issue) {
				t.Fatal(r)
			}
		})
	}
}

func TestMachOArchitectureAndSearchPathAdmission(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cpu           macho.Cpu
		typ           macho.Type
		search, issue string
	}{
		{name: "amd64", cpu: macho.CpuAmd64, typ: macho.TypeExec, search: "", issue: ""},
		{name: "arm64", cpu: macho.CpuArm64, typ: macho.TypeExec, search: "", issue: ""},
		{name: "architecture", cpu: macho.Cpu386, typ: macho.TypeExec, search: "", issue: "unsupported_architecture"},
		{name: "object", cpu: macho.CpuArm64, typ: macho.TypeObj, search: "", issue: "not_executable"},
		{name: "search_path", cpu: macho.CpuArm64, typ: macho.TypeExec, search: "@loader_path/other", issue: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := macho.FileHeader{Magic: macho.Magic64, Cpu: tc.cpu, Type: tc.typ}
			var command bytes.Buffer
			if tc.search != "" {
				length := uint32((12 + len(tc.search) + 1 + 7) / 8 * 8)
				if err := binary.Write(&command, binary.LittleEndian, macho.RpathCmd{
					Cmd:  macho.LoadCmdRpath,
					Len:  length,
					Path: 12,
				}); err != nil {
					t.Fatal(err)
				}
				command.WriteString(tc.search + "\x00")
				command.Write(make([]byte, int(length)-command.Len()))
				h.Ncmd, h.Cmdsz = 1, length
			}
			var raw bytes.Buffer
			if err := binary.Write(&raw, binary.LittleEndian, h); err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(&raw, binary.LittleEndian, uint32(0)); err != nil {
				t.Fatal(err)
			}
			raw.Write(command.Bytes())
			path := filepath.Join(t.TempDir(), "fixture.macho")
			if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
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
			if err := inspectMachO(file, &r); err != nil {
				t.Fatal(err)
			}
			if r.OS != "darwin" || r.Format != "macho" {
				t.Fatal(r)
			}
			if tc.issue != "" && !slices.Contains(r.Issues, tc.issue) {
				t.Fatal(r)
			}
			if tc.search != "" && !slices.Contains(r.SearchPaths, tc.search) {
				t.Fatal(r)
			}
		})
	}
}

func TestCapturedSelftestMustBeCompleteAndUnambiguous(t *testing.T) {
	test := nativecontract.Report{
		Schema:   nativecontract.Schema,
		Version:  "fixture",
		Platform: "linux/amd64",
		Passed:   true,
	}
	for _, id := range nativecontract.IDs() {
		backend, _, _ := strings.Cut(id, "-")
		switch backend {
		case "yara":
			backend = "yara-x"
		case "python":
			backend = "python"
		}
		test.Checks = append(test.Checks, nativecontract.Check{ID: id, Backend: backend, Status: "passed"})
	}
	raw, err := json.Marshal(test)
	if err != nil {
		t.Fatal(err)
	}
	base := newReport()
	base.OS, base.Arch = "linux", "amd64"
	for _, tc := range []struct {
		name, issue      string
		raw              []byte
		stderr           string
		overflow, failed bool
	}{
		{name: "complete", issue: "", raw: raw, stderr: "", overflow: false, failed: false},
		{name: "overflow", issue: "selftest_output_limit", raw: raw, stderr: "", overflow: true, failed: false},
		{name: "process", issue: "selftest_process_failed", raw: raw, stderr: "", overflow: false, failed: true},
		{
			name:     "invalid",
			issue:    "invalid_selftest_report",
			raw:      []byte("{"),
			stderr:   "",
			overflow: false,
			failed:   false,
		},
		{
			name:     "trailing",
			issue:    "trailing_selftest_output",
			raw:      append(slices.Clone(raw), []byte(" {}")...),
			stderr:   "",
			overflow: false,
			failed:   false,
		},
		{
			name:     "incomplete",
			issue:    "selftest_not_complete",
			raw:      []byte(`{"schema":"1","version":"fixture","platform":"linux/amd64","passed":true,"checks":[]}`),
			stderr:   "",
			overflow: false,
			failed:   false,
		},
		{name: "stderr", issue: "unexpected_stderr", raw: raw, stderr: "unexpected", overflow: false, failed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, stderr := &boundedBuffer{limit: 128 << 10, overflow: tc.overflow}, &boundedBuffer{limit: 16 << 10}
			if _, err := out.Write(tc.raw); err != nil {
				t.Error(err)
			}
			if _, err := stderr.Write([]byte(tc.stderr)); err != nil {
				t.Error(err)
			}
			var processErr error
			if tc.failed {
				processErr = errors.New("fixture process failure")
			}
			r := acceptSelftest(base, out, stderr, processErr)
			if tc.issue == "" {
				if !r.Passed || r.Selftest == nil {
					t.Fatal(r)
				}
				return
			}
			if r.Passed || !slices.Contains(r.Issues, tc.issue) {
				t.Fatal(r)
			}
		})
	}
}

func TestTrustedReleaseRoundTrip(t *testing.T) {
	bin := os.Getenv("SCOUT_TEST_BIN")
	if bin == "" {
		t.Skip("set SCOUT_TEST_BIN to an explicitly selected trusted release build")
	}
	r, err := Verify(t.Context(), bin)
	if err != nil || !r.Passed || r.Selftest == nil {
		t.Fatal(r, err)
	}
}
