// Package releasecheck inspects scanner RELEASE binaries, never untrusted skills.
// It does not load inspected libraries. Execution is a separate, explicit phase
// after checking linkage and Go build metadata; only fixed native selftests run.
package releasecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skarm/scout/internal/nativecontract"
)

const maxBinarySize = 512 << 20

//nolint:gochecknoglobals // Read-only system loader metadata shared by binary inspections.
var systemLoaders = map[string][]string{
	"amd64": {"/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib/ld-musl-x86_64.so.1"},
	"arm64": {"/lib/ld-linux-aarch64.so.1", "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", "/lib/ld-musl-aarch64.so.1"},
}

type module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}
type Report struct {
	Schema      string                 `json:"schema"`
	SHA256      string                 `json:"sha256,omitempty"`
	Size        int64                  `json:"size"`
	Format      string                 `json:"format,omitempty"`
	OS          string                 `json:"os,omitempty"`
	Arch        string                 `json:"arch,omitempty"`
	GoVersion   string                 `json:"go_version,omitempty"`
	Modules     []module               `json:"modules"`
	Libraries   []string               `json:"libraries"`
	SearchPaths []string               `json:"search_paths"`
	Issues      []string               `json:"issues"`
	Selftest    *nativecontract.Report `json:"selftest,omitempty"`
	Passed      bool                   `json:"passed"`
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

// RequiredModules are the selected native/config libraries, not an exhaustive
// SBOM. Sums must be present in a releasable Go binary, with no local replaces.
func RequiredModules() []string {
	return []string{
		"github.com/VirusTotal/yara-x/go", "github.com/pelletier/go-toml/v2", "github.com/tree-sitter/go-tree-sitter", "github.com/tree-sitter/tree-sitter-python", "go.yaml.in/yaml/v3",
		"github.com/tree-sitter/tree-sitter-javascript", "github.com/tree-sitter/tree-sitter-typescript",
	}
}

func Inspect(path string) (Report, error) {
	f, e := os.Open(path) //nolint:gosec // G304: path is the release binary explicitly selected by the caller.
	if e != nil {
		return newReport(), errors.New("cannot open release binary")
	}
	defer func() { _ = f.Close() }()

	return inspect(f)
}

func AllowedSystemLibrary(goos, lib string) bool {
	if goos == "windows" {
		switch strings.ToLower(lib) {
		// Exact system API-set contracts imported by the pinned UCRT64 build.
		case "api-ms-win-core-synch-l1-2-0.dll", "api-ms-win-crt-convert-l1-1-0.dll",
			"api-ms-win-crt-environment-l1-1-0.dll", "api-ms-win-crt-filesystem-l1-1-0.dll",
			"api-ms-win-crt-heap-l1-1-0.dll", "api-ms-win-crt-locale-l1-1-0.dll",
			"api-ms-win-crt-math-l1-1-0.dll", "api-ms-win-crt-private-l1-1-0.dll",
			"api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll",
			"api-ms-win-crt-string-l1-1-0.dll":
			return true
		case "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "crypt32.dll", "cryptbase.dll", "dbghelp.dll", "dnsapi.dll",
			"iphlpapi.dll", "kernel32.dll", "msvcrt.dll", "netapi32.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
			"powrprof.dll", "psapi.dll", "rpcrt4.dll", "secur32.dll", "shell32.dll", "synchronization.dll",
			"ucrtbase.dll", "user32.dll", "userenv.dll", "version.dll", "winmm.dll", "ws2_32.dll":
			return true
		}

		return false
	}

	if goos == "linux" {
		switch lib {
		case "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", "libresolv.so.2", "libgcc_s.so.1", "libutil.so.1", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "libc.musl-x86_64.so.1", "libc.musl-aarch64.so.1":
			return true
		}

		return false
	}

	if goos == "darwin" {
		switch lib {
		case "/usr/lib/libSystem.B.dylib", "/usr/lib/libresolv.9.dylib", "/usr/lib/libc++.1.dylib", "/usr/lib/libiconv.2.dylib", "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation", "/System/Library/Frameworks/Security.framework/Versions/A/Security":
			return true
		}

		return false
	}

	return false
}

func ValidateBuildInfo(bi *debug.BuildInfo, goos, arch string) []string {
	issues := make([]string, 0)

	if bi == nil {
		return []string{"missing_build_info"}
	}

	settings := map[string]string{}
	for _, setting := range bi.Settings {
		settings[setting.Key] = setting.Value
	}

	issues = append(issues, buildSettingsIssues(settings, goos, arch)...)

	return append(issues, moduleProvenanceIssues(bi.Deps)...)
}

// Verify executes only the explicitly supplied, trusted scanner release, copied
// byte-for-byte into a fresh directory. It MUST NOT be used on a skill's executable.
// No PATH/HOME/PYTHONPATH/LD_LIBRARY_PATH/DYLD_LIBRARY_PATH is inherited.
func Verify(ctx context.Context, path string) (Report, error) {
	if ctx == nil {
		return newReport(), errors.New("nil verification context")
	}

	if err := ctx.Err(); err != nil {
		return newReport(), err
	}

	f, e := os.Open(path) //nolint:gosec // G304: path is the release binary explicitly selected by the caller.
	if e != nil {
		return newReport(), errors.New("cannot open release binary")
	}
	defer func() { _ = f.Close() }()

	r, e := inspect(f)
	if e != nil {
		return r, e
	}

	if len(r.Issues) > 0 {
		return r, nil
	}

	return verifyNative(ctx, f, r)
}

func newReport() Report {
	return Report{Schema: "1", Modules: []module{}, Libraries: []string{}, SearchPaths: []string{}, Issues: []string{}}
}

func buildSettingsIssues(settings map[string]string, goos, arch string) []string {
	issues := make([]string, 0)
	if settings["CGO_ENABLED"] != "1" {
		issues = append(issues, "cgo_not_enabled")
	}

	if settings["GOOS"] != goos || settings["GOARCH"] != arch {
		issues = append(issues, "build_target_mismatch")
	}

	if settings["-race"] == "true" {
		issues = append(issues, "race_instrumented_binary")
	}

	for _, tag := range strings.FieldsFunc(settings["-tags"], func(r rune) bool { return r == ',' || r == ' ' }) {
		if tag == "coreonly" || tag == "noyarax" || tag == "notreesitter" {
			issues = append(issues, "reduced_build_tag")
		}
	}

	return issues
}

func moduleProvenanceIssues(modules []*debug.Module) []string {
	issues := make([]string, 0)

	found := map[string]bool{}

	for _, m := range modules {
		if m == nil {
			continue
		}

		if m.Replace != nil {
			issues = append(issues, "module_replacement:"+m.Path)
		}

		if moduleHasDigest(m) {
			found[m.Path] = true
		}
	}

	for _, p := range RequiredModules() {
		if !found[p] {
			issues = append(issues, "missing_module_provenance:"+p)
		}
	}

	return issues
}

func verifyNative(ctx context.Context, f *os.File, r Report) (Report, error) {
	if r.OS != runtime.GOOS || r.Arch != runtime.GOARCH {
		r.Issues = append(r.Issues, "native_execution_required")
		return r, nil
	}

	dir, e := os.MkdirTemp("", "scout-releasecheck-")
	if e != nil {
		return r, e
	}
	defer func() { _ = os.RemoveAll(dir) }()

	for _, sub := range []string{"home", "tmp", "empty"} {
		if e = os.Mkdir(filepath.Join(dir, sub), 0o700); e != nil {
			return r, e
		}
	}

	bin, e := copyRelease(f, r, dir)
	if e != nil {
		return r, e
	}

	return runSelftest(ctx, bin, dir, r)
}

func copyRelease(f *os.File, r Report, dir string) (string, error) {
	bin := filepath.Join(dir, "scout")
	if r.OS == "windows" {
		bin += ".exe"
	}

	dst, e := os.OpenFile(bin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700) //nolint:gosec // G302: the private copy must be executable for the requested native selftest.
	if e != nil {
		return "", e
	}

	h := sha256.New()
	_, ce := io.Copy(io.MultiWriter(dst, h), io.NewSectionReader(f, 0, r.Size))

	cl := dst.Close()
	if ce != nil || cl != nil {
		return "", errors.New("cannot copy release binary")
	}

	if hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return "", errors.New("release changed during verification")
	}

	return bin, nil
}

func runSelftest(ctx context.Context, bin, dir string, r Report) (Report, error) {
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(call, bin, "selftest", "--format", "json", "--timeout", "90s")
	cmd.Dir = dir

	cmd.Env = []string{"PATH=" + filepath.Join(dir, "empty"), "HOME=" + filepath.Join(dir, "home"), "TMPDIR=" + filepath.Join(dir, "tmp"), "LANG=C", "LC_ALL=C"}
	if r.OS == "windows" {
		// Windows needs its system directory even with an otherwise private environment.
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"), "WINDIR="+os.Getenv("SystemRoot"),
			"USERPROFILE="+filepath.Join(dir, "home"), "TEMP="+filepath.Join(dir, "tmp"), "TMP="+filepath.Join(dir, "tmp"))
	}

	cmd.WaitDelay = 2 * time.Second
	out := &boundedBuffer{limit: 128 << 10}
	stderr := &boundedBuffer{limit: 16 << 10}
	cmd.Stdout = out
	cmd.Stderr = stderr
	runErr := cmd.Run()

	return acceptSelftest(r, out, stderr, runErr), nil
}

func acceptSelftest(r Report, out, stderr *boundedBuffer, runErr error) Report {
	if out.overflow || stderr.overflow {
		r.Issues = append(r.Issues, "selftest_output_limit")
		return r
	}

	if runErr != nil {
		r.Issues = append(r.Issues, "selftest_process_failed")
	}

	test, issue := decodeSelftest(out.Bytes())
	if issue != "" {
		r.Issues = append(r.Issues, issue)
		return r
	}

	r.Selftest = &test
	if !test.Passed || nativecontract.Validate(test) != nil || test.Platform != r.OS+"/"+r.Arch {
		r.Issues = append(r.Issues, "selftest_not_complete")
	}

	if stderr.Len() > 0 {
		r.Issues = append(r.Issues, "unexpected_stderr")
	}

	r.Passed = len(r.Issues) == 0

	return r
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.overflow = true
		return 0, errors.New("release selftest output limit")
	}

	return b.Buffer.Write(p)
}

func inspect(f *os.File) (Report, error) {
	r := newReport()

	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > maxBinarySize {
		return r, errors.New("release binary is not a bounded regular file")
	}

	r.Size = st.Size()

	h := sha256.New()
	if _, e = io.Copy(h, io.NewSectionReader(f, 0, st.Size())); e != nil {
		return r, errors.New("cannot hash release binary")
	}

	r.SHA256 = hex.EncodeToString(h.Sum(nil))

	var magic [4]byte
	if _, e = f.ReadAt(magic[:], 0); e != nil {
		return r, e
	}

	e = inspectFormat(f, &r, magic)
	if e != nil {
		return r, e
	}

	return inspectBuildInfo(f, r)
}

func inspectELF(f *os.File, r *Report) error {
	ef, e := elf.NewFile(f)
	if e != nil {
		return errors.New("invalid ELF binary")
	}

	r.Format, r.OS = "elf", "linux"

	switch ef.Machine {
	case elf.EM_X86_64:
		r.Arch = "amd64"
	case elf.EM_AARCH64:
		r.Arch = "arm64"
	default:
		r.Issues = append(r.Issues, "unsupported_architecture")
	}

	if ef.Type != elf.ET_EXEC && ef.Type != elf.ET_DYN {
		r.Issues = append(r.Issues, "not_executable")
	}

	r.Libraries, r.SearchPaths, e = elfImports(ef)
	if e != nil {
		return e
	}

	return inspectELFInterpreter(ef, r)
}

func inspectELFInterpreter(ef *elf.File, r *Report) error {
	// Nonstandard dynamic loaders are dependencies too; do not trust DT_NEEDED alone.
	for _, p := range ef.Progs {
		if p.Type == elf.PT_INTERP {
			if p.Filesz > 4096 {
				return errors.New("invalid ELF interpreter")
			}

			b, e := io.ReadAll(p.Open())
			if e != nil {
				return e
			}

			s := strings.TrimSuffix(string(b), "\x00")
			if !allowedLoader(r.Arch, s) {
				r.Issues = append(r.Issues, "non_system_interpreter")
			}
		}
	}

	return nil
}

func inspectMachO(f *os.File, r *Report) error {
	mf, e := macho.NewFile(f)
	if e != nil {
		return errors.New("invalid Mach-O binary")
	}

	r.Format, r.OS = "macho", "darwin"

	switch mf.Cpu {
	case macho.CpuAmd64:
		r.Arch = "amd64"
	case macho.CpuArm64:
		r.Arch = "arm64"
	default:
		r.Issues = append(r.Issues, "unsupported_architecture")
	}

	if mf.Type != macho.TypeExec {
		r.Issues = append(r.Issues, "not_executable")
	}

	r.Libraries, e = mf.ImportedLibraries()
	if e != nil {
		return errors.New("invalid Mach-O import table")
	}

	for _, load := range mf.Loads {
		if rp, ok := load.(*macho.Rpath); ok {
			r.SearchPaths = append(r.SearchPaths, rp.Path)
		}
	}

	return nil
}

func inspectBuildInfo(f *os.File, r Report) (Report, error) {
	sort.Strings(r.Libraries)
	sort.Strings(r.SearchPaths)

	for _, lib := range r.Libraries {
		if !AllowedSystemLibrary(r.OS, lib) {
			r.Issues = append(r.Issues, "non_system_dynamic_library:"+lib)
		}
	}

	if len(r.SearchPaths) > 0 {
		r.Issues = append(r.Issues, "runtime_search_path_present")
	}

	bi, e := buildinfo.Read(f)
	if e != nil {
		return r, errors.New("missing Go build metadata")
	}

	r.GoVersion = bi.GoVersion

	r.Issues = append(r.Issues, ValidateBuildInfo(bi, r.OS, r.Arch)...)
	for _, m := range bi.Deps {
		r.Modules = append(r.Modules, module{Path: m.Path, Version: m.Version, Sum: m.Sum})
	}

	sort.Slice(r.Modules, func(i, j int) bool { return r.Modules[i].Path < r.Modules[j].Path })
	// Inspection alone never means a passed release: actual selftest is required.
	return r, nil
}

func allowedLoader(arch, s string) bool { return slices.Contains(systemLoaders[arch], s) }

func moduleHasDigest(module *debug.Module) bool {
	digest, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(module.Sum, "h1:"))
	return module.Version != "" && strings.HasPrefix(module.Sum, "h1:") && err == nil && len(digest) == 32
}

func inspectFormat(f *os.File, r *Report, magic [4]byte) error {
	if magic[0] == 'M' && magic[1] == 'Z' {
		return inspectPE(f, r)
	}

	switch magic {
	case [4]byte{0x7f, 'E', 'L', 'F'}:
		return inspectELF(f, r)
	case [4]byte{0xcf, 0xfa, 0xed, 0xfe}, [4]byte{0xfe, 0xed, 0xfa, 0xcf}:
		return inspectMachO(f, r)
	default:
		return errors.New("unsupported release format (only thin Linux/macOS and Windows PE binaries)")
	}
}

func decodeSelftest(raw []byte) (nativecontract.Report, string) {
	var test nativecontract.Report

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if e := dec.Decode(&test); e != nil {
		return test, "invalid_selftest_report"
	}

	var extra any
	if dec.Decode(&extra) != io.EOF {
		return test, "trailing_selftest_output"
	}

	return test, ""
}

func elfImports(ef *elf.File) ([]string, []string, error) {
	var searchPaths []string

	libraries, e := ef.ImportedLibraries()
	if e != nil {
		return nil, nil, errors.New("invalid ELF import table")
	}

	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		v, e := ef.DynString(tag)
		if e != nil {
			return nil, nil, errors.New("invalid ELF search paths")
		}

		searchPaths = append(searchPaths, v...)
	}

	return libraries, searchPaths, nil
}
