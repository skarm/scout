package maintenance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const sandboxExecutable = "/usr/bin/sandbox-exec"

type processResult struct {
	Stdout, Stderr []byte
	Code           int
	Seconds        float64
}
type sourceInventory struct {
	Commit    string
	FileCount int `json:"file_count"`
	Files     []struct {
		Path, SHA256 string
		Bytes        int
	}
}
type externalRuntime struct {
	Skillspector  string            `json:"skillspector"`
	Python        string            `json:"python"`
	Yara          string            `json:"yara"`
	VerifiedFiles []string          `json:"verified_installed_source_files"`
	Packages      map[string]string `json:"packages"`
}

type inventoryFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type upstreamSuiteSession struct {
	root, upstream, python, output, source, profile string
	runtime                                         externalRuntime
	env                                             []string
}

type inventoryCollector struct {
	root  string
	files []inventoryFile
}

func requireSandbox() error {
	if runtime.GOOS != "darwin" {
		return errors.New("external upstream execution requires macOS sandbox-exec")
	}

	info, err := os.Stat(sandboxExecutable)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("sandbox-exec is unavailable")
	}

	return nil
}

func verifyUpstream(root, upstream string) (sourceInventory, error) {
	var inventory sourceInventory
	if err := readJSON(filepath.Join(root, "testdata/provenance/upstream-inventory.json"), &inventory); err != nil {
		return inventory, err
	}

	if inventory.Commit != upstreamCommit || inventory.FileCount != len(inventory.Files) {
		return inventory, errors.New("unexpected source inventory")
	}

	for _, item := range inventory.Files {
		path, err := safeJoin(upstream, item.Path)
		if err != nil {
			return inventory, err
		}

		sha, err := fileDigest(path)
		if err != nil {
			return inventory, err
		}

		if sha != item.SHA256 {
			return inventory, fmt.Errorf("upstream source differs: %s", item.Path)
		}
	}

	return inventory, nil
}

func cleanEnvironment(executable, home, tmp string) []string {
	return []string{"PATH=" + filepath.Dir(executable) + ":/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + tmp, "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8", "NO_COLOR=1", "LANGSMITH_TRACING=false", "LANGCHAIN_TRACING_V2=false", "PYTHONDONTWRITEBYTECODE=1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1"}
}

func runSandboxed(ctx context.Context, profile, dir string, env []string, args ...string) (processResult, error) {
	call, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()

	cmd := exec.CommandContext(call, sandboxExecutable, append([]string{"-p", profile}, args...)...) //nolint:gosec // G204: trusted caller-selected executables run under the mandatory OS network policy.
	cmd.Dir, cmd.Env = dir, env

	var out, errout bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &errout
	started := time.Now()
	err := cmd.Run()
	result := processResult{Stdout: out.Bytes(), Stderr: errout.Bytes(), Seconds: time.Since(started).Seconds()}

	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return result, err
		}

		result.Code = exit.ExitCode()
	}

	if call.Err() != nil {
		return result, call.Err()
	}

	return result, nil
}

func networkProfile(output string, loopback bool) string {
	profile := "(version 1)(allow default)(deny network*)"
	if !loopback {
		return profile
	}

	owned := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(output)

	return profile + `(allow network-bind (local ip "localhost:*"))(allow network-inbound (local ip "localhost:*"))(allow network-outbound (remote ip "localhost:*"))(allow network* (local unix-socket (subpath "` + owned + `")) (remote unix-socket (subpath "` + owned + `")))`
}

func checkNetworkDenial(ctx context.Context, profile, dir string, env []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}

	result, err := runSandboxed(ctx, profile, dir, env, executable, "network-denial-probe")
	if err != nil {
		return err
	}

	if result.Code != 0 {
		return errors.New("OS network denial was not verified")
	}

	return nil
}

func networkDenialProbe(ctx context.Context) error {
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(call, "tcp", "1.1.1.1:443")
	if conn != nil {
		_ = conn.Close()
	}

	if !errors.Is(err, os.ErrPermission) {
		return errors.New("public network connection was not denied by the OS")
	}

	return nil
}

func verifyInstalledRuntime(ctx context.Context, python, upstream string) (externalRuntime, error) {
	result, err := inspectInstalledRuntime(python, upstream)
	if err != nil {
		return result, err
	}

	version, err := runSandboxed(ctx, networkProfile("", false), upstream, cleanEnvironment(python, os.TempDir(), os.TempDir()), python, "--version")
	if err != nil {
		return result, err
	}

	if version.Code != 0 {
		return result, errors.New("upstream interpreter version check failed")
	}

	result.Python = strings.TrimSpace(strings.TrimPrefix(string(version.Stdout), "Python "))

	return result, nil
}

func inspectInstalledRuntime(python, upstream string) (externalRuntime, error) {
	result := externalRuntime{Packages: map[string]string{}, VerifiedFiles: []string{}}
	// Preserve the venv executable symlink: resolving it changes Python's environment.
	venv := filepath.Dir(filepath.Dir(python))

	sites, err := filepath.Glob(filepath.Join(venv, "lib", "python*", "site-packages"))
	if err != nil {
		return result, err
	}

	if len(sites) != 1 {
		return result, errors.New("exactly one venv site-packages directory is required")
	}

	sourceFiles, err := installedSourceFiles(sites[0], upstream)
	if err != nil {
		return result, err
	}

	for _, f := range sourceFiles {
		result.VerifiedFiles = append(result.VerifiedFiles, f.Path)
	}

	result.Packages, err = installedPackages(sites[0])
	if err != nil {
		return result, err
	}

	result.Skillspector = result.Packages["skillspector"]

	result.Yara = result.Packages["yara-python"]
	if result.Skillspector != upstreamVersion || result.Yara == "" {
		return result, errors.New("pinned upstream runtime packages unavailable")
	}

	return result, nil
}

func metadataField(content, name string) string {
	for line := range strings.SplitSeq(content, "\n") {
		if value, ok := strings.CutPrefix(line, name+": "); ok {
			return value
		}
	}

	return ""
}

func treeInventory(root string) ([]inventoryFile, error) {
	out := make([]inventoryFile, 0)
	visitor := inventoryCollector{root: root, files: out}
	err := filepath.WalkDir(root, visitor.visit)
	out = visitor.files

	slices.SortFunc(out, func(a, b inventoryFile) int { return strings.Compare(a.Path, b.Path) })

	return out, err
}

func ignoredCopyEntry(name string) bool {
	return slices.Contains([]string{"__pycache__", ".pytest_cache", "dist"}, name) || strings.HasSuffix(name, ".egg-info")
}

func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() && ignoredCopyEntry(entry.Name()) {
			return filepath.SkipDir
		}

		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}

		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}

		if !entry.Type().IsRegular() {
			return errors.New("nonregular source entry")
		}

		return copyFile(path, destination)
	})
}

func copyFile(source, target string) error {
	data, err := os.ReadFile(source) //nolint:gosec // G304: caller-selected pinned source file, never executed here.
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}

	return os.WriteFile(target, data, 0o600) //nolint:gosec // G703: destination comes from safeJoin or a WalkDir-relative path in the fresh output tree.
}

func runUpstreamSuite(ctx context.Context, o options, w io.Writer) error {
	session, err := selectUpstreamSuite(o)
	if err != nil {
		return err
	}

	return session.verifyAndRun(ctx, w)
}

func selectUpstreamSuite(o options) (*upstreamSuiteSession, error) {
	if err := o.require("upstream", "python", "output"); err != nil {
		return nil, err
	}

	if err := requireSandbox(); err != nil {
		return nil, err
	}

	session := &upstreamSuiteSession{root: o.root}
	for _, field := range []struct {
		name        string
		destination *string
	}{{name: "upstream", destination: &session.upstream}, {name: "python", destination: &session.python}, {
		name:        "output",
		destination: &session.output,
	}} {
		value, err := filepath.Abs(o.get(field.name))
		if err != nil {
			return nil, err
		}

		*field.destination = value
	}

	return session, nil
}

func (s *upstreamSuiteSession) verifyAndRun(ctx context.Context, w io.Writer) error {
	if err := s.verifyRuntime(ctx); err != nil {
		return err
	}

	if err := s.prepareFilesystem(ctx); err != nil {
		return err
	}

	return s.execute(ctx, w)
}

func (s *upstreamSuiteSession) verifyRuntime(ctx context.Context) error {
	if _, err := verifyUpstream(s.root, s.upstream); err != nil {
		return err
	}

	installed, err := verifyInstalledRuntime(ctx, s.python, s.upstream)
	s.runtime = installed

	return err
}

func (s *upstreamSuiteSession) prepareFilesystem(ctx context.Context) error {
	if err := newOutput(s.output); err != nil {
		return err
	}

	for _, name := range []string{"home", "tmp"} {
		if err := os.Mkdir(filepath.Join(s.output, name), 0o700); err != nil {
			return err
		}
	}

	s.source = filepath.Join(s.output, "upstream")
	if err := copyTree(s.upstream, s.source); err != nil {
		return err
	}

	s.env = append(cleanEnvironment(s.python, filepath.Join(s.output, "home"), filepath.Join(s.output, "tmp")), "PYTHONPATH="+s.source)
	s.profile = networkProfile(s.output, true)

	return checkNetworkDenial(ctx, s.profile, s.output, s.env)
}

func (s *upstreamSuiteSession) command() []string {
	return []string{"-p", s.profile, s.python, "-m", "pytest", "-p", "pytest_asyncio.plugin", "-p", "pytest_cov.plugin", "-o", "addopts=", "-o", "cache_dir=" + filepath.Join(s.output, "pytest-cache"), "--basetemp=" + filepath.Join(s.output, "pytest-tmp"), "--junitxml=" + filepath.Join(s.output, "junit.xml"), "-q", "--tb=short"}
}

func (s *upstreamSuiteSession) writeMetadata(args []string) error {
	if err := writeJSON(filepath.Join(s.output, "runtime.json"), s.runtime); err != nil {
		return err
	}

	sha, err := fileDigest(filepath.Join(s.root, "testdata/provenance/upstream-inventory.json"))
	if err != nil {
		return err
	}

	return writeJSON(filepath.Join(s.output, "command.json"), object{
		"command":          append([]string{sandboxExecutable}, args...),
		"env":              s.env,
		"inventory_sha256": sha,
		"capture":          "saved captures are processed separately; no runtime monitoring plugin is installed",
	})
}

func (s *upstreamSuiteSession) execute(ctx context.Context, w io.Writer) error {
	args := s.command()
	if err := s.writeMetadata(args); err != nil {
		return err
	}

	code, err := streamUpstreamSuite(ctx, s.source, s.output, s.env, args)
	if err != nil {
		return err
	}

	return s.publishExit(code, w)
}

func (s *upstreamSuiteSession) publishExit(code int, w io.Writer) error {
	if err := writeJSON(filepath.Join(s.output, "exit.json"), object{"exit_code": code}); err != nil {
		return err
	}

	if err := printJSON(w, object{"exit_code": code, "junit": filepath.Join(s.output, "junit.xml")}); err != nil {
		return err
	}

	if code != 0 {
		return errors.New("upstream pytest failed; see retained logs")
	}

	return nil
}

func streamUpstreamSuite(ctx context.Context, source, output string, env, args []string) (int, error) {
	out, err := os.OpenFile(filepath.Join(output, "stdout.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: fixed log filename in the fresh caller-selected run directory.
	if err != nil {
		return 0, err
	}
	defer func() { _ = out.Close() }()

	errout, err := os.OpenFile(filepath.Join(output, "stderr.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: fixed log filename in the fresh caller-selected run directory.
	if err != nil {
		return 0, err
	}

	defer func() { _ = errout.Close() }()

	cmd := exec.CommandContext(ctx, sandboxExecutable, args...) //nolint:gosec // G204: explicitly selected verified upstream pytest runtime under sandbox-exec.
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = source, env, out, errout

	err = cmd.Run()
	if err == nil {
		return 0, nil
	}

	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), nil
	}

	return 0, err
}

func installedPackages(site string) (map[string]string, error) {
	packages := map[string]string{}

	metadata, err := filepath.Glob(filepath.Join(site, "*.dist-info", "METADATA"))
	if err != nil {
		return nil, err
	}

	for _, path := range metadata {
		data, err := os.ReadFile(path) //nolint:gosec // G304: venv distribution metadata under the explicitly selected interpreter installation.
		if err != nil {
			return nil, err
		}

		name, version := metadataField(string(data), "Name"), metadataField(string(data), "Version")
		if name != "" {
			packages[name] = version
		}
	}

	return packages, nil
}

func (c *inventoryCollector) visit(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		return err
	}

	if entry.IsDir() {
		if ignoredCopyEntry(entry.Name()) {
			return filepath.SkipDir
		}

		return nil
	}

	if entry.Type()&os.ModeSymlink != 0 {
		return errors.New("symlink in fixed regression corpus")
	}

	if !entry.Type().IsRegular() {
		return errors.New("nonregular corpus file")
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: WalkDir enumerated this regular file inside the selected corpus tree.
	if err != nil {
		return err
	}

	relative, err := filepath.Rel(c.root, path)
	if err != nil {
		return err
	}

	c.files = append(c.files, inventoryFile{Path: filepath.ToSlash(relative), SHA256: digest(data), Bytes: len(data)})

	return nil
}

func installedSourceFiles(site, upstream string) ([]inventoryFile, error) {
	installed := filepath.Join(site, "skillspector")
	source := filepath.Join(upstream, "src", "skillspector")

	sourceFiles, err := treeInventory(source)
	if err != nil {
		return nil, err
	}

	installedFiles, err := treeInventory(installed)
	if err != nil {
		return nil, err
	}

	if !slices.Equal(sourceFiles, installedFiles) {
		return nil, errors.New("installed upstream runtime differs from pinned source")
	}

	return sourceFiles, nil
}
