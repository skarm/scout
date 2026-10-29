package provenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type listedPackage struct {
	Dir                                           string
	Module                                        *struct{ Dir string }
	GoFiles, CgoFiles, IgnoredGoFiles, EmbedFiles []string
}

// ScannerRuntimeFiles binds product evidence to both build variants and embeds.
// Developer command changes cannot invalidate the product dependency closure.
func ScannerRuntimeFiles(ctx context.Context, root string) ([]string, error) {
	files, err := runtimeFiles(ctx, root, ".", "./cmd/scout")
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, file := range files {
		seen[filepath.ToSlash(file)] = true
	}

	base, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return nil, err
	}

	if !seen[filepath.ToSlash(filepath.Join(base, "scan.go"))] || !seen[filepath.ToSlash(filepath.Join(base, "internal/analysis/engine/engine.go"))] {
		return nil, errors.New("scanner dependency inventory is incomplete")
	}

	return files, nil
}

// DeveloperRuntimeFiles contains the additional developer executable closure.
// Shared product dependencies are recorded once, by ScannerRuntimeFiles.
func DeveloperRuntimeFiles(ctx context.Context, root string) ([]string, error) {
	product, err := ScannerRuntimeFiles(ctx, root)
	if err != nil {
		return nil, err
	}

	developer, err := runtimeFiles(ctx, root, "./cmd/scout-dev")
	if err != nil {
		return nil, err
	}

	files := map[string]bool{}
	for _, file := range developer {
		files[file] = true
	}

	for _, file := range product {
		delete(files, file)
	}

	return sortedRuntimePaths(files), nil
}

func runtimeFiles(ctx context.Context, root string, patterns ...string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	files := map[string]bool{filepath.Join(root, "go.mod"): true, filepath.Join(root, "go.sum"): true}
	for _, tags := range []string{"coreonly", "static_link"} {
		listed, err := listRuntimeFiles(ctx, root, tags, patterns...)
		if err != nil {
			return nil, err
		}

		for _, name := range listed {
			files[name] = true
		}
	}

	return sortedRuntimePaths(files), nil
}

func listRuntimeFiles(ctx context.Context, root, tags string, patterns ...string) ([]string, error) {
	args := append([]string{"list", "-mod=readonly", "-deps", "-json", "-tags=" + tags}, patterns...)
	//nolint:gosec // G204: fixed go executable and trusted repository package patterns, never scanned target input.
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	cmd.Env = offlineEnvironment()

	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scanner dependency inventory: %w", err)
	}

	return decodeRuntimeFiles(root, data)
}

func decodeRuntimeFiles(root string, data []byte) ([]string, error) {
	var err error

	dec := json.NewDecoder(bytes.NewReader(data))
	out := make([]string, 0)

	for {
		var pkg listedPackage
		if err = dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		files, err := runtimePackageFiles(root, pkg)
		if err != nil {
			return nil, err
		}

		out = append(out, files...)
	}

	return out, nil
}

func offlineEnvironment() []string {
	env := make([]string, 0)

	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOPROXY=") && !strings.HasPrefix(v, "GOTOOLCHAIN=") && !strings.HasPrefix(v, "GOFLAGS=") {
			env = append(env, v)
		}
	}

	return append(env, "GOPROXY=off", "GOTOOLCHAIN=local")
}

func checkedRuntimePath(root, dir, name string) (string, error) {
	path := filepath.Join(dir, name)

	relative, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(relative) {
		return "", errors.New("scanner source outside project")
	}

	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("scanner source missing or nonregular")
	}

	return path, nil
}

func runtimePackageFiles(root string, pkg listedPackage) ([]string, error) {
	out := make([]string, 0)
	if pkg.Module == nil || pkg.Module.Dir != root {
		return out, nil
	}

	names := append(append(append(pkg.GoFiles, pkg.CgoFiles...), pkg.IgnoredGoFiles...), pkg.EmbedFiles...)
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		path, err := checkedRuntimePath(root, pkg.Dir, name)
		if err != nil {
			return nil, err
		}

		out = append(out, path)
	}

	return out, nil
}

func sortedRuntimePaths(files map[string]bool) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}

	slices.Sort(paths)

	return paths
}
