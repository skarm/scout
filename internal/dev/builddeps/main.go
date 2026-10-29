// Command builddeps prepares a pinned prebuilt YARA-X C API, then runs a build command.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

const version = "1.22.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:])

	stop()

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "native dependencies:", err)

		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if _, err := exec.LookPath("pkg-config"); err != nil {
		return errors.New("pkg-config is required; install it with your system package manager")
	}

	env := os.Environ()

	flags, err := libraryFlags(ctx, env)
	// Default builds always use the pinned artifact. An explicit pkg-config path
	// permits a developer-provided installation of the same C API version.
	if os.Getenv("PKG_CONFIG_PATH") == "" || err != nil {
		base := os.Getenv("SCOUT_NATIVE_CACHE")
		if base == "" {
			base, err = os.UserCacheDir()
			if err != nil {
				return err
			}

			base = filepath.Join(base, "scout", "native")
		}

		asset, ok := pinnedBottles()[runtime.GOOS+"/"+runtime.GOARCH]
		if !ok {
			return fmt.Errorf("no pinned prebuilt C API for %s/%s; provide YARA-X %s via PKG_CONFIG_PATH", runtime.GOOS, runtime.GOARCH, version)
		}

		prefix := filepath.Join(base, "yara-x-"+version+"-"+asset.sha256)
		if err := ensureBottle(ctx, prefix, asset); err != nil {
			return err
		}

		pc := filepath.Join(prefix, "lib", "pkgconfig")
		if previous := os.Getenv("PKG_CONFIG_PATH"); previous != "" {
			pc += string(os.PathListSeparator) + previous
		}

		env = withEnv(env, "PKG_CONFIG_PATH", pc)

		flags, err = libraryFlags(ctx, env)
		if err != nil {
			return fmt.Errorf("downloaded C API is unusable: %w", err)
		}
	}

	if len(args) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "YARA-X", version, "C API ready")
		return nil
	}
	// Explicit linker flags also separate CGO cache entries for different installations.
	if extra := os.Getenv("CGO_LDFLAGS"); extra != "" {
		flags += " " + extra
	}

	env = withEnv(env, "CGO_LDFLAGS", flags)
	env = withEnv(env, "CGO_ENABLED", "1")
	//nolint:gosec // G204: forwards the developer-selected build command, never scanned input.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr

	return cmd.Run()
}

func libraryFlags(ctx context.Context, env []string) (string, error) {
	query := func(args ...string) (string, error) {
		//nolint:gosec // G204: fixed executable and queries constructed by this build helper.
		cmd := exec.CommandContext(ctx, "pkg-config", args...)
		cmd.Env = env
		out, err := cmd.Output()

		return strings.TrimSpace(string(out)), err
	}
	if _, err := query("--exact-version="+version, "yara_x_capi"); err != nil {
		return "", fmt.Errorf("YARA-X %s C API was not found", version)
	}

	for _, file := range []struct{ variable, name string }{{variable: "libdir", name: "libyara_x_capi.a"}, {
		variable: "includedir",
		name:     "yara_x.h",
	}} {
		dir, err := query("--variable="+file.variable, "yara_x_capi")
		if err != nil {
			return "", err
		}

		if info, err := os.Stat(filepath.Join(dir, file.name)); err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("native C API installation is missing %s", file.name)
		}
	}

	return query("--static", "--libs", "yara_x_capi")
}

func withEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, key+"=") {
			out = append(out, entry)
		}
	}

	return append(out, key+"="+value)
}
