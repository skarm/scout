package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxArchive        = 512 << 20
	licenseFile       = "LICENSE"
	headerFile        = "include/yara_x.h"
	staticLibraryFile = "lib/libyara_x_capi.a"
	pkgConfigFile     = "lib/pkgconfig/yara_x_capi.pc"
	markerFile        = "bottle.sha256"
)

type bottle struct{ sha256 string }

// Homebrew's published YARA-X 1.22.0 bottles. These include the static C API,
// whereas upstream's macOS/Linux release archives contain the CLI only.
func pinnedBottles() map[string]bottle {
	return map[string]bottle{
		"darwin/arm64": {sha256: "840bc2e72baa7e1a02b79f50e4cac7e1604cfa738440bc026fcab8d430641018"}, // macOS 15+
		"linux/arm64":  {sha256: "21415882cf7f1d224af130f74c68fc3b60804203576218ef1143c50cc1477d22"},
		"linux/amd64":  {sha256: "8c1c3d279ceaabe545f000097f6d4c840e1f3cb81181c7f41737f43f76fe0ea1"},
	}
}

//nolint:gosec // G304,G703: paths belong to the developer-selected dependency cache, never scanned input.
func ensureBottle(ctx context.Context, prefix string, asset bottle) error {
	marker, err := os.ReadFile(filepath.Join(prefix, markerFile))
	if err == nil && strings.TrimSpace(string(marker)) == asset.sha256 {
		if err := libraryFiles(prefix); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(prefix), 0o700); err != nil {
		return err
	}

	stage, err := os.MkdirTemp(filepath.Dir(prefix), ".yara-x-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }() // Discard only this build's temporary staging directory.

	_, _ = fmt.Fprintln(os.Stderr, "Downloading pinned YARA-X", version, "C API (Homebrew bottle)")

	archive := filepath.Join(stage, "bottle.tar.gz")
	if err := downloadBottle(ctx, archive, asset); err != nil {
		return err
	}

	content := filepath.Join(stage, "install")
	if err := unpackBottle(archive, content, asset.sha256); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(content, markerFile), []byte(asset.sha256+"\n"), 0o600); err != nil {
		return err
	}

	if err := os.Rename(content, prefix); err != nil {
		// Another build may have populated the same content-addressed cache.
		if marker, readErr := os.ReadFile(filepath.Join(prefix, markerFile)); readErr == nil && strings.TrimSpace(string(marker)) == asset.sha256 {
			if checkErr := libraryFiles(prefix); checkErr == nil {
				return nil
			}
		}

		return repairCache(content, prefix)
	}

	return nil
}

//nolint:gosec // G304: destination is a newly allocated staging file in the dependency cache.
func downloadBottle(ctx context.Context, destination string, asset bottle) error {
	client := &http.Client{Timeout: 10 * time.Minute}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ghcr.io/token?service=ghcr.io&scope=repository:homebrew/core/yara-x:pull", nil)
	if err != nil {
		return err
	}

	authResponse, err := getResponse(client, request)
	if err != nil {
		return err
	}
	defer func() { _ = authResponse.Body.Close() }() // Read-only response; decoding and copy errors are checked.

	if authResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("homebrew registry authentication: HTTP %d", authResponse.StatusCode)
	}

	var auth struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(authResponse.Body, 1<<20)).Decode(&auth); err != nil || auth.Token == "" {
		return errors.New("invalid Homebrew registry token response")
	}

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://ghcr.io/v2/homebrew/core/yara-x/blobs/sha256:"+asset.sha256, nil)
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", "Bearer "+auth.Token)

	response, err := getResponse(client, request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }() // Read-only response; decoding and copy errors are checked.

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("homebrew bottle download: HTTP %d", response.StatusCode)
	}

	file, err := os.Create(destination)
	if err != nil {
		return err
	}

	n, copyErr := io.Copy(file, io.LimitReader(response.Body, maxArchive+1))
	closeErr := file.Close()

	if copyErr != nil {
		return copyErr
	}

	if n > maxArchive {
		return errors.New("native library download exceeds size limit")
	}

	return closeErr
}

func getResponse(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := client.Do(request)
	if err == nil || request.Context().Err() != nil {
		return response, err
	}
	// Retry a failed connection over IPv4 when the host advertises unreachable IPv6.
	dialer := &net.Dialer{Timeout: 30 * time.Second}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()

	fallback := &http.Client{Timeout: client.Timeout, Transport: transport}

	return fallback.Do(request.Clone(request.Context()))
}

//nolint:gosec // G703: checks fixed dependency filenames under the selected cache prefix.
func libraryFiles(prefix string) error {
	names := []string{headerFile, staticLibraryFile, pkgConfigFile, licenseFile}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(prefix, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("incomplete native library cache: %s", name)
		}
	}

	return nil
}

//nolint:gosec // G304: archive is a downloaded cache file; only fixed, authenticated member names are extracted.
func unpackBottle(archive, destination, expectedSHA string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }() // Read-only archive; read errors are checked.

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	if hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return errors.New("YARA-X bottle SHA-256 mismatch")
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }() // The gzip reader owns no underlying file.

	reader := tar.NewReader(io.LimitReader(gz, maxArchive+1))

	wanted := map[string]string{}
	for _, name := range []string{headerFile, staticLibraryFile, pkgConfigFile, licenseFile} {
		wanted["yara-x/"+version+"/"+name] = name
	}

	seen := map[string]bool{}

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		name, ok := wanted[header.Name]
		if !ok {
			continue
		}

		if seen[name] {
			return fmt.Errorf("duplicate native library archive entry: %s", name)
		}

		if err := extractMember(reader, header, filepath.Join(destination, name)); err != nil {
			return err
		}

		seen[name] = true
	}

	if err := libraryFiles(destination); err != nil {
		return err
	}

	pc := filepath.Join(destination, "lib", "pkgconfig", "yara_x_capi.pc")

	data, err := os.ReadFile(pc)
	if err != nil {
		return err
	}
	// Relocate only the package prefix; preserve the bottle's platform linker flags.
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "prefix=") {
		return errors.New("native library pkg-config prefix is missing")
	}

	lines[0] = "prefix=${pcfiledir}/../.."

	return os.WriteFile(pc, []byte(strings.Join(lines, "\n")), 0o600)
}

//nolint:gosec // G304: output path comes from the fixed member allowlist, never from archive filenames.
func extractMember(reader io.Reader, header *tar.Header, path string) error {
	if header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maxArchive/2 {
		return fmt.Errorf("invalid native library archive entry: %s", header.Name)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	_, copyErr := io.CopyN(out, reader, header.Size)
	closeErr := out.Close()

	if copyErr != nil {
		return copyErr
	}

	return closeErr
}

//nolint:gosec // G703: atomically replaces only fixed dependency filenames under the selected cache prefix.
func repairCache(content, prefix string) error {
	info, err := os.Lstat(prefix)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("native dependency cache is not a directory: %s", prefix)
	}

	for _, name := range []string{headerFile, staticLibraryFile, pkgConfigFile, licenseFile, markerFile} {
		target := filepath.Join(prefix, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}

		if err := os.Rename(filepath.Join(content, name), target); err != nil {
			return err
		}
	}

	return libraryFiles(prefix)
}
