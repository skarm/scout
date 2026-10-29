package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type target struct {
	name, label, binary, extension string
}

type entry struct {
	path, name string
	info       fs.FileInfo
}

type candidate struct {
	target target
	files  []entry
}

func targets() []target {
	return []target{
		{name: "darwin-arm64", label: "macos-arm64", binary: "scout", extension: ".tar.gz"},
		{name: "linux-amd64", label: "linux-amd64", binary: "scout", extension: ".tar.gz"},
		{name: "windows-amd64", label: "windows-amd64", binary: "scout.exe", extension: ".zip"},
	}
}

func packageRelease(version, candidates, output string) (err error) {
	if !validVersion(version) {
		return errors.New("invalid release version")
	}

	checked := make([]candidate, 0, len(targets()))
	for _, platform := range targets() {
		files, err := candidateFiles(filepath.Join(candidates, "native-candidate-"+platform.name), platform.binary)
		if err != nil {
			return fmt.Errorf("%s: %w", platform.name, err)
		}

		checked = append(checked, candidate{target: platform, files: files})
	}

	if err = os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}

	// Refuse existing output and remove only this invocation's partial output.
	if err = os.Mkdir(output, 0o700); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(output))
		}
	}()

	var checksums strings.Builder

	for _, item := range checked {
		root := "scout-" + version + "-" + item.target.label
		name := root + item.target.extension
		path := filepath.Join(output, name)

		if item.target.extension == ".zip" {
			err = writeZIP(path, item.files)
		} else {
			err = writeTar(path, item.files)
		}

		if err != nil {
			return err
		}

		sum, err := digest(path)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintf(&checksums, "%s  %s\n", sum, name)
	}

	return os.WriteFile(filepath.Join(output, "SHA256SUMS"), []byte(checksums.String()), 0o600)
}

func validVersion(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}

	for index, char := range []byte(value) {
		alnum := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
		if !alnum && (index == 0 || char != '.' && char != '+' && char != '-') {
			return false
		}
	}

	return true
}

func candidateFiles(root, binary string) ([]entry, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() {
		return nil, errors.New("candidate root must be a directory")
	}

	files := make([]entry, 0, 1)

	for _, name := range []string{binary, "scout.sha256"} {
		path := filepath.Join(root, name)

		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("missing or nonregular candidate file: %s", name)
		}

		if name == binary {
			files = append(files, entry{path: path, name: name, info: info})
		}
	}

	checksum, err := os.ReadFile(filepath.Join(root, "scout.sha256")) //nolint:gosec // G304: fixed checksum filename in the operator-selected build artifact.
	if err != nil {
		return nil, err
	}

	expected := strings.Fields(string(checksum))

	actual, err := digest(filepath.Join(root, binary))
	if err != nil {
		return nil, err
	}

	if len(expected) != 2 || expected[1] != binary || expected[0] != actual {
		return nil, errors.New("candidate checksum mismatch")
	}

	return files, nil
}

func digest(path string) (string, error) {
	file, err := os.Open(path) //nolint:gosec // G304: hashes an explicitly selected build artifact, never scanned input.
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }() // Read errors are checked; the input is never modified.

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeTar(path string, files []entry) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: creates a fixed archive name in this invocation's new output directory.
	if err != nil {
		return err
	}

	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)

	defer func() { err = errors.Join(err, archive.Close(), compressed.Close(), file.Close()) }()

	for _, item := range files {
		header, err := tar.FileInfoHeader(item.info, "")
		if err != nil {
			return err
		}

		header.Name = item.name
		// Artifact downloads reset executable bits. Restore them in the archive
		// without modifying the checked candidate's files.
		header.Mode = 0o755
		if err = archive.WriteHeader(header); err != nil {
			return err
		}

		if err = copyFile(archive, item.path); err != nil {
			return err
		}
	}

	return nil
}

func writeZIP(path string, files []entry) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: creates a fixed archive name in this invocation's new output directory.
	if err != nil {
		return err
	}

	archive := zip.NewWriter(file)
	defer func() { err = errors.Join(err, archive.Close(), file.Close()) }()

	for _, item := range files {
		header, err := zip.FileInfoHeader(item.info)
		if err != nil {
			return err
		}

		header.Name = item.name
		header.SetMode(0o755)
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if err = copyFile(writer, item.path); err != nil {
			return err
		}
	}

	return nil
}

func copyFile(writer io.Writer, path string) error {
	file, err := os.Open(path) //nolint:gosec // G304: copies an enumerated regular file from a verified build candidate.
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)

	return errors.Join(err, file.Close())
}
