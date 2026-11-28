package fetch

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/artifactpath"
	"github.com/skarm/scout/report"
)

const (
	codeGITInvalidBlob              = "git_invalid_blob"
	codeGITInvalidTree              = "git_invalid_tree"
	codeGITRevisionNotCommit        = "git_revision_not_commit"
	codeGITTreeEntryLimit           = "git_tree_entry_limit"
	codeGITTreeUnavailableOrLimited = "git_tree_unavailable_or_limited"
	codeGITUnsafeTreePath           = "git_unsafe_tree_path"
	codeGITUnsupportedTreeEntry     = "git_unsupported_tree_entry"
	codeGitBlobStreamFailed         = "git_blob_stream_failed"
)

const (
	maxGitTreeBytes = 4 << 20
	maxGitFiles     = 16384
)

type gitFile struct {
	path, id string
	mode     fs.FileMode
}

type gitBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *gitBuffer) Write(data []byte) (int, error) {
	if int64(len(data)) > b.limit-int64(b.buffer.Len()) {
		return 0, fail(codeByteLimit)
	}

	return b.buffer.Write(data)
}

func (r gitWorkspace) archive(ctx context.Context, revision string, limit int64) ([]byte, error) {
	// Verify the pinned object is itself a commit, without peeling a tag.
	typeOutput := &gitBuffer{limit: 16}
	command := r.command(ctx, "cat-file", "-t", revision)

	command.Stdout = typeOutput
	if err := command.Run(); err != nil || typeOutput.buffer.String() != "commit\n" {
		return nil, gitFailure(ctx, codeGITRevisionNotCommit)
	}

	listing := &gitBuffer{limit: min(limit, maxGitTreeBytes)}
	command = r.command(ctx, "ls-tree", "-r", "-z", "--full-tree", revision)

	command.Stdout = listing
	if err := command.Run(); err != nil {
		return nil, gitFailure(ctx, codeGITTreeUnavailableOrLimited)
	}

	files, err := parseGitTree(listing.buffer.String())
	if err != nil {
		return nil, err
	}

	// Unlike git archive, the captured tree includes files marked export-ignore
	// and does not perform export-subst, filters or working-tree conversions.
	output := &gitBuffer{limit: limit}

	archive := zip.NewWriter(output)
	if err := r.writeGitFiles(ctx, archive, files, limit); err != nil {
		return nil, err
	}

	if err := archive.Close(); err != nil {
		return nil, gitFailure(ctx, codeByteLimit)
	}

	return output.buffer.Bytes(), nil
}

func parseGitTree(listing string) ([]gitFile, error) {
	if listing == "" {
		return nil, nil
	}

	records, ok := strings.CutSuffix(listing, "\x00")
	if !ok {
		return nil, fail(codeGITInvalidTree)
	}

	names := artifactpath.Namespace{MaxNodes: maxGitFiles * 2}

	var files []gitFile
	for entry := range strings.SplitSeq(records, "\x00") {
		if len(files) == maxGitFiles {
			return nil, fail(codeGITTreeEntryLimit)
		}

		header, name, ok := strings.Cut(entry, "\t")

		fields := strings.Fields(header)
		if !ok || len(fields) != 3 || !isHex(fields[2], gitCommitHexBytes) {
			return nil, fail(codeGITInvalidTree)
		}

		mode := fs.FileMode(0o644)
		if fields[0] == "100755" {
			mode = 0o755
		}

		if fields[1] != "blob" || fields[0] != "100644" && fields[0] != "100755" {
			return nil, fail(codeGITUnsupportedTreeEntry)
		}

		if artifactpath.Validate(name, report.MaxArtifactPathBytes, report.MaxArtifactPathDepth) != nil || names.Add(name, false) != nil {
			return nil, fail(codeGITUnsafeTreePath)
		}

		files = append(files, gitFile{name, fields[2], mode})
	}

	return files, nil
}

func (r gitWorkspace) writeGitFiles(ctx context.Context, archive *zip.Writer, files []gitFile, limit int64) error {
	command := r.command(ctx, "cat-file", "--batch")

	input, err := command.StdinPipe()
	if err != nil {
		return fail(codeGitBlobStreamFailed)
	}

	defer func() { _ = input.Close() }()

	output, err := command.StdoutPipe()
	if err != nil {
		return fail(codeGitBlobStreamFailed)
	}
	defer func() { _ = output.Close() }()

	if err := command.Start(); err != nil {
		return gitFailure(ctx, codeGitBlobStreamFailed)
	}

	readErr := writeGitBlobStream(archive, files, input, bufio.NewReader(output), limit)

	_ = input.Close()
	if readErr != nil {
		_ = output.Close()
		_ = command.Process.Kill()
	}

	waitErr := command.Wait()

	if err := ctx.Err(); err != nil {
		return err
	}

	if readErr != nil {
		return readErr
	}

	if waitErr != nil {
		return gitFailure(ctx, codeGitBlobStreamFailed)
	}

	return nil
}

func writeGitBlobStream(archive *zip.Writer, files []gitFile, input io.Writer, output *bufio.Reader, limit int64) error {
	for _, file := range files {
		if _, err := io.WriteString(input, file.id+"\n"); err != nil {
			return fail(codeGitBlobStreamFailed)
		}

		size, err := readGitBlobHeader(output, file.id)
		if err != nil {
			return err
		}

		if size > limit {
			return fail(codeByteLimit)
		}

		limit -= size

		header := &zip.FileHeader{Name: file.path, Method: zip.Store}
		header.SetMode(file.mode)

		entry, writeErr := archive.CreateHeader(header)
		if writeErr != nil {
			return fail(codeByteLimit)
		}

		if _, err := io.CopyN(entry, output, size); err != nil {
			if typed, ok := errors.AsType[*Error](err); ok {
				return typed
			}

			return fail(codeGitBlobStreamFailed)
		}

		if next, err := output.ReadByte(); err != nil || next != '\n' {
			return fail(codeGitBlobStreamFailed)
		}
	}

	return nil
}

func readGitBlobHeader(output *bufio.Reader, id string) (int64, error) {
	header, err := output.ReadSlice('\n')

	fields := strings.Fields(string(header))
	if err != nil || len(fields) != 3 || fields[0] != id || fields[1] != "blob" {
		return 0, fail(codeGITInvalidBlob)
	}

	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return 0, fail(codeGITInvalidBlob)
	}

	return size, nil
}
