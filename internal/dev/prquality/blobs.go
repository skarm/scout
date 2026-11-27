package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

type blobReader func(string) ([]byte, error)

// Use one streaming Git process. Fetch and parse each blob before asking for
// the next one, so large diffs do not accumulate every object's contents.
func readGitBlobs(ctx context.Context, visit func(blobReader) error) error {
	cmd := exec.CommandContext(ctx, "git", "cat-file", "--batch")

	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return err
	}

	if err := cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()

		return fmt.Errorf("git cat-file --batch: %w", err)
	}

	reader := bufio.NewReader(output)
	readErr := visit(func(id string) ([]byte, error) {
		if _, err := io.WriteString(input, id+"\n"); err != nil {
			return nil, fmt.Errorf("request Git blob: %w", err)
		}

		return readBatchBlob(reader, id)
	})

	_ = input.Close()
	if readErr != nil {
		// A failed consumer may have left a large response in the pipe.
		_ = output.Close()
	}

	waitErr := cmd.Wait()

	if readErr != nil {
		return readErr
	}

	if waitErr != nil {
		return fmt.Errorf("git cat-file --batch: %w", waitErr)
	}

	return nil
}

func readBatchBlob(reader *bufio.Reader, id string) ([]byte, error) {
	header, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("read Git blob header: %w", err)
	}

	fields := strings.Fields(string(header))
	if len(fields) != 3 || fields[0] != id || fields[1] != "blob" {
		return nil, fmt.Errorf("missing or invalid Git blob %s", id)
	}

	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 0 {
		return nil, errors.New("invalid Git blob size")
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("read Git blob contents: %w", err)
	}

	separator, err := reader.ReadByte()
	if err != nil || separator != '\n' {
		return nil, errors.New("invalid Git blob terminator")
	}

	return data, nil
}
