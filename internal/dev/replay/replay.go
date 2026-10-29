// Package replay scans saved captured inputs through the public offline API.
// Captured files are materialized in private temporary directories, never run.
package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/capture/archiveutil"
	"github.com/skarm/scout/internal/capture/ingest"
	"github.com/skarm/scout/internal/dev/replaywire"
	"github.com/skarm/scout/policy"
	"github.com/skarm/scout/report"
)

const errorReplayDeadline = "replay_deadline"

const (
	maxLineBytes         = 64 << 20
	maxInputBytes  int64 = 1 << 30
	maxRecords           = 65536
	maxFileRecords       = 100000
	maxWindowBytes       = 64 << 20
)

type Options struct {
	Workers int
	Timeout time.Duration
}
type Summary = replaywire.Summary

type capturedFile struct {
	name       string
	data       []byte
	executable bool
}
type record struct {
	id        string
	files     []capturedFile
	rejection string
}
type encodedFile struct {
	name, data string
	executable bool
}
type result = replaywire.Record

type stream struct {
	lines *bufio.Scanner
	line  int
}

type encodedRecord struct {
	id    string
	files []encodedFile
}

// Run retains input order with at most 2*Workers accepted records in flight.
// Ambiguous JSON/IDs stop the stream after publishing its valid prefix. A valid
// captured record refused by path/file/byte limits receives an explicit row.
func Run(ctx context.Context, scanner *scout.Scanner, input io.Reader, output io.Writer, options Options) (Summary, error) {
	var summary Summary
	if err := validate(ctx, scanner, input, output, options); err != nil {
		return summary, err
	}

	gate, err := policy.New(policy.Options{FailAt: report.High})
	if err != nil {
		return summary, err
	}

	stream := newStream(input)

	seen := make(map[string]bool)
	for {
		batch, readErr := readWindow(ctx, stream, scanner.Limits(), seen, 2*options.Workers)

		summary.Inputs += len(batch)
		for _, row := range scanWindow(ctx, scanner, gate, batch, options) {
			if err := writeResult(output, row); err != nil {
				return summary, err
			}

			summary.AddOutcome(row)
		}

		if readErr != nil {
			return summary, readErr
		}

		if err := ctx.Err(); err != nil {
			return summary, err
		}

		if len(batch) == 0 {
			return summary, nil
		}
	}
}

func validate(ctx context.Context, scanner *scout.Scanner, input io.Reader, output io.Writer, options Options) error {
	if ctx == nil || scanner == nil || input == nil || output == nil {
		return errors.New("replay requires context, scanner and streams")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := options.validate(); err != nil {
		return err
	}

	return validateReplayPlan(scanner.InspectionPlan())
}

func (o Options) validate() error {
	if o.Workers < 1 || o.Workers > 8 || o.Timeout < time.Second || o.Timeout > time.Minute {
		return errors.New("replay workers must be 1..8 and timeout 1s..1m")
	}

	return nil
}

func validateReplayPlan(plan report.InspectionPlan) error {
	if plan.Egress.Enabled() {
		return errors.New("replay requires an offline scanner")
	}

	if plan.HasServiceChecks() {
		return errors.New("replay excludes external service checks")
	}

	return nil
}

func newStream(input io.Reader) *stream {
	reader := bufio.NewScanner(io.LimitReader(input, maxInputBytes+1))
	reader.Buffer(make([]byte, 64<<10), maxLineBytes+2)

	var consumed int64

	reader.Split(func(data []byte, eof bool) (int, []byte, error) {
		advance, token, err := bufio.ScanLines(data, eof)

		consumed += int64(advance)
		if consumed > maxInputBytes {
			return 0, nil, errors.New("replay input byte budget exceeded")
		}

		return advance, token, err
	})

	return &stream{lines: reader}
}

func readWindow(ctx context.Context, input *stream, limits scout.Limits, seen map[string]bool, size int) ([]record, error) {
	batch := make([]record, 0, size)

	var retainedBytes int64

	for len(batch) < size {
		if err := ctx.Err(); err != nil {
			return batch, err
		}

		if !input.lines.Scan() {
			return batch, input.lines.Err()
		}

		input.line++
		if len(seen) >= maxRecords {
			return batch, inputError(input.line, "record count limit")
		}

		value, err := decodeRecord(input.lines.Bytes(), limits)
		if err != nil {
			return batch, inputError(input.line, "invalid captured record")
		}

		if seen[value.id] {
			return batch, inputError(input.line, "duplicate capture ID")
		}

		seen[value.id] = true

		batch = append(batch, value)
		for _, file := range value.files {
			retainedBytes += int64(len(file.data))
		}

		if retainedBytes >= maxWindowBytes {
			break
		}
	}

	return batch, nil
}

func inputError(line int, code string) error { return fmt.Errorf("replay record %d: %s", line, code) }

func decodeRecord(data []byte, limits scout.Limits) (record, error) {
	if len(data) > maxLineBytes || !utf8.Valid(data) {
		return record{}, errors.New("invalid line")
	}

	d := json.NewDecoder(bytes.NewReader(data))

	var captured encodedRecord

	seen, err := readObject(d, "record", captured.field)
	if err != nil {
		return record{}, err
	}

	if !seen["id"] || !seen["files"] || !replaywire.ValidDigest(captured.id) {
		return record{}, errors.New("invalid captured identity")
	}

	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return record{}, errors.New("trailing record data")
	}

	return prepareRecord(captured.id, captured.files, limits), nil
}

func delim(d *json.Decoder, want json.Delim) bool {
	token, err := d.Token()
	return err == nil && token == want
}

func stringToken(d *json.Decoder) (string, error) {
	token, err := d.Token()

	value, ok := token.(string)
	if err != nil || !ok {
		return "", errors.New("string value required")
	}

	return value, nil
}

func decodeFiles(d *json.Decoder) ([]encodedFile, error) {
	if !delim(d, '[') {
		return nil, errors.New("files array required")
	}

	files := make([]encodedFile, 0)
	for d.More() {
		if len(files) >= maxFileRecords {
			return nil, errors.New("file record limit")
		}

		file, err := decodeFile(d)
		if err != nil {
			return nil, err
		}

		files = append(files, file)
	}

	if !delim(d, ']') {
		return nil, errors.New("unterminated files array")
	}

	return files, nil
}

func decodeFile(d *json.Decoder) (encodedFile, error) {
	var file encodedFile

	seen, err := readObject(d, "file", file.field)
	if err != nil {
		return file, err
	}

	if !seen["name"] || !seen["data"] || strings.ContainsAny(file.data, "\r\n") {
		return file, errors.New("invalid captured file")
	}

	_, err = io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(file.data)))

	return file, err
}

func prepareRecord(id string, files []encodedFile, limits scout.Limits) record {
	value := record{id: id}
	if len(files) == 0 || len(files) > min(limits.Capture.MaxFiles, limits.MaxCaptureFiles) {
		value.rejection = "input file count limit"
		return value
	}

	names := archiveutil.Namespace{MaxNodes: min(limits.Capture.MaxEntries, limits.MaxCaptureEntries)}

	var total int64

	for _, file := range files {
		if ingest.ValidatePath(file.name, limits.Capture.MaxPathBytes, limits.Capture.MaxDepth) != nil || names.Add(file.name, false) != nil {
			value.rejection = "unsupported captured path"
			return value
		}

		size := int64(base64.StdEncoding.DecodedLen(len(file.data)))
		if strings.HasSuffix(file.data, "==") {
			size -= 2
		} else if strings.HasSuffix(file.data, "=") {
			size--
		}

		total += size
		if size > limits.Capture.MaxFileBytes || total > min(limits.Capture.MaxTotalBytes, limits.MaxCaptureBytes) {
			value.rejection = "input byte limit"
			return value
		}

		decoded, _ := base64.StdEncoding.Strict().DecodeString(file.data) // Already strictly validated above.
		value.files = append(value.files, capturedFile{name: file.name, data: decoded, executable: file.executable})
	}

	return value
}

func scanWindow(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, batch []record, options Options) []result {
	results := make([]result, len(batch))

	jobs := make(chan int, len(batch))
	for i := range batch {
		jobs <- i
	}

	close(jobs)

	var workers sync.WaitGroup
	for i := 0; i < min(options.Workers, len(batch)); i++ {
		workers.Go(func() {
			for index := range jobs {
				results[index] = scanRecord(ctx, scanner, gate, batch[index], options)
			}
		})
	}

	workers.Wait()

	return results
}

func initialResult(value record, options Options) result {
	return result{
		ID:            value.id,
		Version:       scout.Version(),
		BudgetSeconds: int(options.Timeout / time.Second),
		Coverage:      report.Failed,
		Decision:      report.Review,
		Findings:      []report.Finding{},
		Diagnostics:   []string{},
		State:         report.RunFailed,
	}
}

func scanRecord(ctx context.Context, scanner *scout.Scanner, gate *policy.Gate, value record, options Options) result {
	answer := initialResult(value, options)
	if value.rejection != "" {
		answer.Error = value.rejection
		return answer
	}

	call, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	if call.Err() != nil {
		answer.State = report.RunCancelled
		answer.Error = errorReplayDeadline

		return answer
	}

	directory, err := materialize(call, value.files)
	if err != nil {
		answer.Error = "replay_capture_error"
		if call.Err() != nil {
			answer.State, answer.Error = report.RunCancelled, errorReplayDeadline
		}

		return answer
	}

	run, scanErr := scanner.Scan(call, scout.Path(directory))
	cleanupErr := os.RemoveAll(directory)

	acceptRun(&answer, run, gate)
	acceptFaults(&answer, call, run, scanErr)

	if cleanupErr != nil {
		answer.Error = "replay_cleanup_error"
		answer.State = report.RunFailed
	}

	if (answer.State != report.RunComplete || answer.Error != "") && answer.Decision == report.Allow {
		answer.Decision = report.Review
	}

	return answer
}

func materialize(ctx context.Context, files []capturedFile) (string, error) {
	directory, err := os.MkdirTemp("", "scout-replay-")
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if err = ctx.Err(); err != nil {
			break
		}

		if err = writeCapturedFile(directory, file); err != nil {
			break
		}
	}

	if err != nil {
		_ = os.RemoveAll(directory)
		return "", err
	}

	return directory, nil
}

func writeResult(output io.Writer, value result) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	data = append(data, '\n')

	n, err := output.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}

	return err
}

// Object grammar owns duplicate-key and delimiter admission once for both
// captured record shapes. Field decoders retain their exact allowed vocabulary.
func readObject(d *json.Decoder, kind string, field func(*json.Decoder, string) error) (map[string]bool, error) {
	if !delim(d, '{') {
		return nil, errors.New(kind + " object required")
	}

	seen := map[string]bool{}

	for d.More() {
		key, err := stringToken(d)
		if err != nil || seen[key] {
			return nil, errors.New("invalid or duplicate " + kind + " key")
		}

		seen[key] = true
		if err := field(d, key); err != nil {
			return nil, err
		}
	}

	if !delim(d, '}') {
		return nil, errors.New("unterminated " + kind + " object")
	}

	return seen, nil
}

func (r *encodedRecord) field(d *json.Decoder, key string) (err error) {
	switch key {
	case "id":
		r.id, err = stringToken(d)
	case "files":
		r.files, err = decodeFiles(d)
	default:
		err = errors.New("unknown record key")
	}

	return err
}

func (f *encodedFile) field(d *json.Decoder, key string) (err error) {
	switch key {
	case "name":
		f.name, err = stringToken(d)
	case "data":
		f.data, err = stringToken(d)
	case "executable":
		var token any

		token, err = d.Token()

		var ok bool

		f.executable, ok = token.(bool)
		if !ok {
			err = errors.New("executable must be boolean")
		}
	default:
		err = errors.New("unknown file key")
	}

	return err
}

func acceptRun(answer *result, run report.Run, gate *policy.Gate) {
	answer.State, answer.RunDigest = run.State, run.Digest

	answer.Decision = gate.Evaluate(run, time.Now().UTC()).Decision
	if len(run.Targets) == 1 {
		acceptAnalysis(answer, run.Targets[0])
	}
}

func acceptAnalysis(answer *result, target report.TargetResult) {
	analysis := target.Analysis

	answer.Coverage, answer.Findings = analysis.Coverage.Completeness, analysis.Findings
	if answer.Findings == nil {
		answer.Findings = []report.Finding{}
	}

	seen := map[string]bool{}
	for _, diagnostic := range analysis.Diagnostics {
		if !seen[diagnostic.Code] {
			answer.Diagnostics = append(answer.Diagnostics, diagnostic.Code)
			seen[diagnostic.Code] = true
		}
	}

	sort.Strings(answer.Diagnostics)

	if target.State == report.RunFailed {
		answer.Error = "input_or_extraction_error"
		answer.Coverage = report.Failed
	}
}

func acceptFaults(answer *result, call context.Context, run report.Run, scanErr error) {
	if run.State == report.RunCancelled || run.State != report.RunComplete && call.Err() != nil {
		answer.Error = errorReplayDeadline
	}

	if run.Digest == "" || len(run.Targets) != 1 {
		answer.Error = "replay_runtime_error"
		answer.State = report.RunFailed
	}

	// ErrIncomplete includes deliberate static coverage gaps. Preserve those
	// observations without misclassifying them as generic execution faults.
	if scanErr != nil && !errors.Is(scanErr, scout.ErrIncomplete) && answer.Error == "" {
		answer.Error = "replay_runtime_error"
		answer.State = report.RunFailed
	}
}

func writeCapturedFile(directory string, file capturedFile) error {
	name := filepath.Join(directory, filepath.FromSlash(file.name))
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}

	mode := os.FileMode(0o600)
	if file.executable {
		mode = 0o700
	}

	// Captured names pass ingest.ValidatePath before materialization in this private staging directory.
	out, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: admitted local path within a fresh private staging directory.
	if err != nil {
		return err
	}

	n, writeErr := out.Write(file.data)
	if writeErr == nil && n != len(file.data) {
		writeErr = io.ErrShortWrite
	}

	err = errors.Join(writeErr, out.Close())
	if err != nil {
		return err
	}

	return err
}
