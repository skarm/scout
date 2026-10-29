package scout_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/skarm/scout"
	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/osv"
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

func TestInvalidOptionsAndTargetsAreRejectedBeforeRun(t *testing.T) {
	if _, err := scout.New(context.Background(), scout.Options{}); !errors.Is(err, scout.ErrInvalidOptions) {
		t.Fatalf("zero options accepted: %v", err)
	}
	s := testScanner(t, basicOptions())
	for _, target := range []scout.Target{{}, scout.Path("https://example.invalid/a"), scout.Reader("a", nil)} {
		r, err := s.Scan(context.Background(), target)
		if !errors.Is(err, scout.ErrInvalidInput) || r.State != report.Unknown {
			t.Fatalf("invalid input began run: %+v %v", r, err)
		}
	}
}

func TestNewValidationRejectsInvalidDomainBudgets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*scout.Options)
	}{
		{name: "capture zero bytes", change: func(o *scout.Options) { o.Limits.Capture.MaxFileBytes = 0 }},
		{name: "extraction zero objects", change: func(o *scout.Options) { o.Limits.Extraction.MaxObjects = 0 }},
		{name: "parser zero timeout", change: func(o *scout.Options) { o.Limits.Analysis.ParserTimeout = 0 }},
		{name: "signature zero timeout", change: func(o *scout.Options) { o.Signatures.Timeout = 0 }},
		{
			name:   "signature oversized rules",
			change: func(o *scout.Options) { o.Signatures.ExtraRules = make([]byte, (256<<10)+1) },
		},
		{name: "unknown harness", change: func(o *scout.Options) { o.Harness.Host = "unknown" }},
		{name: "zero targets", change: func(o *scout.Options) { o.Concurrency.Targets = 0 }},
		{name: "excess targets", change: func(o *scout.Options) { o.Concurrency.Targets = 33 }},
		{name: "zero workers", change: func(o *scout.Options) { o.Concurrency.Workers = 0 }},
		{name: "excess workers", change: func(o *scout.Options) { o.Concurrency.Workers = 33 }},
		{name: "zero run timeout", change: func(o *scout.Options) { o.Limits.Timeout = 0 }},
		{name: "excess run timeout", change: func(o *scout.Options) { o.Limits.Timeout = 10*time.Minute + 1 }},
		{name: "zero operations", change: func(o *scout.Options) { o.Limits.Analysis.MaxOperations = 0 }},
		{name: "excess operations", change: func(o *scout.Options) { o.Limits.Analysis.MaxOperations = (1 << 40) + 1 }},
		{name: "zero matches", change: func(o *scout.Options) { o.Limits.Analysis.MaxMatchesPerRule = 0 }},
		{name: "excess matches", change: func(o *scout.Options) { o.Limits.Analysis.MaxMatchesPerRule = 100001 }},
		{name: "zero aggregate capture bytes", change: func(o *scout.Options) { o.Limits.MaxCaptureBytes = 0 }},
		{
			name:   "excess aggregate capture bytes",
			change: func(o *scout.Options) { o.Limits.MaxCaptureBytes = (256 << 20) + 1 },
		},
		{name: "zero aggregate extracted bytes", change: func(o *scout.Options) { o.Limits.MaxExtractedBytes = 0 }},
		{
			name:   "excess aggregate extracted bytes",
			change: func(o *scout.Options) { o.Limits.MaxExtractedBytes = (256 << 20) + 1 },
		},
		{name: "zero aggregate files", change: func(o *scout.Options) { o.Limits.MaxCaptureFiles = 0 }},
		{
			name:   "excess aggregate files",
			change: func(o *scout.Options) { o.Limits.MaxCaptureFiles = 100001; o.Limits.MaxCaptureEntries = 100001 },
		},
		{
			name:   "aggregate entries below files",
			change: func(o *scout.Options) { o.Limits.MaxCaptureEntries = o.Limits.MaxCaptureFiles - 1 },
		},
		{name: "excess aggregate entries", change: func(o *scout.Options) { o.Limits.MaxCaptureEntries = 100001 }},
		{name: "zero service requests", change: func(o *scout.Options) { o.Limits.MaxServiceRequests = 0 }},
		{name: "excess service requests", change: func(o *scout.Options) { o.Limits.MaxServiceRequests = 257 }},
		{name: "custom checks required", change: func(o *scout.Options) { o.Checks = nil }},
		{name: "named checks cannot be overridden", change: func(o *scout.Options) { o.Profile = scout.Standard }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := basicOptions()
			tc.change(&o)
			assertInvalidNewOptions(t, o)
		})
	}
}

func TestNewValidationChecksExplicitServices(t *testing.T) {
	provider, err := review.NewHTTP(review.HTTPOptions{
		Endpoint:         "https://review.invalid/v1/chat/completions",
		Model:            "test-model",
		Timeout:          time.Second,
		MaxOutputTokens:  2048,
		MaxResponseBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*scout.Options)
	}{
		{
			name:   "download limits",
			change: func(o *scout.Options) { d := fetch.DefaultOptions(); d.Timeout = 0; o.Download = &d },
		},
		{
			name:   "configured disabled vulnerabilities",
			change: func(o *scout.Options) { v := osv.DefaultOptions(); o.Vulnerabilities = &v },
		},
		{
			name:   "vulnerability consent",
			change: func(o *scout.Options) { v := osv.DefaultOptions(); v.Enabled = true; o.Vulnerabilities = &v },
		},
		{
			name:   "review profile requires provider",
			change: func(o *scout.Options) { o.Profile = scout.Review; o.Checks = nil },
		},
		{name: "configured disabled review", change: func(o *scout.Options) {
			o.Review = &scout.ReviewOptions{Provider: provider, Settings: review.DefaultOptions()}
		}},
		{name: "review source consent", change: func(o *scout.Options) {
			r := review.DefaultOptions()
			r.Enabled = true
			o.Review = &scout.ReviewOptions{Provider: provider, Settings: r}
		}},
		{name: "review missing provider", change: func(o *scout.Options) {
			r := review.DefaultOptions()
			r.Enabled, r.AllowSourceUpload = true, true
			o.Review = &scout.ReviewOptions{Settings: r}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := basicOptions()
			tc.change(&o)
			assertInvalidNewOptions(t, o)
		})
	}
	o := basicOptions()
	r := review.DefaultOptions()
	r.Enabled, r.AllowSourceUpload = true, true
	o.Review = &scout.ReviewOptions{Provider: provider, Settings: r}
	testScanner(t, o)
}

func TestNewValidationAcceptsBoundaryBudgetsAndSignatureClamps(t *testing.T) {
	o := basicOptions()
	o.Concurrency = scout.Concurrency{Targets: 32, Workers: 32}
	o.Limits.Timeout = 10 * time.Minute
	o.Limits.Analysis.MaxOperations = 1 << 40
	o.Limits.Analysis.MaxMatchesPerRule = 100000
	o.Limits.MaxCaptureBytes, o.Limits.MaxExtractedBytes = 256<<20, 256<<20
	o.Limits.MaxCaptureFiles, o.Limits.MaxCaptureEntries = 100000, 100000
	o.Limits.MaxServiceRequests = 256
	o.Limits.Capture.MaxEntries, o.Limits.Capture.MaxFiles = 100000, 100000
	o.Limits.Capture.MaxFileBytes, o.Limits.Capture.MaxTotalBytes = 32<<20, 256<<20
	testScanner(t, o)

	o = basicOptions()
	o.Limits.Timeout = time.Nanosecond
	o.Limits.Analysis.MaxOperations, o.Limits.Analysis.MaxMatchesPerRule = 1, 1
	o.Limits.MaxCaptureBytes, o.Limits.MaxExtractedBytes = 1, 1
	o.Limits.MaxCaptureFiles, o.Limits.MaxCaptureEntries, o.Limits.MaxServiceRequests = 1, 1, 1
	testScanner(t, o)
}

func TestAllTargetsValidateBeforeReadersAreConsumed(t *testing.T) {
	s := testScanner(t, basicOptions())
	input := &watchedReader{}
	run, err := s.ScanMany(context.Background(), []scout.Target{scout.Reader("a.txt", input), scout.Reader("../bad.txt", strings.NewReader("x"))})
	if !errors.Is(err, scout.ErrInvalidInput) || input.reads != 0 || len(run.Targets) != 0 {
		t.Fatalf("reads=%d state=%s err=%v", input.reads, run.State, err)
	}
}

func assertInvalidNewOptions(t *testing.T, options scout.Options) {
	t.Helper()
	scanner, err := scout.New(context.Background(), options)
	if scanner != nil {
		_ = scanner.Close()
	}
	var failure *scout.Error
	if scanner != nil || !errors.Is(err, scout.ErrInvalidOptions) || !errors.As(err, &failure) || failure.Code != "invalid_options" {
		t.Fatalf("invalid options did not fail preflight: scanner=%t error=%v", scanner != nil, err)
	}
}

type watchedReader struct{ reads int }

func (r *watchedReader) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }
