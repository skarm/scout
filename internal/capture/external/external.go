// Package external follows explicitly authorized literal source references.
// It only captures bytes: no Git, package manager, shell or target code runs.
package external

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/netpolicy"
	"github.com/skarm/scout/report"
)

const (
	statusLimit = "limit"
)

var referencePattern = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `\\]+`)

type Options struct {
	AllowedOrigins        []string
	MaxDepth, MaxRequests int
	MaxBytes              int64
}

type queued struct {
	file  artifact.File
	depth int
}

type traversal struct {
	ctx                   context.Context
	options               Options
	download              fetch.Options
	limits                report.CaptureLimits
	report                *report.ExternalClosure
	files                 []artifact.File
	skipped               []report.File
	diagnostics           []report.Diagnostic
	queue                 []queued
	names                 map[string]bool
	allowed               map[string]bool
	seen                  map[string]string
	rootBytes, downloaded int64
	requests              int
}

func (o Options) Validate(loopback bool) error {
	if o.MaxDepth < 1 || o.MaxDepth > 8 || o.MaxRequests < 1 || o.MaxRequests > 64 || o.MaxBytes < 1 || o.MaxBytes > 32<<20 || len(o.AllowedOrigins) < 1 || len(o.AllowedOrigins) > 32 {
		return errors.New("invalid external traversal limits")
	}

	for _, origin := range o.AllowedOrigins {
		u, err := netpolicy.ParseURL(origin, netpolicy.URLPolicy{MaxBytes: 2048, AllowLoopback: loopback})
		if err != nil || u.Path != "" && u.Path != "/" {
			return errors.New("external origins must be explicit HTTPS origins")
		}
	}

	return nil
}

func Expand(ctx context.Context, snapshot artifact.Snapshot, o Options, download fetch.Options, limits report.CaptureLimits) (artifact.Snapshot, *report.ExternalClosure, error) {
	closure := &report.ExternalClosure{
		MaxDepth:    o.MaxDepth,
		MaxRequests: o.MaxRequests,
		MaxBytes:    o.MaxBytes,
		References:  []report.ExternalReference{},
	}
	if !download.Enabled {
		return snapshot, closure, errors.New("external download permission required")
	}

	if err := o.Validate(download.AllowLoopback); err != nil {
		return snapshot, closure, err
	}

	closure.Complete = true

	t := newTraversal(ctx, snapshot, o, download, limits, closure)
	for i := 0; i < len(t.queue); i++ {
		if ctx.Err() != nil {
			closure.Complete = false
			break
		}

		t.inspect(t.queue[i])
	}

	if !closure.Complete {
		t.diagnostics = append(t.diagnostics, report.Diagnostic{
			Code:         "external_closure_incomplete",
			Message:      "At least one external source was denied, failed or exceeded a traversal budget.",
			AffectsScope: true,
		})
	}

	result := artifact.New(snapshot.Metadata().SourceKind+"+external", t.files, t.skipped, t.diagnostics, snapshot.Complete() && closure.Complete)

	return result, closure, ctx.Err()
}

func newTraversal(ctx context.Context, snapshot artifact.Snapshot, o Options, download fetch.Options, limits report.CaptureLimits, closure *report.ExternalClosure) *traversal {
	t := &traversal{
		ctx:         ctx,
		options:     o,
		download:    download,
		limits:      limits,
		report:      closure,
		files:       snapshot.Files(),
		diagnostics: snapshot.Diagnostics(),
		names:       map[string]bool{},
		allowed:     map[string]bool{},
		seen:        map[string]string{},
	}
	for _, f := range snapshot.Metadata().Files {
		t.names[f.Path] = true
		if f.Status != report.CaptureCaptured {
			t.skipped = append(t.skipped, f)
		} else {
			t.rootBytes += f.Size
		}
	}

	for _, file := range t.files {
		t.queue = append(t.queue, queued{file: file, depth: 0})
	}

	for _, raw := range o.AllowedOrigins {
		u, _ := url.Parse(raw)
		t.allowed[strings.ToLower(u.Scheme+"://"+u.Host)] = true
	}

	return t
}

func (t *traversal) inspect(item queued) {
	text := item.file.Content()

	matches := referencePattern.FindAllStringIndex(text, 513)
	if len(matches) > 512 {
		t.report.Complete = false
		matches = matches[:512]
	}

	for _, at := range matches {
		if len(t.report.References) >= 4096 {
			t.report.Complete = false
			break
		}

		raw := strings.TrimRight(text[at[0]:at[1]], ".,;:)]}")
		if len(raw) > 2048 {
			t.report.Complete = false
			continue
		}

		u, err := url.Parse(raw)
		if err != nil || !externalSource(u.Path) {
			continue
		}

		meta := item.file.Metadata()
		ref := report.ExternalReference{
			Source: report.SourceRef{
				Path:       meta.Path,
				SHA256:     meta.SHA256,
				ByteStart:  at[0],
				ByteEnd:    at[0] + len(raw),
				SpanSHA256: artifact.Hash([]byte(raw)),
			},
			URLSHA256: artifact.Hash([]byte(raw)),
			Depth:     item.depth + 1,
			Status:    "denied",
		}
		t.follow(raw, u, item.depth, &ref)

		if ref.Status != report.CaptureCaptured && ref.Status != report.CaptureAlreadyCaptured {
			t.report.Complete = false
		}

		t.report.References = append(t.report.References, ref)
	}
}

func (t *traversal) follow(raw string, u *url.URL, depth int, ref *report.ExternalReference) {
	if existing, ok := t.seen[raw]; ok {
		ref.Path = existing
		ref.Status = report.CaptureAlreadyCaptured

		return
	}

	if !t.allowed[strings.ToLower(u.Scheme+"://"+u.Host)] {
		return
	}

	if depth >= t.options.MaxDepth || t.requests >= t.options.MaxRequests || len(t.files) >= t.limits.MaxFiles || len(t.files)+len(t.skipped) >= t.limits.MaxEntries {
		ref.Status = statusLimit
		return
	}

	options := t.download
	options.Revision = ""
	options.ExpectedSHA256 = ""

	options.MaxBytes = min(options.MaxBytes, t.limits.MaxFileBytes, t.limits.MaxTotalBytes-t.rootBytes-t.downloaded, t.options.MaxBytes-t.downloaded)
	if options.MaxBytes < 1 {
		ref.Status = statusLimit
		return
	}

	t.requests++
	t.downloaded += options.MaxBytes

	payload, err := fetch.Get(t.ctx, raw, options)
	if err != nil {
		ref.Status = report.OutcomeFailed
		return
	}

	t.downloaded -= options.MaxBytes - int64(len(payload.Data))
	t.publish(raw, payload, ref)
}

func (t *traversal) publish(raw string, payload fetch.Payload, ref *report.ExternalReference) {
	name := fmt.Sprintf(".scout-external/%s/%s", ref.URLSHA256, payload.Name)
	if len(name) > t.limits.MaxPathBytes || strings.Count(name, "/")+1 > t.limits.MaxDepth {
		ref.Status = statusLimit
		return
	}

	if t.names[name] {
		ref.Status = "namespace_conflict"
		return
	}

	file := artifact.NewFile(name, payload.Data, false).WithGeneratedName()
	t.files = append(t.files, file)
	t.queue = append(t.queue, queued{file: file, depth: ref.Depth})
	t.names[name] = true
	t.seen[raw] = name
	ref.Path = name
	ref.BytesSHA256 = file.Metadata().SHA256
	ref.Status = report.CaptureCaptured
}

func externalSource(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".md", ".txt", ".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".go", ".sql", ".json", ".yaml", ".yml", ".toml", ".zip", ".tar", ".gz":
		return true
	}

	return false
}
