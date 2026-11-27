package dependencies

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"

	"golang.org/x/mod/module"
)

// collectGoVendor uses only module headers from a captured Go vendor inventory.
// A replacement header without an original version is a bookkeeping trailer.
func collectGoVendor(ctx context.Context, doc document.File, out *report.DependencyReport) {
	name := doc.Artifact().Metadata().Path
	if name != "vendor/modules.txt" && !strings.HasSuffix(name, "/vendor/modules.txt") {
		return
	}

	manifest := report.DependencyManifest{Path: name, Status: report.OutcomeCompleted, Parser: "go-vendor-inventory", ParserVersion: "1"}
	defer func() { out.Manifests = append(out.Manifests, manifest) }()

	start := 0

	for line := range strings.SplitSeq(doc.Artifact().Content(), "\n") {
		if ctx.Err() != nil {
			manifest.Status = report.OutcomeCancelled
			return
		}

		span := source.Span{Start: start, End: start + len(line)}
		start = span.End + 1

		body, ok := strings.CutPrefix(line, "# ")
		if !ok {
			continue
		}

		fields := strings.Fields(body)
		if len(fields) >= 2 && fields[1] == "=>" {
			continue
		}

		if !appendVendorDeclaration(out, doc, fields, span) {
			manifest.Status = report.OutcomePartial
		}

		if len(out.Declarations) >= maxDeclarations {
			manifest.Status = report.OutcomePartial
			return
		}
	}
}

func appendVendorDeclaration(out *report.DependencyReport, doc document.File, fields []string, span source.Span) bool {
	if len(fields) < 2 || module.Check(fields[0], fields[1]) != nil {
		return false
	}

	name, version := fields[0], fields[1]
	switch {
	case len(fields) == 5 && fields[2] == "=>" && module.Check(fields[3], fields[4]) == nil:
		name, version = fields[3], fields[4]
	case len(fields) != 2:
		return false
	}

	return appendDecl(out, doc, nil, report.EcosystemGo, name, version, report.VersionExactLockfile, span, false)
}
