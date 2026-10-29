// Package dependencies inventories captured declarations without invoking any
// build tool, importer, resolver, checksum service or vulnerability API.
package dependencies

import (
	"context"
	"strconv"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func Collect(ctx context.Context, docs []document.File) report.DependencyReport {
	out := report.DependencyReport{
		Scope:        "captured-go-npm-python-declarations-not-install-attestation",
		Manifests:    []report.DependencyManifest{},
		Declarations: []report.Dependency{},
		Limitations: []string{
			"go.mod require versions are declared minimums under Go MVS, not evidence of the version that would be selected or installed.",
			"No dependencies are downloaded, built or executed. Optional vulnerability checks are reported separately; declarations do not establish reachability or integrity.",
			"Replacement paths are not opened. An exact replacement version does not establish source trust or integrity. Unsupported ecosystems remain in whole-artifact coverage.",
		},
	}
	for _, doc := range docs {
		collectPackages(ctx, doc, &out)

		for _, u := range doc.Units() {
			if u.Language != language.GoMod {
				continue
			}

			out.Manifests = append(out.Manifests, report.DependencyManifest{
				Path:          doc.Artifact().Metadata().Path,
				Status:        u.Status,
				Parser:        u.ParserID,
				ParserVersion: u.ParserVersion,
			})
			if !collectGoModule(ctx, doc, u, &out) {
				return out
			}
		}
	}

	return out
}

func collectGoModule(ctx context.Context, doc document.File, u document.Unit, out *report.DependencyReport) bool {
	tree, ok := u.Tree.(parse.GoModTree)
	if !ok || tree.File == nil {
		return true
	}
	// The parser rejects duplicate replacement coordinates. Build one index per
	// module; each requirement can match only its wildcard and exact version.
	replacements := make(map[module.Version]*modfile.Replace, len(tree.File.Replace))
	for _, replacement := range tree.File.Replace {
		replacements[replacement.Old] = replacement
	}

	for _, r := range tree.File.Require {
		if ctx.Err() != nil {
			out.Manifests[len(out.Manifests)-1].Status = report.OutcomeCancelled
			out.Limitations = append(out.Limitations, "Dependency declaration inventory was cancelled.")

			return false
		}

		start, end := r.Syntax.Span()

		span, err := u.View.Original(source.Span{Start: start.Byte, End: end.Byte})
		if err != nil {
			out.Manifests[len(out.Manifests)-1].Status = "evidence_mapping_failed"
			out.Limitations = append(out.Limitations, "A declaration could not be mapped to captured bytes; it was not published as verified evidence.")

			continue
		}

		meta := doc.Artifact().Metadata()
		d := report.Dependency{
			Ecosystem:        report.EcosystemGo,
			Module:           r.Mod.Path,
			DeclaredVersion:  r.Mod.Version,
			VersionSemantics: report.VersionGoMinimum,
			Indirect:         r.Indirect,
			Replacement:      "none",
			Source: report.SourceRef{
				Path:       meta.Path,
				SHA256:     meta.SHA256,
				ByteStart:  span.Start,
				ByteEnd:    span.End,
				SpanSHA256: artifact.Hash([]byte(doc.Artifact().Content()[span.Start:span.End])),
			},
		}
		applyGoReplacements(&d, doc, u, replacements, r, out)
		d.ID = artifact.Hash([]byte("dependency-v1\x00" + meta.Path + "\x00" + meta.SHA256 + "\x00" + strconv.Itoa(span.Start) + "\x00" + strconv.Itoa(span.End)))
		out.Declarations = append(out.Declarations, d)
	}

	return true
}

func applyGoReplacements(d *report.Dependency, doc document.File, u document.Unit, replacements map[module.Version]*modfile.Replace, required *modfile.Require, out *report.DependencyReport) {
	// Wildcards are applied first so exact-version replacements take precedence.
	for _, coordinate := range []module.Version{{Path: required.Mod.Path}, required.Mod} {
		replacement := replacements[coordinate]
		if replacement == nil {
			continue
		}

		start, end := replacement.Syntax.Span()

		meta := doc.Artifact().Metadata()
		if mapped, err := u.View.Original(source.Span{Start: start.Byte, End: end.Byte}); err == nil {
			d.ReplacementSource = &report.SourceRef{
				Path:       meta.Path,
				SHA256:     meta.SHA256,
				ByteStart:  mapped.Start,
				ByteEnd:    mapped.End,
				SpanSHA256: artifact.Hash([]byte(doc.Artifact().Content()[mapped.Start:mapped.End])),
			}
		} else {
			d.ReplacementSource = nil
			out.Manifests[len(out.Manifests)-1].Status = "evidence_mapping_failed"
			out.Limitations = append(out.Limitations, "A replacement declaration could not be mapped to captured bytes.")
		}

		if replacement.New.Version == "" {
			d.Replacement, d.ReplacementModule, d.ReplacementVersion = "local-unresolved", "", ""
		} else {
			d.Replacement, d.ReplacementModule, d.ReplacementVersion = "module", replacement.New.Path, replacement.New.Version
		}
	}
}
