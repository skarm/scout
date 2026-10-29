package analyzer

import (
	"context"
	"errors"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"

	"golang.org/x/mod/modfile"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var moduleReplacementRules = map[string]moduleReplacementKind{
	ruleSC002: moduleLocalReplacement,
	ruleSC003: moduleRedirectedReplacement,
}

type moduleCheck struct{ id string }

type moduleReplacementKind uint8

const (
	// An unknown rule selects no real replacement kind.
	_ moduleReplacementKind = iota
	moduleSelfReplacement
	moduleLocalReplacement
	moduleRedirectedReplacement
)

func (a moduleCheck) Rule() report.Rule {
	r := report.Rule{
		ID: a.id, Version: "1", Severity: report.Medium, Category: "supply-chain", Method: "go-mod-structure",
		Limitation: "Declarations only. No dependency download, checksum verification, vulnerability database or proof of execution. A legitimate local replacement may require review.",
	}
	switch a.id {
	case ruleSC002:
		r.Title = "Go module uses a local replacement outside module checksum verification"
	case ruleSC003:
		r.Title = "Go module dependency identity is redirected to a different module"
	}

	r.Description = r.Title

	return r
}

func (moduleCheck) AppliesTo(f document.File) bool { return hasParsedUnit[parse.GoModTree](f) }

func (a moduleCheck) Find(ctx context.Context, f document.File, budget int) (Result, error) {
	var out Result
	if err := ctx.Err(); err != nil {
		return out, err
	}

	for u := range parsedUnits[parse.GoModTree](f) {
		tree := u.tree
		if tree.File == nil {
			continue
		}

		for _, r := range tree.File.Replace {
			if err := ctx.Err(); err != nil {
				return out, err
			}

			if replacementKind(r) != moduleReplacementRules[a.id] {
				continue
			}

			if len(out.Matches) >= budget {
				out.Truncated = true
				return out, nil
			}

			start, end := r.Syntax.Span()

			at, err := u.View.Original(source.Span{Start: start.Byte, End: end.Byte})
			if err != nil {
				return out, errors.New("go.mod source mapping failed")
			}

			out.Matches = append(out.Matches, Match{Start: at.Start, End: at.End})
		}
	}

	return out, nil
}

func replacementKind(replacement *modfile.Replace) moduleReplacementKind {
	if replacement.New.Version == "" {
		return moduleLocalReplacement
	}

	if replacement.Old.Path != replacement.New.Path {
		return moduleRedirectedReplacement
	}

	return moduleSelfReplacement
}
