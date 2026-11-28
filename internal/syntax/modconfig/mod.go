// Package modconfig parses captured go.mod bytes, never loading a module or
// running go commands. The pinned x/mod parser is selected through Go modules.
package modconfig

import (
	"context"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const (
	codeByteLimit            = "byte_limit"
	codeDuplicateReplacement = "duplicate_replacement"
	codeDuplicateRequirement = "duplicate_requirement"
	codeInvalidCoordinate    = "invalid_coordinate"
	codeInvalidEncoding      = "invalid_encoding"
	codeMissingModule        = "missing_module"
	codeNilContext           = "nil_context"
	codeNodeLimit            = "node_limit"
	codeSyntaxError          = "syntax_error"
)

const (
	MaxBytes      = 256 << 10
	maxDirectives = 4096
)

type Error struct{ Code string }

// Parse rejects ambiguous duplicate requirements/replacements. Parser errors
// deliberately do not include input text, which could contain secret material.
func Parse(ctx context.Context, data string) (*modfile.File, error) {
	if ctx == nil {
		return nil, &Error{Code: codeNilContext}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(data) > MaxBytes {
		return nil, &Error{Code: codeByteLimit}
	}

	if !utf8.ValidString(data) || strings.ContainsRune(data, 0) {
		return nil, &Error{Code: codeInvalidEncoding}
	}

	f, err := modfile.Parse("", []byte(data), nil)
	if err != nil {
		return nil, &Error{Code: codeSyntaxError}
	}

	if err := validateModule(ctx, f); err != nil {
		return nil, err
	}

	return f, nil
}

func (e *Error) Error() string { return "go.mod: " + e.Code }

func validateModule(ctx context.Context, f *modfile.File) error {
	if f.Module == nil {
		return &Error{Code: codeMissingModule}
	}

	if len(f.Require)+len(f.Replace)+len(f.Exclude)+len(f.Retract) > maxDirectives {
		return &Error{Code: codeNodeLimit}
	}

	requires := map[string]bool{}

	for _, r := range f.Require {
		if err := ctx.Err(); err != nil {
			return err
		}

		if requires[r.Mod.Path] {
			return &Error{Code: codeDuplicateRequirement}
		}

		requires[r.Mod.Path] = true
		if module.Check(r.Mod.Path, r.Mod.Version) != nil {
			return &Error{Code: codeInvalidCoordinate}
		}
	}

	if err := validateReplacements(f.Replace); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}

func validateReplacements(values []*modfile.Replace) error {
	replacements := map[string]bool{}

	for _, r := range values {
		k := r.Old.Path + "@" + r.Old.Version
		if replacements[k] {
			return &Error{Code: codeDuplicateReplacement}
		}

		replacements[k] = true

		if r.New.Version != "" && module.Check(r.New.Path, r.New.Version) != nil {
			return &Error{Code: codeInvalidCoordinate}
		}
	}

	return nil
}
