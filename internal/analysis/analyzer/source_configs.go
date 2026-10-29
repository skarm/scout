// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Selected additional SC10 direct configuration surfaces; never resolved online.

package analyzer

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/skarm/scout/report"

	"github.com/skarm/scout/internal/analysis/sourcepolicy"
	"github.com/skarm/scout/internal/syntax/source"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	lineSourceKeys  = stringSet("registry index-url extra-index-url find-links repository")
	nodeLineConfigs = stringSet(".yarnrc .npmrc")
)

type sourceConfigAssignment struct {
	key, value string
	assigned   bool
}

func directSourceConfig(ctx context.Context, name, text string, emit func(source.Span)) bool {
	switch name {
	case "pip.conf", "pip.ini", ".pypirc", ".yarnrc", ".npmrc":
		return directLineSourceConfig(ctx, name, text, emit)
	case "settings.xml", "pom.xml", "nuget.config":
		return directXMLSourceConfig(ctx, name, text, emit)
	}

	return false
}

func readSourceConfigAssignment(name, text string) sourceConfigAssignment {
	key, value, assigned := strings.Cut(text, "=")
	if name == ".yarnrc" && !assigned {
		if fields := strings.Fields(text); len(fields) == 2 {
			key, value, assigned = fields[0], fields[1], true
		}
	}

	return sourceConfigAssignment{
		key:      strings.TrimSpace(key),
		value:    strings.Trim(strings.TrimSpace(value), `"'`),
		assigned: assigned,
	}
}

func directLineSourceConfig(ctx context.Context, name, text string, emit func(source.Span)) bool {
	kind := report.EcosystemPyPI
	if nodeLineConfigs[name] {
		kind = report.EcosystemNPM
	}

	offset := 0

	for line := range strings.Lines(text) {
		if ctx.Err() != nil {
			return true
		}

		trim := strings.TrimSpace(line)

		assignment := readSourceConfigAssignment(name, trim)
		if !sourceConfigComment(trim) && assignment.assigned && lineSourceKeys[assignment.key] && !sourcepolicy.Default(assignment.value, kind) {
			emit(source.Span{Start: offset, End: offset + len(line)})
		}

		offset += len(line)
	}

	return false
}

func directXMLSourceConfig(ctx context.Context, name, text string, emit func(source.Span)) bool {
	dec := xml.NewDecoder(strings.NewReader(text))
	stack := make([]string, 0)
	operations := 0

	for {
		if ctx.Err() != nil {
			return true
		}

		before := int(dec.InputOffset())

		tok, e := dec.Token()
		if e != nil {
			return !errors.Is(e, io.EOF)
		}

		operations++
		if operations > 8192 {
			return true
		}

		switch node := tok.(type) {
		case xml.StartElement:
			stack = append(stack, node.Name.Local)
			if len(stack) > 64 {
				return true
			}

			inspectNuGetSource(name, node, stack, source.Span{Start: before, End: int(dec.InputOffset())}, emit)
		case xml.EndElement:
			stack = stack[:len(stack)-1] // Decoder.Token has already checked balanced XML names.
		case xml.CharData:
			inspectMavenSource(name, node, stack, source.Span{Start: before, End: int(dec.InputOffset())}, emit)
		}
	}
}

func inspectNuGetSource(name string, node xml.StartElement, stack []string, span source.Span, emit func(source.Span)) {
	if name == "nuget.config" && node.Name.Local == "add" && len(stack) > 1 && stack[len(stack)-2] == "packageSources" {
		for _, a := range node.Attr {
			if a.Name.Local == "value" && strings.TrimSpace(a.Value) != "https://api.nuget.org/v3/index.json" {
				emit(span)
			}
		}
	}
}

func inspectMavenSource(name string, node xml.CharData, stack []string, span source.Span, emit func(source.Span)) {
	if name != "nuget.config" && len(stack) > 1 && stack[len(stack)-1] == "url" {
		parent := stack[len(stack)-2]
		if parent == "mirror" || parent == "repository" || parent == "pluginRepository" {
			v := strings.TrimSpace(string(node))
			if v != "" && v != "https://repo.maven.apache.org/maven2" && v != "https://repo1.maven.org/maven2" {
				emit(span)
			}
		}
	}
}
