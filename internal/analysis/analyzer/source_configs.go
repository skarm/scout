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

const (
	maxSourceXMLOperations = 8192
	maxSourceXMLDepth      = 64
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

type mavenSourceURL struct {
	depth int
	start int
	text  strings.Builder
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

	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '\'' || value[0] == '"') {
		value = value[1 : len(value)-1]
	}

	return sourceConfigAssignment{
		key:      strings.TrimSpace(key),
		value:    value,
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

		sourceKey := lineSourceKeys[assignment.key] || name == ".npmrc" && strings.HasSuffix(assignment.key, ":registry")
		if !sourceConfigComment(trim) && assignment.assigned && sourceKey && !sourcepolicy.Default(assignment.value, kind) {
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

	var mavenURL *mavenSourceURL

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
		if operations > maxSourceXMLOperations {
			return true
		}

		switch node := tok.(type) {
		case xml.StartElement:
			if mavenURL != nil {
				// A repository URL is text, not nested XML markup.
				return true
			}

			stack = append(stack, node.Name.Local)
			if len(stack) > maxSourceXMLDepth {
				return true
			}

			inspectNuGetSource(name, node, stack, source.Span{Start: before, End: int(dec.InputOffset())}, emit)

			if mavenSourceElement(name, stack) {
				mavenURL = &mavenSourceURL{depth: len(stack), start: int(dec.InputOffset())}
			}
		case xml.EndElement:
			if mavenURL != nil && mavenURL.depth == len(stack) {
				inspectMavenSource(mavenURL.text.String(), source.Span{Start: mavenURL.start, End: before}, emit)
				mavenURL = nil
			}

			stack = stack[:len(stack)-1] // Decoder.Token has already checked balanced XML names.
		case xml.CharData:
			if mavenURL != nil {
				mavenURL.text.Write(node)
			}
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

func mavenSourceElement(name string, stack []string) bool {
	if name != "nuget.config" && len(stack) > 1 && stack[len(stack)-1] == "url" {
		parent := stack[len(stack)-2]
		return parent == "mirror" || parent == "repository" || parent == "pluginRepository"
	}

	return false
}

func inspectMavenSource(text string, span source.Span, emit func(source.Span)) {
	v := strings.TrimSpace(text)
	if v != "" && v != "https://repo.maven.apache.org/maven2" && v != "https://repo1.maven.org/maven2" {
		emit(span)
	}
}
