// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted offline MCP Registry posture checks. Captured-byte evidence, bounded
// JSON parsing and static integration are Scout-specific; no acquisition/trust.

package analyzer

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/language"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

//nolint:gochecknoglobals // Immutable lookup data shared by concurrent scans; initialized once to avoid rebuilding it per input.
var mutableRegistryVersions = stringSet("latest next beta alpha stable canary edge main master dev nightly preview")

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var registryRecordInspectors = map[string]registryRecordInspector{
	ruleMCPRepository:     registryRepository,
	ruleMCPOfficialStatus: registryStatus,
	ruleMCPPlainHTTP:      registryRemoteHTTP,
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var registryCollectionFields = map[string]registryFieldShape{
	"repository": registryNullableObject,
	"packages":   registryObjectCollection,
	"remotes":    registryObjectCollection,
}

type registryCheck struct{ id string }

type (
	registryObservationEmitter func(*jsonconfig.Node, report.Severity, bool)
	registryRecordInspector    func(*jsonconfig.Node, *jsonconfig.Node, registryObservationEmitter)
)

type registryFieldShape uint8

const (
	registryNullableObject registryFieldShape = iota
	registryObjectCollection
)

func RegistryRules() []Analyzer {
	out := make([]Analyzer, 0, 5)
	for _, id := range []string{ruleMCPPackageVersion, "MCP-PACKAGE-SHA256", ruleMCPRepository, ruleMCPOfficialStatus, ruleMCPPlainHTTP} {
		out = append(out, registryCheck{id: id})
	}

	return out
}

func (a registryCheck) Rule() report.Rule {
	title := map[string]string{
		ruleMCPPackageVersion: "Registry package version requires review",
		"MCP-PACKAGE-SHA256":  "Registry package content digest requires review",
		ruleMCPRepository:     "Registry repository reference is unavailable",
		ruleMCPOfficialStatus: "Registry status is unavailable or not active",
		ruleMCPPlainHTTP:      "Registry record declares a plaintext HTTP endpoint",
	}[a.id]

	severity := report.High
	if a.id == ruleMCPRepository {
		severity = report.Info
	}

	if a.id == ruleMCPOfficialStatus {
		severity = report.Medium
	}

	return report.Rule{
		ID:          a.id,
		Version:     "1",
		Title:       title,
		Description: title,
		Severity:    severity,
		Category:    "registry-posture",
		Method:      "captured-registry-record-analysis",
		Limitation:  "Bounded registry-shaped JSON servers envelopes only. Fields are untrusted registry assertions, not verified ownership, integrity or service behavior. Missing/wrong-typed optional facts are info/unavailable; malformed record/collection shapes remain incomplete. Selected upstream version grammar; no registry access, package install, signature verification or history comparison. Descriptor severity is a maximum.",
	}
}

func (registryCheck) AppliesTo(document.File) bool { return true }

func (a registryCheck) Find(ctx context.Context, d document.File, budget int) (Result, error) {
	out := Result{}
	seen := map[source.Span]bool{}
	partial := false
	operations := 0

	for u := range parsedUnits[parse.JSONTree](d) {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}

		records := registryEnvelopeRecords(u)

		emit := registryEmitter(u.Unit, &out, &partial, seen, budget)

		for _, entry := range records {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}

			operations++
			if operations > 8192 {
				return out, errors.New("registry record budget exceeded")
			}

			record := entry.Get("server")
			if !registryCollectionsValid(record) {
				partial = true
				continue
			}

			if err := a.inspectRegistryRecord(entry, record, &operations, emit); err != nil {
				return out, err
			}
		}
	}

	if partial {
		return out, errors.New("registry candidate shape incomplete")
	}

	return out, ctx.Err()
}

func (a registryCheck) inspectRegistryRecord(entry, record *jsonconfig.Node, operations *int, emit func(*jsonconfig.Node, report.Severity, bool)) error {
	if inspect := registryRecordInspectors[a.id]; inspect != nil {
		inspect(entry, record, emit)
		return nil
	}

	return a.inspectRegistryPackages(record, operations, emit)
}

func (a registryCheck) inspectRegistryPackages(record *jsonconfig.Node, operations *int, emit func(*jsonconfig.Node, report.Severity, bool)) error {
	for _, p := range record.GetOrEmpty("packages").Elements {
		*operations++
		if *operations > 8192 {
			return errors.New("registry record budget exceeded")
		}

		key := "version"
		if a.id == "MCP-PACKAGE-SHA256" {
			key = "fileSha256"
		}

		n := p.Get(key)

		value, ok := n.Text()
		if !ok {
			emit(p, report.Info, true)
			continue
		}

		kind, _ := p.Get("registryType").Text()

		valid := specificRegistryVersion(kind, value)
		if a.id == "MCP-PACKAGE-SHA256" {
			valid = textmatch.LowerHex(value, 64)
		}

		if !valid {
			emit(n, report.High, false)
		}
	}

	return nil
}

func registryEmitter(u document.Unit, out *Result, partial *bool, seen map[source.Span]bool, budget int) func(*jsonconfig.Node, report.Severity, bool) {
	return func(n *jsonconfig.Node, severity report.Severity, unavailable bool) {
		if n == nil || out.Truncated {
			return
		}

		at, e := u.View.Original(n.Span)
		if e != nil {
			*partial = true
			return
		}

		if seen[at] {
			return
		}

		seen[at] = true

		if len(out.Matches) >= budget {
			out.Truncated = true
			return
		}

		signal := "registry_assertion"
		if unavailable {
			signal = "evidence_unavailable"
		}

		out.Matches = append(out.Matches, Match{
			Start:          at.Start,
			End:            at.End,
			Severity:       severity,
			ContextSignals: []string{signal},
		})
	}
}

func registryRepository(_, record *jsonconfig.Node, emit registryObservationEmitter) {
	repository := record.Get("repository")

	value, known := repository.Get("url").Text()
	if !known || value == "" {
		if repository == nil {
			repository = record
		}

		emit(repository, report.Info, true)
	}
}

func registryStatus(entry, _ *jsonconfig.Node, emit registryObservationEmitter) {
	node := entry.Get("_meta").Get("io.modelcontextprotocol.registry/official").Get("status")

	value, known := node.Text()
	if !known {
		emit(entry, report.Info, true)
	} else if value != "active" {
		emit(node, report.Medium, false)
	}
}

func registryRemoteHTTP(_, record *jsonconfig.Node, emit registryObservationEmitter) {
	for _, remote := range record.GetOrEmpty("remotes").Elements {
		node := remote.Get("url")
		if value, known := node.Text(); known && strings.HasPrefix(strings.ToLower(value), "http://") {
			emit(node, report.High, false)
		}
	}
}

func specificRegistryVersion(kind, value string) bool {
	if mutableRegistryVersions[strings.ToLower(value)] {
		return false
	}

	digit := false
	for _, r := range value {
		digit = digit || unicode.IsDigit(r)
		if unicode.IsSpace(r) || strings.ContainsRune("^~*><=|", r) {
			return false
		}
	}

	if !digit || registryVersionWildcard(value) {
		return false
	}

	return kind != "npm" || textmatch.Version(strings.TrimPrefix(value, "v"))
}

func registryVersionWildcard(value string) bool {
	for part := range strings.SplitSeq(value, ".") {
		if part == "x" || part == "X" || part == "*" {
			return true
		}
	}

	return false
}

// Registry envelopes and collection shapes are explicit admission grammars;
// their fields remain untrusted assertions after the grammar accepts them.
func registryEnvelopeRecords(unit typedUnit[parse.JSONTree]) []*jsonconfig.Node {
	root := unit.tree.Root
	if unit.Language != language.JSON || root == nil || root.Kind != jsonconfig.KindObject {
		return nil
	}

	servers := root.GetOrEmpty("servers")
	if servers.Kind != jsonconfig.KindArray {
		return nil
	}

	return servers.Elements
}

func registryCollectionsValid(record *jsonconfig.Node) bool {
	if record == nil || record.Kind != jsonconfig.KindObject {
		return false
	}

	name, known := record.Get("name").Text()
	if !known || name == "" {
		return false
	}

	for key, shape := range registryCollectionFields {
		if !validRegistryField(record.Get(key), shape) {
			return false
		}
	}

	return true
}

func validRegistryField(node *jsonconfig.Node, shape registryFieldShape) bool {
	if node == nil {
		return true
	}

	if shape == registryNullableObject {
		return node.Kind == jsonconfig.KindNull || node.Kind == jsonconfig.KindObject
	}

	if node.Kind != jsonconfig.KindArray {
		return false
	}

	for _, element := range node.Elements {
		if element.Kind != jsonconfig.KindObject {
			return false
		}
	}

	return true
}
