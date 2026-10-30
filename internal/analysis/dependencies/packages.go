package dependencies

import (
	"context"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"

	"golang.org/x/mod/semver"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/internal/textmatch"
	"github.com/skarm/scout/report"
)

const maxDeclarations = 8192

var (
	requirement    = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^\s;#]+)?`)
	exactPyVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?$`)
)

var (
	//nolint:gochecknoglobals // Read-only manifest filename sets shared by dependency captures.
	packageJSONNames = map[string]bool{
		"package.json":        true,
		"package-lock.json":   true,
		"npm-shrinkwrap.json": true,
		"pipfile.lock":        true,
	}
	//nolint:gochecknoglobals // Read-only manifest filename sets shared by dependency captures.
	pythonTOMLNames = map[string]bool{"pyproject.toml": true, "uv.lock": true, "poetry.lock": true, "pipfile": true}
)

type dependencyAdder func(eco, pkg, version, kind string, node *jsonconfig.Node, indirect bool)

type requirementDeclaration struct {
	name, version, kind string
	partial, skip       bool
}

func exactNPM(v string) bool { return textmatch.Version(v) && semver.IsValid("v"+v) }

func logicalName(p string) string {
	// Derived URIs contain escaped member names; this is only a format hint, not
	// file ownership or permission. The raw source still identifies the object.
	if u, e := url.PathUnescape(p); e == nil {
		p = u
	}

	return strings.ToLower(path.Base(p))
}

func appendDecl(out *report.DependencyReport, doc document.File, u *document.Unit, eco, name, version, semantics string, span source.Span, indirect bool) bool {
	if len(out.Declarations) >= maxDeclarations {
		return false
	}

	if !(textmatch.Token(name, 256, "@/_.-") && (textmatch.Alnum(name[0]) || name[0] == '@')) || len(version) > 256 {
		return false
	}
	// Source references and digests retain the declaration. An unresolved source
	// specifier may carry a credential-bearing URL: do not print it as a version.
	if semantics == report.VersionUnresolved {
		version = "unresolved"
	}

	ref, ok := declarationSource(doc, u, span)
	if !ok {
		return false
	}

	m := doc.Artifact().Metadata()
	span = source.Span{Start: ref.ByteStart, End: ref.ByteEnd}

	id := artifact.Hash([]byte("dependency-v2\x00" + m.Path + "\x00" + m.SHA256 + "\x00" + eco + "\x00" + name + "\x00" + strconv.Itoa(span.Start) + "\x00" + strconv.Itoa(span.End) + "\x00" + strconv.Itoa(len(out.Declarations))))
	out.Declarations = append(out.Declarations, report.Dependency{
		ID:               id,
		Ecosystem:        eco,
		Module:           name,
		DeclaredVersion:  version,
		VersionSemantics: semantics,
		Indirect:         indirect,
		Replacement:      "none",
		Source:           ref,
	})

	return true
}

func declarationSource(doc document.File, u *document.Unit, span source.Span) (report.SourceRef, bool) {
	if u != nil {
		var err error

		span, err = u.View.Original(span)
		if err != nil {
			return report.SourceRef{}, false
		}
	}

	raw := doc.Artifact().Content()
	if span.Start < 0 || span.End > len(raw) || span.Start >= span.End {
		return report.SourceRef{}, false
	}

	m := doc.Artifact().Metadata()
	ref := report.SourceRef{
		Path:       m.Path,
		SHA256:     m.SHA256,
		ByteStart:  span.Start,
		ByteEnd:    span.End,
		SpanSHA256: artifact.Hash([]byte(raw[span.Start:span.End])),
	}

	return ref, true
}

func collectPackages(ctx context.Context, doc document.File, out *report.DependencyReport) {
	name := logicalName(doc.Artifact().Metadata().Path)
	switch {
	case pythonTOMLNames[name]:
		collectPythonTOML(ctx, doc, out, name)
	case name == "requirements.txt" || strings.HasPrefix(name, "requirements-") && strings.HasSuffix(name, ".txt"):
		collectRequirements(ctx, doc, out)
	case packageJSONNames[name]:
		collectJSONPackages(ctx, doc, out, name)
	}
}

func collectJSONPackages(ctx context.Context, doc document.File, out *report.DependencyReport, name string) {
	unit, root, status := manifestTree(doc, language.JSON)

	mi := len(out.Manifests)
	out.Manifests = append(out.Manifests, report.DependencyManifest{
		Path:          doc.Artifact().Metadata().Path,
		Status:        status,
		Parser:        "json-stdlib-strict",
		ParserVersion: "1",
	})

	if root == nil {
		return
	}

	if root.Kind != jsonconfig.KindObject {
		out.Manifests[mi].Status = report.OutcomePartial
		return
	}

	partial := false
	add := func(eco, pkg, v, kind string, n *jsonconfig.Node, indirect bool) {
		if !appendDecl(out, doc, &unit, eco, pkg, v, kind, n.Span, indirect) {
			partial = true
		}
	}

	malformed := collectJSONDeclarations(ctx, name, root, unit.View.Text(), add)
	if partial || malformed {
		out.Manifests[mi].Status = report.OutcomePartial
	}
}

func manifestTree(doc document.File, language string) (document.Unit, *jsonconfig.Node, string) {
	for _, unit := range doc.Units() {
		if unit.Language != language || unit.Origin != "file" {
			continue
		}

		if tree, ok := unit.Tree.(parse.JSONTree); ok {
			return unit, tree.Root, unit.Status
		}

		return unit, nil, unit.Status
	}

	return document.Unit{}, nil, "unsupported"
}

func collectJSONDeclarations(ctx context.Context, name string, root *jsonconfig.Node, text string, add dependencyAdder) bool {
	switch name {
	case "package.json":
		return collectPackageManifest(root, add)
	case "pipfile.lock":
		return collectPipfileLock(ctx, root, add)
	default:
		return collectNPMLock(ctx, root, text, add)
	}
}

func collectPackageManifest(root *jsonconfig.Node, add dependencyAdder) bool {
	partial := false

	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		n := root.Get(field)
		if n == nil {
			continue
		}

		if n.Kind != jsonconfig.KindObject {
			partial = true
			continue
		}

		for _, m := range n.Members {
			v, ok := m.Value.Text()
			if !ok {
				partial = true
				continue
			}

			kind := report.VersionUnresolved
			if exactNPM(v) {
				kind = report.VersionExactDeclaration
			}

			add(report.EcosystemNPM, m.Key, v, kind, m.Value, false)
		}
	}

	return partial
}

func collectPipfileLock(ctx context.Context, root *jsonconfig.Node, add dependencyAdder) bool {
	metadata := root.Get("_meta")
	indexes := pipfileSources(metadata.Get("sources"))

	if metadata != nil && metadata.Kind != jsonconfig.KindObject {
		indexes = pipfileIndexes{}
	}

	partial := !indexes.valid

	for _, category := range root.Members {
		if category.Key == "_meta" {
			continue
		}

		if ctx.Err() != nil {
			return true
		}

		n := category.Value

		if n.Kind != jsonconfig.KindObject {
			partial = true
			continue
		}

		for _, m := range n.Members {
			if ctx.Err() != nil {
				return true
			}

			v, ok := m.Value.Get("version").Text()
			if !ok {
				partial = true
				continue
			}

			kind := report.VersionUnresolved

			if pipfileExactVersion(m.Value, v, indexes) {
				v = strings.TrimPrefix(v, "==")
				kind = report.VersionExactLockfile
			}

			add(report.EcosystemPyPI, normalizePyPIName(m.Key), v, kind, m.Value, false)
		}
	}

	return partial
}

func collectNPMLock(ctx context.Context, root *jsonconfig.Node, text string, add dependencyAdder) bool {
	partial := false
	lv := root.Get("lockfileVersion")

	v := ""
	if lv != nil && lv.Kind == jsonconfig.KindNumber {
		v = text[lv.Span.Start:lv.Span.End]
	}

	switch v {
	case "2", "3":
		n := root.Get("packages")
		if n == nil || n.Kind != jsonconfig.KindObject {
			partial = true
			break
		}

		partial = collectNPMPackages(ctx, n, add)
	case "1":
		partial = collectNPMLockV1(ctx, root.Get("dependencies"), 0, add)
	default:
		partial = true
	}

	return partial
}

func collectNPMPackages(ctx context.Context, n *jsonconfig.Node, add dependencyAdder) bool {
	partial := false

	for _, m := range n.Members {
		if ctx.Err() != nil {
			return true
		}

		if m.Key == "" {
			continue
		}

		pkg, v, kind, ok := npmPackageCoordinate(m.Key, m.Value)
		if !ok {
			partial = true
			continue
		}

		add(report.EcosystemNPM, pkg, v, kind, m.Value, true)
	}

	return partial
}

func npmPackageCoordinate(name string, n *jsonconfig.Node) (string, string, string, bool) {
	p := name

	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return "", "", "", false
	}

	pkg := p[i+len("node_modules/"):]
	if explicit, ok := n.Get("name").Text(); ok {
		pkg = explicit
	}

	v, ok := n.Get("version").Text()
	if !ok {
		return "", "", "", false
	}

	kind := npmLockSemantics(v, n.Get("resolved"))
	if n.Get("link") != nil {
		kind = report.VersionUnresolved
	}

	return pkg, v, kind, true
}

func collectNPMLockV1(ctx context.Context, n *jsonconfig.Node, depth int, add dependencyAdder) bool {
	if n == nil {
		return false
	}

	if depth > 32 || n.Kind != jsonconfig.KindObject {
		return true
	}

	partial := false

	for _, member := range n.Members {
		if ctx.Err() != nil {
			return true
		}

		version, ok := member.Value.Get("version").Text()
		if !ok {
			partial = true
			continue
		}

		kind := npmLockSemantics(version, member.Value.Get("resolved"))

		add(report.EcosystemNPM, member.Key, version, kind, member.Value, depth > 0)

		if collectNPMLockV1(ctx, member.Value.Get("dependencies"), depth+1, add) {
			partial = true
		}
	}

	return partial
}

func normalizePyPIName(s string) string {
	var out strings.Builder

	dash := false

	for _, r := range strings.ToLower(s) {
		if r == '_' || r == '.' || r == '-' {
			if !dash {
				out.WriteByte('-')
			}

			dash = true
		} else {
			out.WriteRune(r)

			dash = false
		}
	}

	return out.String()
}

func collectRequirements(ctx context.Context, doc document.File, out *report.DependencyReport) {
	mi := len(out.Manifests)
	out.Manifests = append(out.Manifests, report.DependencyManifest{
		Path:          doc.Artifact().Metadata().Path,
		Status:        report.OutcomeCompleted,
		Parser:        "pep508-constrained-lines",
		ParserVersion: "1",
	})
	raw := doc.Artifact().Content()
	offset := 0

	for _, line := range strings.SplitAfter(raw, "\n") {
		if ctx.Err() != nil {
			out.Manifests[mi].Status = report.OutcomeCancelled
			return
		}

		s := strings.TrimSpace(line)
		start := offset
		offset += len(line)

		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}

		parsed := parseRequirementLine(s)
		if parsed.partial {
			out.Manifests[mi].Status = report.OutcomePartial
		}

		if parsed.skip {
			continue
		}

		pkg, v, kind := parsed.name, parsed.version, parsed.kind

		if !appendDecl(out, doc, nil, report.EcosystemPyPI, normalizePyPIName(pkg), v, kind, source.Span{Start: start, End: offset}, false) {
			out.Manifests[mi].Status = report.OutcomePartial
			return
		}
	}
}

func parseRequirementLine(s string) requirementDeclaration {
	if strings.HasPrefix(s, "-") || strings.Contains(s, "\\") {
		return requirementDeclaration{partial: true, skip: true}
	}

	parts := requirement.FindStringSubmatch(s)
	if parts == nil {
		return requirementDeclaration{partial: true, skip: true}
	}

	suffix := strings.TrimSpace(s[len(parts[0]):])
	comment := strings.HasPrefix(suffix, "#")

	kind := report.VersionUnresolved
	if parts[2] == "==" && exactPyVersion.MatchString(parts[3]) && (suffix == "" || comment) {
		kind = report.VersionExactDeclaration
	}

	return requirementDeclaration{name: parts[1], version: parts[3], kind: kind, partial: suffix != "" && !comment}
}

// A different registry/source may serve different bytes for the same name/version.
// We do not query the public ecosystem database as if that origin were resolved.
func trustedNPMResolution(n *jsonconfig.Node) bool {
	if n == nil {
		return true
	} // Missing provenance is reported as a declaration, not attested installation.

	s, ok := n.Text()
	if !ok {
		return false
	}

	u, e := url.Parse(s)

	return e == nil && u.Scheme == "https" && u.Host == "registry.npmjs.org" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

func npmLockSemantics(version string, resolved *jsonconfig.Node) string {
	if exactNPM(version) && trustedNPMResolution(resolved) {
		return report.VersionExactLockfile
	}

	return report.VersionUnresolved
}
