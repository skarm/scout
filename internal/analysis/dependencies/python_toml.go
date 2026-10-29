package dependencies

import (
	"context"
	"strings"

	"github.com/skarm/scout/internal/syntax/language"

	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

type tomlCollector struct {
	ctx     context.Context
	doc     document.File
	out     *report.DependencyReport
	unit    document.Unit
	partial bool
}

// Collect only real TOML parser trees. References cover the enclosing unit
// because the selected decoder does not expose scalar positions. No includes are followed.
func collectPythonTOML(ctx context.Context, doc document.File, out *report.DependencyReport, name string) {
	u, root, status := manifestTree(doc, language.TOML)

	mi := len(out.Manifests)
	out.Manifests = append(out.Manifests, report.DependencyManifest{
		Path:          doc.Artifact().Metadata().Path,
		Status:        status,
		Parser:        u.ParserID,
		ParserVersion: u.ParserVersion,
	})

	if root == nil || root.Kind != jsonconfig.KindObject {
		return
	}

	c := tomlCollector{ctx: ctx, doc: doc, out: out, unit: u}

	switch name {
	case "pyproject.toml":
		c.pyproject(root)
	case "pipfile":
		c.pipfile(root)
	case "uv.lock", "poetry.lock":
		c.lock(root, name)
	}

	if c.partial {
		out.Manifests[mi].Status = report.OutcomePartial
	}

	if ctx.Err() != nil {
		out.Manifests[mi].Status = report.OutcomeCancelled
	}
}

func (c *tomlCollector) add(pkg, version, kind string, n *jsonconfig.Node, indirect bool) {
	if c.ctx.Err() != nil || n == nil || !appendDecl(c.out, c.doc, &c.unit, report.EcosystemPyPI, normalizePyPIName(pkg), version, kind, n.Span, indirect) {
		c.partial = true
	}
}

func (c *tomlCollector) requirement(n *jsonconfig.Node) {
	s, ok := n.Text()
	if !ok {
		c.partial = true
		return
	}

	s = strings.TrimSpace(s)

	m := requirement.FindStringSubmatch(s)
	if m == nil || m[1] == "" {
		c.partial = true
		return
	}

	kind := report.VersionUnresolved
	if m[2] == "==" && exactPyVersion.MatchString(m[3]) && len(m[0]) == len(s) {
		kind = report.VersionExactDeclaration
	} else {
		c.partial = true
	}

	c.add(m[1], m[3], kind, n, false)
}

func (c *tomlCollector) list(n *jsonconfig.Node) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindArray {
		c.partial = true
		return
	}

	for _, item := range n.Elements {
		c.requirement(item)
	}
}

func (c *tomlCollector) groupedLists(n *jsonconfig.Node) {
	if n == nil {
		return
	}

	if n.Kind != jsonconfig.KindObject {
		c.partial = true
		return
	}

	for _, member := range n.Members {
		c.list(member.Value)
	}
}

func (c *tomlCollector) pyproject(root *jsonconfig.Node) {
	project := root.Get("project")
	c.list(project.Get("dependencies"))
	c.groupedLists(project.Get("optional-dependencies"))
	c.groupedLists(root.Get("dependency-groups"))
	c.list(root.Get("build-system").Get("requires"))
	// Poetry constraints are not PEP 508 strings; retain unresolved coordinates.
	for _, table := range []*jsonconfig.Node{root.Get("tool").Get("poetry").Get("dependencies"), root.Get("tool").Get("poetry").Get("dev-dependencies")} {
		if table == nil {
			continue
		}

		if table.Kind != jsonconfig.KindObject {
			c.partial = true
			continue
		}

		for _, member := range table.Members {
			if member.Key == "python" {
				continue
			}

			version, ok := member.Value.Text()
			if !ok {
				version, _ = member.Value.Get("version").Text()
			}

			c.add(member.Key, version, report.VersionUnresolved, member.Value, false)
			c.partial = true
		}
	}

	if root.Get("tool").Get("poetry").Get("group") != nil {
		c.partial = true
	}
}

func (c *tomlCollector) pipfile(root *jsonconfig.Node) {
	for _, field := range []string{"packages", "dev-packages"} {
		table := root.Get(field)
		if table == nil {
			continue
		}

		if table.Kind != jsonconfig.KindObject {
			c.partial = true
			continue
		}

		for _, member := range table.Members {
			version, ok := member.Value.Text()
			if !ok {
				version, _ = member.Value.Get("version").Text()
			}

			kind := report.VersionUnresolved
			if ok && strings.HasPrefix(version, "==") && exactPyVersion.MatchString(strings.TrimPrefix(version, "==")) {
				kind, version = report.VersionExactDeclaration, strings.TrimPrefix(version, "==")
			} else {
				c.partial = true
			}

			c.add(member.Key, version, kind, member.Value, false)
		}
	}
}

func (c *tomlCollector) lock(root *jsonconfig.Node, name string) {
	packages := root.Get("package")
	if packages == nil || packages.Kind != jsonconfig.KindArray {
		c.partial = true
		return
	}

	for _, pkg := range packages.Elements {
		pn, ok := pkg.Get("name").Text()
		version, versionOK := pkg.Get("version").Text()

		if !ok {
			c.partial = true
			continue
		}

		kind := report.VersionUnresolved
		if versionOK && pythonRegistrySource(pkg.Get("source"), name) && exactPyVersion.MatchString(version) {
			kind = report.VersionExactLockfile
		} else {
			c.partial = true
		}

		c.add(pn, version, kind, pkg, true)
	}
}

func pythonRegistrySource(source *jsonconfig.Node, name string) bool {
	registry := true
	if name == "uv.lock" {
		_, registry = source.Get("registry").Text()
	} else if source != nil {
		kind, _ := source.Get("type").Text()
		registry = kind == "legacy" || kind == "index"
	}

	if source != nil {
		address, _ := source.Get("registry").Text()
		if address == "" {
			address, _ = source.Get("url").Text()
		}

		if address != "" && address != "https://pypi.org/simple" && address != "https://pypi.org/simple/" {
			registry = false
		}
	}

	return registry
}
