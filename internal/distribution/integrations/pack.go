// Package integrations ships installable reviewer assets. It does not install,
// activate, execute, or fetch code. The scanner's native capabilities are separate.
package integrations

import (
	"archive/zip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/skarm/scout/internal/distribution/skills"
	"github.com/skarm/scout/knowledge"
	"github.com/skarm/scout/report"
)

const (
	bundleReviewMaterials = "review-materials"
	skillsPrefix          = "skills/"
)

const
// Version identifies the compiled reviewer-transfer pack rather than a
// required Scout binary version.
version = "scout-reviewer-transfer-v4"

//go:embed assets sources
var assets embed.FS

//nolint:gochecknoglobals // The bundle table is immutable embedded-asset metadata shared by exports.
var bundleSpecs = map[string]bundleSpec{
	"agent-skill": {},
	report.HostClaudeCode: {
		skillPrefix: skillsPrefix,
		assets: []bundleAsset{{
			path:  ".claude-plugin/plugin.json",
			asset: "assets/claude/plugin.json",
		}},
	},
	report.HostCodex: {
		skillPrefix: skillsPrefix,
		assets: []bundleAsset{{
			path:  ".codex-plugin/plugin.json",
			asset: "assets/codex/plugin.json",
		}},
	},
	"pi": {
		skillPrefix: skillsPrefix,
		assets: []bundleAsset{{
			path:  "package.json",
			asset: "assets/pi/package.json",
		}, {
			path:  "extensions/scout.ts",
			asset: "assets/pi/scout.ts",
		}, {
			path:  "extensions/lib/runner.mjs",
			asset: "assets/shared/runner.mjs",
		}, {
			path:  "extensions/lib/adapters.mjs",
			asset: "assets/shared/adapters.mjs",
		}},
	},
	"opencode": {
		skillPrefix: ".opencode/skills/",
		assets: []bundleAsset{{
			path:  ".opencode/package.json",
			asset: "assets/opencode/package.json",
		}, {
			path:  ".opencode/tools/scout_scan.ts",
			asset: "assets/opencode/scout_scan.ts",
		}, {
			path:  ".opencode/commands/scout.md",
			asset: "assets/opencode/scout.md",
		}, {
			path:  ".opencode/lib/scout/runner.mjs",
			asset: "assets/shared/runner.mjs",
		}, {
			path:  ".opencode/lib/scout/adapters.mjs",
			asset: "assets/shared/adapters.mjs",
		}},
	},
	bundleReviewMaterials: {skillPrefix: skillsPrefix},
}

// File contains one trusted embedded bundle entry. Callers own its returned
// bytes.
type file struct {
	// Path is the safe slash-separated destination path within the ZIP archive.
	Path string
	// Data contains a detached copy of the entry bytes.
	Data []byte
}

// Entry records one packaged file identity in the exported manifest.
type entry struct {
	// Path is the entry path within the standalone bundle.
	Path string `json:"path"`
	// Bytes is the complete entry size in bytes.
	Bytes int `json:"bytes"`
	// SHA256 is the lowercase hexadecimal digest of the entry bytes.
	SHA256 string `json:"sha256"`
}

// Manifest identifies a standalone bundle and all packaged entries except the
// manifest itself.
type Manifest struct {
	// SchemaVersion identifies the bundle-manifest schema.
	SchemaVersion int `json:"schema_version"`
	// Version identifies the compiled reviewer-transfer pack revision.
	Version string `json:"version"`
	// Bundle names the selected installation layout.
	Bundle string `json:"bundle"`
	// SHA256 binds the packaged entry inventory without attesting authorship.
	SHA256 string `json:"sha256"`
	// Files lists every packaged entry except .scout-bundle.json itself.
	Files []entry `json:"files"`
	// Scope states the limits of the inventory and transfer claims.
	Scope string `json:"scope"`
}

type (
	bundleAsset struct{ path, asset string }
	bundleSpec  struct {
		skillPrefix string
		assets      []bundleAsset
	}
)

type skillBundleCollector struct {
	prefix string
	files  []file
}

// Names returns a fresh list; callers cannot modify subsequent exports.
func Names() []string {
	return []string{"agent-skill", report.HostClaudeCode, report.HostCodex, "pi", "opencode", bundleReviewMaterials}
}

// Files returns a detached standalone bundle with English and Russian
// instructions, licenses and transfer metadata. It does not install files or
// consult target configuration.
func Files(name string) ([]file, error) {
	spec, ok := bundleSpecs[name]
	if !ok {
		return nil, errors.New("unknown integration bundle")
	}

	out, err := skillBundle(spec.skillPrefix)
	if err != nil {
		return nil, err
	}

	assets := append([]bundleAsset{{path: "README.md", asset: "assets/README.md"}, {
		path:  "README.ru.md",
		asset: "assets/README.ru.md",
	}, {
		path:  "NOTICE",
		asset: "assets/NOTICE",
	}, {
		path:  "LICENSE",
		asset: "assets/LICENSE",
	}, {
		path:  "transfer-manifest.json",
		asset: "sources/transfer-manifest.json",
	}, {
		path:  spec.skillPrefix + "skill-inspector/NOTICE",
		asset: "assets/NOTICE",
	}, {
		path:  spec.skillPrefix + "skill-inspector/LICENSE",
		asset: "assets/LICENSE",
	}}, spec.assets...)
	for _, asset := range assets {
		out = append(out, file{Path: asset.path, Data: content(asset.asset)})
	}

	if name == bundleReviewMaterials {
		generated, err := reviewMaterials()
		if err != nil {
			return nil, err
		}

		out = append(out, generated...)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })

	if err := validateBundleFiles(out); err != nil {
		return nil, err
	}

	return out, nil
}

// Inventory returns the deterministic manifest for a named standalone bundle,
// without writing or installing it.
func Inventory(name string) (Manifest, error) {
	files, e := Files(name)
	if e != nil {
		return Manifest{}, e
	}

	return inventory(name, files), nil
}

// WriteZIP emits a deterministic, non-executable archive of trusted embedded bytes.
// It does not mutate a user's installed extensions. File publication is the caller's job.
func WriteZIP(w io.Writer, name string) error {
	if w == nil {
		return errors.New("writer required")
	}

	files, err := Files(name)
	if err != nil {
		return err
	}

	b, err := json.MarshalIndent(inventory(name, files), "", "  ")
	if err != nil {
		return err
	}

	files = append(files, file{Path: ".scout-bundle.json", Data: append(b, '\n')})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	z := zip.NewWriter(w)

	for _, f := range files {
		h := &zip.FileHeader{Name: f.Path, Method: zip.Deflate}
		h.Modified = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
		h.SetMode(0o644)

		dst, e := z.CreateHeader(h)
		if e != nil {
			_ = z.Close()
			return e
		}

		if _, e = dst.Write(f.Data); e != nil {
			_ = z.Close()
			return e
		}
	}

	return z.Close()
}

func (c *skillBundleCollector) visit(path string, entry fs.DirEntry, err error) error {
	if err != nil {
		return err
	}

	if entry.IsDir() {
		return nil
	}

	data, err := skills.Files.ReadFile(path)
	if err != nil {
		return err
	}

	c.files = append(c.files, file{Path: c.prefix + path, Data: data})

	return nil
}

func skillBundle(prefix string) ([]file, error) {
	collector := skillBundleCollector{prefix: prefix}
	err := fs.WalkDir(skills.Files, "skill-inspector", collector.visit)

	return collector.files, err
}

func reviewMaterials() ([]file, error) {
	data, err := json.MarshalIndent(knowledge.Export(), "", "  ")
	if err != nil {
		return nil, err
	}

	out := []file{{Path: "validation/pack.json", Data: append(data, '\n')}}

	for _, mode := range knowledge.Modes() {
		prompt, err := knowledge.Prompt(mode)
		if err != nil {
			return nil, err
		}

		out = append(out, file{Path: "validation/prompts/" + mode + ".md", Data: []byte(prompt)})
	}

	return out, nil
}

func validateBundleFiles(files []file) error {
	for i, file := range files {
		if !fs.ValidPath(file.Path) || strings.Contains(file.Path, "\\") || i > 0 && files[i-1].Path == file.Path {
			return errors.New("invalid compiled bundle path")
		}
	}

	return nil
}

func content(name string) []byte {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic("missing compiled integration asset: " + name)
	}

	return b
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func inventory(name string, files []file) Manifest {
	m := Manifest{
		SchemaVersion: 1,
		Version:       version,
		Bundle:        name,
		Files:         []entry{},
		Scope:         "Packaged adapted reviewer assets, not native-engine acceptance, upstream identity or installation authorization.",
	}
	for _, f := range files {
		m.Files = append(m.Files, entry{Path: f.Path, Bytes: len(f.Data), SHA256: digest(f.Data)})
	}

	data, _ := json.Marshal(m.Files)
	m.SHA256 = digest(data)

	return m
}
