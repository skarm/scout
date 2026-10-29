// Package buildinfo reports module versions embedded in the running binary.
// It does not read go.mod or resolve dependencies at runtime.
package buildinfo

import (
	"runtime/debug"
	"sync"
)

//nolint:gochecknoglobals // Lazily caches immutable build metadata shared by all version lookups.
var currentBuildInfo = sync.OnceValue(func() *debug.BuildInfo {
	info, _ := debug.ReadBuildInfo()
	return info
})

// ModuleVersion returns the version of the named main or dependency module,
// following replacements. It preserves Go's version spelling, including the v
// prefix and pseudo-versions. Local modules without a version return "(devel)";
// missing modules or unavailable build metadata return "unknown".
func ModuleVersion(path string) string {
	return moduleVersion(currentBuildInfo(), path)
}

func moduleVersion(info *debug.BuildInfo, path string) string {
	if info == nil || path == "" {
		return "unknown"
	}

	if info.Main.Path == path {
		return resolvedVersion(&info.Main)
	}

	for _, dependency := range info.Deps {
		if dependency != nil && dependency.Path == path {
			return resolvedVersion(dependency)
		}
	}

	return "unknown"
}

func resolvedVersion(module *debug.Module) string {
	if module.Replace != nil {
		module = module.Replace
	}

	if module.Version == "" {
		return "(devel)"
	}

	return module.Version
}
