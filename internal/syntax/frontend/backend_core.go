//go:build coreonly

package frontend

import "context"

// BackendFor reports the reduced core build, which contains no parser substitutes. It is
// used for offline core tests, never advertised as a full native release.
func BackendFor(format string) Backend {
	return Backend{Format: format, Name: "not-linked", Version: "0", Reason: "coreonly build excludes embedded parsers"}
}

func parsePython(context.Context, string) (*Node, error) {
	return nil, &Failure{Category: "unavailable"}
}

func parseYAML(context.Context, string) (*ConfigNode, error) {
	return nil, &Failure{Category: "unavailable"}
}

func parseTOML(context.Context, string) (*ConfigNode, error) {
	return nil, &Failure{Category: "unavailable"}
}
