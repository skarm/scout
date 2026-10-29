// Package skills embeds the installable reviewer skill, not scanner test inputs.
package skills

import "embed"

// Files contains the independently usable skill and its progressive references.
// The exported embed.FS is read-only; callers receive their own byte slices.
//
//go:embed skill-inspector
var Files embed.FS
