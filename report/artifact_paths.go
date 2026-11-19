package report

const (
	// ObjectScheme identifies a virtual object extracted from captured bytes.
	ObjectScheme = "scout-object"
	// ObjectPathPrefix is the prefix used for extracted objects in the artifact inventory.
	ObjectPathPrefix = ObjectScheme + "://"
)

const (
	// MaxArtifactEntries bounds captured and extracted inventory entries.
	MaxArtifactEntries = 100000
	// MaxArtifactPathBytes bounds an inventory path in bytes.
	MaxArtifactPathBytes = 4096
	// MaxArtifactPathDepth bounds path components admitted by capture and ZIP validation.
	MaxArtifactPathDepth = 128
)
