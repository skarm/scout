package jsonconfig

// Node kinds describe JSON-shaped configuration values, including YAML/TOML projections.
const (
	// KindObject identifies object.
	KindObject = "object"
	// KindArray identifies array.
	KindArray = "array"
	// KindString identifies string.
	KindString = "string"
	// KindBool identifies bool.
	KindBool = "bool"
	// KindNumber identifies number.
	KindNumber = "number"
	// KindNull identifies null.
	KindNull = "null"
)
