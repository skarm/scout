// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified from SkillSpector behavioral_ast AST10 and taint TT6 call sets.

package python

//nolint:gochecknoglobals // Read-only Python semantic classification tables are shared by scans.
var (
	pyUnsafeDeserializers = map[string]bool{
		"pickle.load":        true,
		"pickle.loads":       true,
		"cPickle.load":       true,
		"cPickle.loads":      true,
		"_pickle.load":       true,
		"_pickle.loads":      true,
		"marshal.load":       true,
		"marshal.loads":      true,
		"dill.load":          true,
		"dill.loads":         true,
		"jsonpickle.decode":  true,
		"pandas.read_pickle": true,
		"joblib.load":        true,
		"yaml.unsafe_load":   true,
	}
	pySafeYAMLLoaders = map[string]bool{"yaml.SafeLoader": true, "yaml.CSafeLoader": true, "yaml.BaseLoader": true}
)

// Safety decisions consume the arguments already evaluated by callExpression.
// Source-shape introspection must not reinterpret a resolved loader or flag.
func (w *pyWalker) unsafeDeserialization(call pyCall) bool {
	switch call.name {
	case "yaml.load":
		loader, _ := call.argument("Loader", 1)
		return !pySafeYAMLLoaders[loader.symbol()]
	case "torch.load":
		return call.keywords["weights_only"].truth != 2
	case "numpy.load":
		allow, present := call.argument("allow_pickle", 2)
		if present && allow.truth == 0 {
			w.limited = true
		}

		return allow.truth == 2
	default:
		return pyUnsafeDeserializers[call.name]
	}
}

func (call pyCall) argument(keyword string, position int) (pyValue, bool) {
	if value, present := call.keywords[keyword]; present {
		return value, true
	}

	if position < len(call.positional) {
		return call.positional[position], true
	}

	return pyValue{}, false
}
