// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Fixed lexical guards adapted from the corresponding detector expressions.

package shell

import "strings"

func pythonModuleCommand(s string) bool {
	return s == "python" || strings.HasPrefix(s, "python3")
}

func pythonConfigIndexKey(s string) bool {
	return strings.HasSuffix(s, ".index-url") || strings.HasSuffix(s, ".extra-index-url")
}

func removalBroadTarget(s string) bool {
	return s == "*" || s == "/*" || s == "~" || strings.HasPrefix(s, "~/")
}

func stringSet(text string) map[string]bool {
	m := map[string]bool{}
	for s := range strings.FieldsSeq(text) {
		m[s] = true
	}

	return m
}
