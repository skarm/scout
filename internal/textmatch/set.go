// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

package textmatch

import "strings"

// WordSet builds a membership lookup from whitespace-separated words.
func WordSet(text string) map[string]bool {
	m := map[string]bool{}
	for s := range strings.FieldsSeq(text) {
		m[s] = true
	}

	return m
}
