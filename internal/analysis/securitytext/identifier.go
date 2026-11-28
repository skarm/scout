// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0

package securitytext

import (
	"strings"
	"unicode"
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var invisibleControls = &unicode.RangeTable{R16: []unicode.Range16{
	{Lo: 0x200b, Hi: 0x200d, Stride: 1}, {Lo: 0x202a, Hi: 0x202e, Stride: 1}, {Lo: 0x2066, Hi: 0x2069, Stride: 1}, {
		Lo:     0xfeff,
		Hi:     0xfeff,
		Stride: 1,
	},
}}

// HasInvisibleControls reports selected zero-width or bidirectional controls.
func HasInvisibleControls(text string) bool {
	return strings.ContainsFunc(text, func(char rune) bool { return unicode.Is(invisibleControls, char) })
}

// ConfusingIdentifier reports hidden controls or mixed Latin and Cyrillic/Greek letters.
func ConfusingIdentifier(s string) bool {
	if HasInvisibleControls(s) {
		return true
	}

	latin, other := false, false

	for _, r := range s {
		if unicode.In(r, unicode.Latin) {
			latin = true
		}

		if unicode.In(r, unicode.Cyrillic, unicode.Greek) {
			other = true
		}
	}

	return latin && other // Natural-language non-Latin descriptions are not identifiers.
}
