// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified P5 instructional/educational/warning-context handling.

package analyzer

import (
	"regexp"
	"strings"
)

//nolint:gochecknoglobals // Immutable marker tables shared by concurrent scans.
var (
	harmfulSubstances         = regexp.MustCompile(`(?i)\b(?:cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx gas|mustard gas|anthrax|deadly nightshade|aconite|hemlock|oleander)\b`)
	harmfulInstructionMarkers = []string{"step ", "recipe", "ingredient", "add ", "mix ", "stir ", "instructions", "how to", "directions", "prepare", "cook", "bake"}
	harmfulEducationalMarkers = []string{"history of", "discovered by", "chemical compound", "periodic table", "forensic", "detective", "mystery", "agatha christie", "toxicology", "poison control", "symptoms of", "treatment for", "antidote", "emergency", "call 911", "warning", "danger", "never", "do not", "toxic", "lethal", "deadly", "fatal", "avoid", "keep away"}
)

func harmfulSubstanceExempt(text string, start, end int) bool {
	surrounding := strings.ToLower(text[max(0, start-250):min(len(text), end+250)])
	for _, marker := range harmfulInstructionMarkers {
		if strings.Contains(surrounding, marker) {
			return false
		}
	}

	for _, marker := range harmfulEducationalMarkers {
		if strings.Contains(surrounding, marker) {
			return true
		}
	}

	return false
}
