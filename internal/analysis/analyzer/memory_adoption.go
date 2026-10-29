// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Bounded state-adoption grammar adapted from SkillSpector MP3.

package analyzer

import (
	"context"
	"regexp"
)

var (
	adoptionStart  = regexp.MustCompile(`(?i)\b(?:treat|consider|regard|use|adopt)\s+(?:(?:the|this|that)\s+)?(?:reset\s+)?[\[(*_'"]{0,4}state\b`)
	adoptionTarget = regexp.MustCompile(`(?i)\bas\s+(?:your\s+(?:(?:conversation|chat|dialogue)(?:\s+(?:state|history|context|transcript))?|memory)|(?:the\s+)?(?:agent|assistant|llm|(?:ai|language)\s+model)(?:'s|’s)\s+(?:conversation|chat|dialogue|memory|context|state|history|transcript))\b`)
)

var adoptionSentenceBreak = regexp.MustCompile(`[.!?](?:[\s\v\p{Z}\x{85}]|$)`)

func memoryAdoptions(ctx context.Context, text string, emit func(int, int) bool) bool {
	starts := adoptionStart.FindAllStringIndex(text, 65537)

	limited := len(starts) > 65536
	if limited {
		starts = starts[:65536]
	}

	for i, at := range starts {
		if ctx.Err() != nil {
			return true
		}

		bound := min(len(text), at[1]+512)
		if i+1 < len(starts) {
			bound = min(bound, starts[i+1][0])
		}

		tail := text[at[1]:bound]
		tail = adoptionSentence(tail)

		target := adoptionTarget.FindStringIndex(tail)
		if target == nil {
			continue
		}

		end := at[1] + target[1]
		if directlyProhibited(text, at[0], end) {
			continue
		}

		if !emit(at[0], end) {
			return true
		}
	}

	return limited
}

func adoptionSentence(tail string) string {
	if boundaries := paragraphBoundaries(tail); len(boundaries) > 0 {
		tail = tail[:boundaries[0][0]]
	}

	if boundary := adoptionSentenceBreak.FindStringIndex(tail); boundary != nil {
		tail = tail[:boundary[0]]
	}

	return tail
}
