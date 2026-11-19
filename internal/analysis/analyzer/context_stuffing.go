// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Bounded equivalent of MP2's short-phrase backreference (RE2 has no backrefs).

package analyzer

import (
	"context"
	"unicode"
)

// A repetition records its period and source offsets; the scanner updates one
// start boundary while flush applies the same length/meaningfulness grammar.
type contextRepetition struct {
	runes         []rune
	offsets       []int
	start, period int
	emit          func(int, int) bool
}

const (
	minContextPayloadBytes = 256
	textScanCheckBytes     = 4096
)

func repeatedContext(ctx context.Context, text string, emit func(int, int) bool) bool {
	runes := []rune(text)

	// Single-byte runes already use byte offsets, including invalid UTF-8 bytes.
	var offsets []int
	if len(runes) != len(text) {
		offsets = make([]int, 0, len(runes)+1)
		for at := range text {
			offsets = append(offsets, at)
		}

		offsets = append(offsets, len(text))
	}

	for period := 2; period <= min(20, len(runes)/21); period++ {
		repetition := contextRepetition{runes: runes, offsets: offsets, period: period, emit: emit}

		for i := period; i < len(runes); i++ {
			if i%textScanCheckBytes == 0 && ctx.Err() != nil {
				return true
			}

			if runes[i] == '\n' || runes[i] != runes[i-period] {
				if !repetition.flush(i) {
					return true
				}

				repetition.start = i - period + 1
			}
		}

		if !repetition.flush(len(runes)) {
			return true
		}
	}

	return false
}

func (r contextRepetition) flush(end int) bool {
	if end-r.start < r.period*21 {
		return true
	}

	meaningful := end-r.start > minContextPayloadBytes
	for _, char := range r.runes[r.start:min(end, r.start+r.period)] {
		meaningful = meaningful || unicode.IsLetter(char) || unicode.IsDigit(char)
	}

	if !meaningful {
		return true
	}

	start := r.start
	if r.offsets != nil {
		start, end = r.offsets[start], r.offsets[end]
	}

	return r.emit(start, end)
}
