// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted from SkillSpector static_yara per-instance ransomware exclusions.

package signatures

import (
	"bytes"
	"regexp"
)

var (
	ransomwareStorage  = regexp.MustCompile(`(?i)^[\t ]+(?:at[\t ]+rest|in[\t ]+transit)\b`)
	ransomwarePayment  = regexp.MustCompile(`(?i)\b(?:pay|send)\b`)
	ransomwareMinimum  = regexp.MustCompile(`(?i)^(?:pay|send)[\t ]{1,8}(?:(?:anything|any[\t ]{1,8}amount)[\t ]{1,8})?(?:less|fewer)[\t ]{1,8}than\b`)
	ransomwareNegation = regexp.MustCompile(`(?i)^[\t ]*(?:(?:[-*+>]|[0-9]{1,3}[.)])[\t ]+){0,3}(?:["'(\[]|‘|“)?[*_]{0,2}(?:you[\t ]+(?:(?:should|must)[\t ]+)?)?(?:never|do[\t ]+not|don't|don’t|must[\t ]+not|should[\t ]+not|avoid)[*_]{0,2}(?:[\t ]+ever)?[\t ]+$`)
)

func negatedRansomwarePayment(data []byte, at int) bool {
	start := max(0, at-80)
	// Preserve the actual clause boundary: a clipped window is not a beginning.
	boundary := bytes.LastIndexAny(data[start:at], "\r\n.;:!?,")
	if boundary >= 0 {
		start += boundary + 1
	} else if start > 0 {
		return false
	}

	return ransomwareNegation.Match(data[start:at]) && !ransomwareMinimum.Match(data[at:min(len(data), at+80)])
}

func acceptRansomwareInstance(identifier string, data []byte, start, end int) bool {
	if identifier == "$ransom_note" && ransomwareStorage.Match(data[end:min(len(data), end+81)]) {
		return false
	}

	switch identifier {
	case "$payment_then_context", contextPaymentPattern, "$explicit_ransom_payment":
		payments := ransomwarePayment.FindAllIndex(data[start:end], -1)
		if identifier != contextPaymentPattern && len(payments) > 1 {
			payments = payments[:1]
		}

		for _, p := range payments {
			if !negatedRansomwarePayment(data, start+p[0]) {
				return true
			}
		}

		return len(payments) == 0
	}

	return true
}
