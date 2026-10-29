// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Fixed lexical guards adapted from the corresponding detector expressions.

package analyzer

import "strings"

func completeQuotes(s string) bool {
	for at := 0; at < len(s); {
		quote := s[at]
		if quote != '\'' && quote != '"' {
			at++
			continue
		}

		end := strings.IndexByte(s[at+1:], quote)
		if end < 0 {
			return false
		}

		at += end + 2
	}

	return true
}

func regexpKeywordStart(s string) int {
	for _, word := range []string{"return", "throw", "case"} {
		if strings.HasSuffix(s, word) {
			return len(s) - len(word)
		}
	}

	return -1
}

func paddingDelimiter(s string) bool {
	s = strings.Trim(s, "\t ")
	s = strings.TrimSuffix(strings.TrimPrefix(s, ":"), ":")

	return s != "" && strings.Trim(s, "-") == ""
}

func requirementsSourceFlag(s string) bool {
	return strings.Contains(s, "--index-url") || strings.Contains(s, "--extra-index-url") || strings.Contains(s, "--find-links") || strings.HasPrefix(s, "-i ") || strings.HasPrefix(s, "-f ")
}

func sourceConfigComment(s string) bool {
	return strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";")
}
