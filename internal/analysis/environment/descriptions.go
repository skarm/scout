// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package environment

import (
	"strings"
	"unicode"

	"github.com/skarm/scout/report"
)

// The Jaccard matcher and English stop words are adapted from Cisco
// skill-scanner's scanner.py. Scout tokenizes Unicode letter words.
//
//nolint:gosec // This literal is a public English stop-word list.
const descriptionStopWords = " the a an is are was were be been being have has had do does did will would could should can may might must shall to of in for on with at by from as into through and or but if then else when up down out that this these those it its they them their "

type skillDescription struct {
	fact  fact
	words map[string]struct{}
}

func descriptionWords(value string) map[string]struct{} {
	words := map[string]struct{}{}

	for word := range strings.FieldsFuncSeq(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsNumber(r) && r != '_'
	}) {
		valid := true

		for _, r := range word {
			if !unicode.IsLetter(r) && !unicode.IsMark(r) {
				valid = false
				break
			}
		}

		if valid && !strings.Contains(descriptionStopWords, " "+word+" ") {
			words[word] = struct{}{}
		}
	}

	return words
}

func (b *builder) relateDescriptions(descriptions []skillDescription, unknown int) {
	if unknown > 0 && len(descriptions)+unknown > 1 {
		b.issue("skill_description_context_incomplete")
	}

	for i, left := range descriptions {
		for _, right := range descriptions[i+1:] {
			if !b.step() {
				return
			}

			if left.fact.target == right.fact.target && left.fact.Source.Path == right.fact.Source.Path {
				continue
			}

			small, large := left.words, right.words

			if len(small) > len(large) {
				small, large = large, small
			}

			if 2*len(small) <= len(large) {
				continue
			}

			if !b.spend(uint64(len(small))) {
				return
			}

			if basisPoints := descriptionSimilarity(small, large); basisPoints != 0 {
				b.emitRelationship(report.EnvironmentSkillDescriptionOverlap, left.fact, right.fact, basisPoints)
			}
		}
	}
}

func descriptionSimilarity(small, large map[string]struct{}) int {
	shared, remaining := 0, len(small)
	// Jaccard > 1/2 requires 3*shared > len(small)+len(large).
	required := (len(small)+len(large))/3 + 1

	for word := range small {
		remaining--

		if _, exists := large[word]; exists {
			shared++
		}

		if shared+remaining < required {
			return 0
		}
	}

	union := len(small) + len(large) - shared

	return (report.DescriptionSimilarityScale*shared + union/2) / union
}
