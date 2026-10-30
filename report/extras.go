package report

import (
	"fmt"
	"strconv"
	"strings"
)

func writeExtras(b *strings.Builder, r Analysis, evaluation Evaluation, md bool) {
	q := strconv.QuoteToASCII
	heading := "\nReview controls\n"

	if md {
		q = mdCode
		heading = "### Review controls\n\n"
	}

	b.WriteString(heading)

	if len(evaluation.Suppressed) != 0 {
		_, _ = fmt.Fprintf(b, "Operator-approved exemptions: %d. Findings are retained below.\n\n", len(evaluation.Suppressed))

		for _, s := range evaluation.Suppressed {
			_, _ = fmt.Fprintf(b, "Approved occurrence %s by %s entry %d until %s.\n\n", q(s.FindingID), q(s.Kind), s.EntryIndex, q(s.Expires))
		}
	}

	_, _ = fmt.Fprintf(b, "Metadata review: %s; %d parsed/candidate documents. Syntax does not establish runtime activation.\n\n", q(string(r.Metadata.Completeness)), len(r.Metadata.Files))

	for _, f := range r.Metadata.Files {
		_, _ = fmt.Fprintf(b, "Metadata %s (%s, %s): %s.\n\n", q(f.Path), q(f.Format), q(f.Status), q(strings.Join(f.Issues, ", ")))
	}

	writeSignatureExtras(b, r, q)
	writeRelatedExtras(b, r, q)
}

func writeSignatureExtras(b *strings.Builder, r Analysis, q func(string) string) {
	if r.Signatures.Enabled {
		_, _ = fmt.Fprintf(b, "YARA: %s; %d planned objects; rules %s. Engine absence is not a clean result.\n\n", q(r.Signatures.Completeness), len(r.Signatures.Outcomes), q(r.Signatures.RulesSHA256))

		for _, o := range r.Signatures.Outcomes {
			if o.Status != OutcomeCompleted || o.Truncated {
				_, _ = fmt.Fprintf(b, "YARA object %s: %s.\n\n", q(o.Path), q(o.Status))
			}
		}
	}
}

func writeRelatedExtras(b *strings.Builder, r Analysis, q func(string) string) {
	for _, f := range r.Findings {
		if len(f.RelatedEvidence) > 0 {
			_, _ = fmt.Fprintf(b, "Related captured evidence for %s (not a runtime flow):\n\n", q(f.ID))
		}

		for _, ref := range f.RelatedEvidence {
			_, _ = fmt.Fprintf(b, "%s bytes %d..%d, SHA256 %s.\n\n", q(ref.Path), ref.ByteStart, ref.ByteEnd, q(ref.SpanSHA256))
		}

		if len(f.SignatureNames) > 0 {
			_, _ = fmt.Fprintf(b, "YARA signature names for %s: %s.\n\n", q(f.ID), q(strings.Join(f.SignatureNames, ", ")))
		}
	}
}

func writeVulnerabilityExtras(b *strings.Builder, r Analysis, q func(string) string) {
	if !r.Vulnerabilities.Enabled {
		b.WriteString("Known-vulnerability lookup: disabled; no claim of CVE coverage.\n\n")
	} else {
		_, _ = fmt.Fprintf(b, "Known-vulnerability lookup: %s, completeness %s, queries %d, matches %d; query time %s.\n\n", q(r.Vulnerabilities.Source), q(string(r.Vulnerabilities.Completeness)), len(r.Vulnerabilities.Queries), len(r.Vulnerabilities.Matches), q(r.Vulnerabilities.QueriedAt))

		coordinates := make(map[string]string, len(r.Vulnerabilities.Queries))
		for _, query := range r.Vulnerabilities.Queries {
			coordinates[query.DependencyID] = query.DependencyID
			if query.Name != "" && query.Version != "" {
				coordinates[query.DependencyID] = query.Ecosystem + ":" + query.Name + "@" + query.Version
			}
		}

		for _, v := range r.Vulnerabilities.Matches {
			packages := make([]string, 0, len(v.DependencyIDs))
			for _, id := range v.DependencyIDs {
				label := coordinates[id]
				if label == "" {
					label = id
				}

				packages = append(packages, label)
			}

			_, _ = fmt.Fprintf(b, "Advisory %s matches captured exact coordinate(s) %s; not proof of exploitability.\n\n", q(v.ID), q(strings.Join(packages, ", ")))
		}

		for _, v := range r.Vulnerabilities.Queries {
			if v.Status != OutcomeCompleted && v.Status != OutcomeCached {
				_, _ = fmt.Fprintf(b, "Unchecked dependency %s: %s.\n\n", q(coordinates[v.DependencyID]), q(v.Status))
			}
		}
	}
}
