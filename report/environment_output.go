package report

import (
	"bytes"
	"fmt"
	"strconv"
)

func writeEnvironment(out *bytes.Buffer, environment *EnvironmentReport, md bool) {
	if environment == nil {
		return
	}

	quote := strconv.QuoteToASCII
	if md {
		quote = mdCode

		out.WriteString("## Selected environment\n\n")
	}

	_, _ = fmt.Fprintf(out, "Environment analysis: %s; observations: %d.\n\n", quote(string(environment.Completeness)), len(environment.Observations))
	out.WriteString("These are captured declarations and capability combinations. Runtime activation and cross-component data flow are not established.\n\n")

	for _, observation := range environment.Observations {
		_, _ = fmt.Fprintf(out, "Environment observation %s: %s.\n", quote(observation.ID), quote(observation.Kind))
		for _, ref := range observation.Evidence {
			_, _ = fmt.Fprintf(out, "- %s: target %s, %s, bytes %d..%d; span SHA-256 %s.\n", quote(ref.Role), quote(ref.TargetID), quote(ref.Source.Path), ref.Source.ByteStart, ref.Source.ByteEnd, quote(ref.Source.SpanSHA256))
		}

		out.WriteString("\n")
	}

	for _, issue := range environment.Issues {
		_, _ = fmt.Fprintf(out, "Environment gap: %s.\n", quote(issue))
	}

	for _, limitation := range environment.Limitations {
		_, _ = fmt.Fprintf(out, "%s\n\n", quote(limitation))
	}
}
