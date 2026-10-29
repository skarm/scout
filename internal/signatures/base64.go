package signatures

const (
	metadataPoisoningRule = "agent_skill_mcp_tool_poisoning_metadata"
	longBase64Global      = "scout_long_base64"
	longBase64Minimum     = 120
	// YARA-X 1.22's regex VM stops before ingesting byte 4096. Preserve
	// its greedy match lengths, including up to two trailing padding bytes.
	longBase64MatchLimit = 4095
)

// longBase64Spans evaluates /[A-Za-z0-9+\/]{120,}={0,2}/ in one pass.
// The built-in rule only tests its existence; no count/offset expression
// depends on the full match list. Nine witnesses suffice to reproduce the
// report's eight-span limit and its truncation flag, without materializing
// every overlapping suffix of a long run. This specialization does not apply
// to operator-provided rules.
func longBase64Spans(data []byte) []Span {
	var spans []Span

	for at := 0; at < len(data); {
		if !base64Byte(data[at]) {
			at++
			continue
		}

		start := at
		for at < len(data) && base64Byte(data[at]) {
			at++
		}

		end := at
		for end < len(data) && end < at+2 && data[end] == '=' {
			end++
		}

		for pos := start; pos <= at-longBase64Minimum; pos++ {
			if spans == nil {
				spans = make([]Span, 0, 9)
			}

			spans = append(spans, Span{Start: pos, End: min(end, pos+longBase64MatchLimit)})
			if len(spans) == 9 {
				return spans
			}
		}
	}

	return spans
}

func base64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/'
}
