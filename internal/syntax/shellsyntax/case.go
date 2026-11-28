package shellsyntax

const (
	codeDepthLimit             = "depth_limit"
	codeExpectedCaseIn         = "expected_case_in"
	codeExpectedCasePattern    = "expected_case_pattern"
	codeExpectedCasePatternEnd = "expected_case_pattern_end"
	codeExpectedCaseSelector   = "expected_case_selector"
	codeUnsupportedCaseHeader  = "unsupported_case_header"
)

func (p *parser) commandCase(c *Command) error {
	_, _ = p.take() // case

	selector, err := p.take()
	if err != nil {
		return err
	}

	if selector.kind != tokenWord {
		return p.fail(codeExpectedCaseSelector)
	}

	if caseHeaderHasSubstitution(selector.word) {
		return p.fail(codeUnsupportedCaseHeader)
	}

	in, err := p.skipNewlines()
	if err != nil {
		return err
	}

	if !p.keyword(in, "in") {
		return p.fail(codeExpectedCaseIn)
	}

	_, _ = p.take()

	if p.depth >= MaxDepth {
		return p.fail(codeDepthLimit)
	}

	// Keep the same token stream and pending heredocs across arm boundaries.
	p.depth++

	err = p.caseArms(c, &CaseSelection{Word: selector.word})
	p.depth--

	return err
}

func (p *parser) caseArms(c *Command, selection *CaseSelection) error {
	for {
		t, err := p.skipNewlines()
		if err != nil {
			return err
		}

		if p.keyword(t, keywordEsac) {
			_, _ = p.take()
			c.Span.End = t.span.End
			c.Case = selection
			// Include the path on which none of the patterns match.
			c.Alternatives = append(c.Alternatives, &File{})

			return nil
		}

		if t.kind == tokenOpenParen {
			_, _ = p.take()
		}

		patterns, err := p.casePatterns()
		if err != nil {
			return err
		}

		body, err := p.list(caseArmList)
		if err != nil {
			return err
		}

		selection.Patterns = append(selection.Patterns, patterns)
		c.Alternatives = append(c.Alternatives, body)

		t, _ = p.peek() // the arm list stops at ;; or esac
		if t.kind == tokenEndCase {
			_, _ = p.take()
		}
	}
}

func (p *parser) casePatterns() ([]*Word, error) {
	var patterns []*Word

	for {
		pattern, err := p.take()
		if err != nil {
			return nil, err
		}

		if pattern.kind != tokenWord {
			return nil, p.fail(codeExpectedCasePattern)
		}

		if caseHeaderHasSubstitution(pattern.word) {
			return nil, p.fail(codeUnsupportedCaseHeader)
		}

		patterns = append(patterns, pattern.word)

		end, err := p.take()
		if err != nil {
			return nil, err
		}

		switch end.kind {
		case tokenCloseParen:
			return patterns, nil
		case Pipe:
		default:
			return nil, p.fail(codeExpectedCasePatternEnd)
		}
	}
}

func (p *parser) caseArmEnd(t token, kind listKind) bool {
	return kind == caseArmList && (t.kind == tokenEndCase || p.keyword(t, keywordEsac))
}

func (p *parser) keyword(t token, text string) bool {
	return t.kind == tokenWord && p.text[t.span.Start:t.span.End] == text
}

func caseHeaderHasSubstitution(word *Word) bool {
	for _, part := range word.Parts {
		if part.Kind == PartSubstitution {
			return true
		}
	}

	return false
}
