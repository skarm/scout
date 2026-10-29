package check

import "github.com/skarm/scout/internal/analysis/document"

// FileLanguageFacts contains bounded observations produced once for a file.
type FileLanguageFacts struct {
	Rules map[string]*Facts
}

// LanguageFacts belongs to one preparation phase and is immutable after binding.
type LanguageFacts map[string]*FileLanguageFacts

// LanguageConsumer projects immutable facts without rewalking prepared syntax.
type LanguageConsumer interface {
	Analyzer
	WithLanguageFacts(LanguageFacts) Analyzer
}

// NewFileLanguageFacts creates a file's observations with a separate limit per rule.
func NewFileLanguageFacts(limits map[string]int) *FileLanguageFacts {
	f := &FileLanguageFacts{Rules: map[string]*Facts{}}
	for id, limit := range limits {
		f.Rules[id] = NewFacts(limit)
	}

	return f
}

func (f LanguageFacts) Result(doc document.File, id string, limit int) (Result, error) {
	v := f[doc.Artifact().Metadata().Path]
	if v == nil {
		return Result{}, nil
	}

	return v.Rules[id].Result(limit)
}
