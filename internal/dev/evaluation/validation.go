package evaluation

import (
	"errors"
	"io/fs"
	"slices"
)

func (c Corpus) validate() error {
	if c.SchemaVersion != 1 || !slices.Contains([]string{"authored_regression_not_holdout", "independent_labelled_corpus"}, c.Kind) || len(c.Cases) == 0 || len(c.Cases) > 4096 {
		return errors.New("invalid corpus identity or case count")
	}

	ids := map[string]bool{}
	for _, value := range c.Cases {
		if ids[value.ID] {
			return errors.New("invalid or duplicate case")
		}

		if err := value.validate(); err != nil {
			return err
		}

		ids[value.ID] = true
	}

	return nil
}

func (c Case) validate() error {
	if c.ID == "" || len(c.ID) > 128 || c.Category == "" || len(c.Category) > 128 || !fs.ValidPath(c.Path) || len(c.Path) > 1024 {
		return errors.New("invalid or duplicate case")
	}

	if !slices.Contains([]string{"signal", "benign", "ambiguous", "known_static_gap"}, c.Label) {
		return errors.New("invalid case label")
	}

	return nil
}
