package semantic

import (
	"github.com/skarm/scout/report"
	"github.com/skarm/scout/review"
)

type sourceObject struct{ path, sha256 string }

// evidenceIndex preserves excerpt order within an object and the first exact
// reference. Graph links need containment; verification needs exact identity.
type evidenceIndex struct {
	objects    map[sourceObject][]review.Excerpt
	exact      map[report.SourceRef]review.Citation
	components map[string]bool
}

func indexEvidence(excerpts []review.Excerpt) evidenceIndex {
	index := evidenceIndex{
		objects:    map[sourceObject][]review.Excerpt{},
		exact:      map[report.SourceRef]review.Citation{},
		components: map[string]bool{},
	}

	for _, ex := range excerpts {
		key := sourceObject{path: ex.Path, sha256: ex.ObjectSHA256}
		index.objects[key] = append(index.objects[key], ex)

		ref := sourceRef(ex)
		if _, exists := index.exact[ref]; !exists {
			index.exact[ref] = review.Citation{ExcerptID: ex.ID, SHA256: ex.SHA256}
		}

		for _, id := range ex.Components {
			index.components[id] = true
		}
	}

	return index
}

func (index evidenceIndex) containing(ref report.SourceRef) []review.Citation {
	for _, ex := range index.objects[sourceObject{path: ref.Path, sha256: ref.SHA256}] {
		if ex.ByteStart <= ref.ByteStart && ex.ByteEnd >= ref.ByteEnd {
			return []review.Citation{{ExcerptID: ex.ID, SHA256: ex.SHA256}}
		}
	}

	return nil
}
