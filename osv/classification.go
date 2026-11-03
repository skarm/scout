package osv

import (
	"errors"
	"time"

	"github.com/skarm/scout/internal/syntax/jsonconfig"
	"github.com/skarm/scout/report"
)

// Online querybatch answers have no trusted malware classification. Preserve
// their positive vulnerability matches while leaving this selected coverage gap.
func markClassificationGaps(r *report.VulnerabilityReport) {
	if !r.ClassifiedCache {
		return
	}

	for i := range r.Queries {
		if r.Queries[i].Status == report.OutcomeCompleted {
			r.Queries[i].Status = "classification_not_cached"
			r.Completeness = report.Partial
		}
	}
}

func validateCachedMetadata(v ID, cache Cache) error {
	if cache.Version == 1 && (v.Kind != "" || v.Source != (report.AdvisorySource{})) {
		return errors.New("classified advisories require cache version 2")
	}

	metadata := report.Vulnerability{Kind: v.Kind, Source: v.Source, DatabaseModified: v.Modified}
	if err := metadata.ValidateMetadata(); err != nil {
		return err
	}

	if v.Kind == report.AdvisoryMaliciousPackage {
		modified, _ := time.Parse(time.RFC3339, v.Modified)
		if modified.After(cache.QueriedAt) {
			return errors.New("advisory modification time exceeds cache query time")
		}
	}

	return nil
}

func validCacheMetadataShape(root *jsonconfig.Node, version int) bool {
	for _, record := range root.Get("records").Elements {
		values := record.Get("vulnerabilities")
		if values == nil || values.Kind != jsonconfig.KindArray {
			return false
		}

		for _, v := range values.Elements {
			kind, source := v.Get("kind"), v.Get("source")
			if version == 1 && (kind != nil || source != nil) {
				return false
			}

			if kind != nil && (kind.Kind != jsonconfig.KindString || kind.String != "vulnerability" && kind.String != report.AdvisoryMaliciousPackage) {
				return false
			}

			if source != nil && !validCacheSourceShape(source) {
				return false
			}
		}
	}

	return true
}

func validCacheSourceShape(source *jsonconfig.Node) bool {
	if source.Kind != jsonconfig.KindObject {
		return false
	}

	for _, key := range []string{"name", "url", "revision"} {
		value, ok := source.Get(key).Text()
		if !ok || value == "" {
			return false
		}
	}

	return true
}
