package document

import (
	"strings"

	"github.com/skarm/scout/report"
)

// Address identifies a file within a captured snapshot or container. Names and
// namespaces retain their recorded spelling; this model does not resolve paths.
type Address struct {
	Namespace string
	Name      string
}

// CapturedAddresses assigns snapshot paths and declared archive-member
// coordinates to their captured file paths. Other derived objects have no
// ambient snapshot address. Extractor-specific trust remains a consumer policy.
func CapturedAddresses(docs []File, extraction report.ExtractionReport) map[string]Address {
	addresses := map[string]Address{}

	for _, doc := range docs {
		name := doc.Artifact().Metadata().Path
		if !strings.HasPrefix(name, "scout-object://") {
			addresses[name] = Address{Namespace: "snapshot", Name: name}
		}
	}

	for _, object := range extraction.Objects {
		if object.Role == "archive_member" {
			addresses[object.File.Path] = Address{Namespace: object.ParentPath, Name: object.MemberName}
		}
	}

	return addresses
}
