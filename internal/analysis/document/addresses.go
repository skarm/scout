package document

import (
	"strings"

	"github.com/skarm/scout/internal/capture/artifact"
	"github.com/skarm/scout/report"
)

// Address identifies a file by namespace and recorded name within captured data.
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
		if !strings.HasPrefix(name, report.ObjectPathPrefix) {
			addresses[name] = Address{Namespace: artifact.RootNamespace, Name: name}
		}
	}

	for _, object := range extraction.Objects {
		if object.Role == "archive_member" {
			addresses[object.File.Path] = Address{Namespace: artifact.ArchiveNamespace(object.ParentPath), Name: object.MemberName}
		}
	}

	return addresses
}
