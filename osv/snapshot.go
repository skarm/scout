package osv

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/skarm/scout/report"
)

const (
	// MaxSnapshotBytes bounds one compressed, operator-supplied ecosystem archive.
	MaxSnapshotBytes          = 384 << 20
	maxSnapshotExpanded       = 768 << 20
	maxSnapshotRecord         = 2 << 20
	maxSnapshotEntries        = 400000
	maxSnapshotAffected       = 800000
	maxSnapshotPackageRecords = 8192
)

// SnapshotArchive is a seekable OSV ecosystem dump. It is consumed by
// LoadSnapshot and need only remain open for the duration of that call.
type SnapshotArchive struct {
	Reader io.ReaderAt
	Size   int64
}

// Snapshot is an immutable in-memory index of operator-selected OSV dumps.
// It can be shared between scanners.
type Snapshot struct {
	ecosystems map[string]snapshotEcosystem
	provenance []report.AdvisorySnapshot
}

type snapshotEcosystem struct {
	packages map[string][]snapshotMatch
	complete bool
}

type snapshotMatch struct {
	id       ID
	versions []string
	ranges   []affectedRange
}

type snapshotAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions  []string         `json:"versions"`
	Ranges    []affectedRange  `json:"ranges"`
	Severity  []severityVector `json:"severity"`
	Database  severityLabel    `json:"database_specific"`
	Ecosystem severityLabel    `json:"ecosystem_specific"`
}

// SnapshotEcosystems lists the supported official archive directory names.
func SnapshotEcosystems() [3]string {
	return [3]string{report.EcosystemGo, report.EcosystemNPM, report.EcosystemPyPI}
}

// LoadSnapshot indexes the specified official all.zip archives. A malformed or
// truncated archive leaves a coverage gap while retaining any valid positives.
func LoadSnapshot(ctx context.Context, archives map[string]SnapshotArchive) (*Snapshot, error) {
	if ctx == nil || len(archives) == 0 {
		return nil, errors.New("OSV snapshot requires at least one ecosystem archive")
	}

	out := &Snapshot{ecosystems: make(map[string]snapshotEcosystem, len(archives))}
	for _, ecosystem := range SnapshotEcosystems() {
		if archive, ok := archives[ecosystem]; ok {
			data, provenance, err := loadEcosystem(ctx, ecosystem, archive)
			if err != nil {
				return nil, err
			}

			out.ecosystems[ecosystem] = data
			out.provenance = append(out.provenance, provenance)
		}
	}

	if len(out.ecosystems) != len(archives) {
		return nil, errors.New("unsupported OSV snapshot ecosystem")
	}

	return out, nil
}

func loadEcosystem(ctx context.Context, ecosystem string, archive SnapshotArchive) (snapshotEcosystem, report.AdvisorySnapshot, error) {
	out := snapshotEcosystem{packages: map[string][]snapshotMatch{}}

	provenance := report.AdvisorySnapshot{Ecosystem: ecosystem, Bytes: archive.Size}
	if archive.Reader == nil || archive.Size <= 0 || archive.Size > MaxSnapshotBytes {
		return out, provenance, errors.New("invalid OSV archive size")
	}

	reader := snapshotReader{ctx, archive.Reader}

	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(reader, 0, archive.Size)); err != nil {
		return out, provenance, err
	}

	provenance.SHA256 = hex.EncodeToString(hash.Sum(nil))

	// Official large ecosystems use ZIP64. Members are read in memory and never
	// extracted to paths. Standard ZIP parsing also validates CRCs as we read.
	tree, err := zip.NewReader(reader, archive.Size)
	if err != nil || len(tree.File) == 0 || len(tree.File) > maxSnapshotEntries {
		return out, provenance, ctx.Err()
	}

	out.complete = true
	remaining, count := uint64(maxSnapshotExpanded), 0

	seen := make(map[string]struct{}, len(tree.File))
	for _, file := range tree.File {
		if ctx.Err() != nil {
			return out, provenance, ctx.Err()
		}

		if file.UncompressedSize64 > remaining || count >= maxSnapshotAffected {
			out.complete = false
			break
		}

		remaining -= file.UncompressedSize64

		record, ok := readSnapshotRecord(file)
		if _, duplicate := seen[record.ID]; !ok || duplicate {
			out.complete = false
			continue
		}

		seen[record.ID] = struct{}{}
		if record.Withdrawn != "" {
			if _, err := time.Parse(time.RFC3339, record.Withdrawn); err != nil {
				out.complete = false
			}

			continue
		}

		n := out.indexRecord(ecosystem, record)

		count += n
		if n == 0 {
			out.complete = false
		}
	}

	out.complete = out.complete && count > 0
	provenance.Complete = out.complete

	return out, provenance, nil
}

type snapshotReader struct {
	ctx    context.Context
	reader io.ReaderAt
}

func (r snapshotReader) ReadAt(data []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}

	return r.reader.ReadAt(data, offset)
}

func readSnapshotRecord(file *zip.File) (advisoryRecord, bool) {
	var record advisoryRecord
	if file.UncompressedSize64 > maxSnapshotRecord || !file.Mode().IsRegular() {
		return record, false
	}

	reader, err := file.Open()
	if err != nil {
		return record, false
	}

	defer func() { _ = reader.Close() }()

	raw, err := io.ReadAll(io.LimitReader(reader, maxSnapshotRecord+1))
	if err != nil || len(raw) > maxSnapshotRecord || json.Unmarshal(raw, &record) != nil ||
		!safeID(record.ID) || file.Name != record.ID+".json" {
		return record, false
	}

	return record, true
}

func (s *snapshotEcosystem) indexRecord(ecosystem string, record advisoryRecord) int {
	var count int

	base := record.detail()

	for _, item := range record.Affected {
		if item.Package.Ecosystem != ecosystem {
			continue
		}

		name := snapshotPackage(ecosystem, item.Package.Name)
		if name == "" || len(name) > report.MaxAdvisoryCoordinateBytes {
			s.complete = false
			continue
		}

		detail := base.withAffected(item)
		s.packages[name] = append(s.packages[name], snapshotMatch{
			id:       ID{ID: record.ID, Modified: record.Modified, Detail: &detail},
			versions: item.Versions, ranges: item.Ranges,
		})
		count++
	}

	return count
}

func snapshotPackage(ecosystem, name string) string {
	if ecosystem != report.EcosystemPyPI {
		return name
	}

	return strings.Join(strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	}), "-")
}

func (s *Snapshot) lookup(g *queryGroup) ([]ID, string) {
	ecosystem := g.q.Package.Ecosystem

	db, ok := s.ecosystems[ecosystem]
	if !ok {
		return nil, statusSnapshotUnavailable
	}

	version, valid := parseSnapshotVersion(ecosystem, g.q.Version)
	if !valid {
		return nil, statusSnapshotUnknownVersion
	}

	matches := db.packages[snapshotPackage(ecosystem, g.q.Package.Name)]
	complete := db.complete && len(matches) <= maxSnapshotPackageRecords

	var ids []ID

	positions := map[string]int{}

	for _, item := range matches[:min(len(matches), maxSnapshotPackageRecords)] {
		hit, supported := matchesSnapshotVersion(item.versions, item.ranges, ecosystem, g.q.Version, version)
		complete = complete && supported

		if !hit {
			continue
		}

		if i, exists := positions[item.id.ID]; exists {
			if item.id.Detail.Severity.Rank() > ids[i].Detail.Severity.Rank() {
				ids[i] = item.id
			}

			continue
		}

		positions[item.id.ID] = len(ids)
		ids = append(ids, item.id)
	}

	if complete {
		return ids, report.OutcomeSnapshot
	}

	return ids, statusSnapshotIncomplete
}

func lookupSnapshot(ctx context.Context, groups []*queryGroup, db *Snapshot, cached map[coordinateKey]Record, set, fallback func(*queryGroup, string)) {
	for _, group := range groups {
		if group.done {
			continue
		}

		if ctx.Err() != nil {
			set(group, report.OutcomeCancelled)
			continue
		}

		if _, ok := cached[key(group.q.Package.Ecosystem, group.q.Package.Name, group.q.Version)]; ok {
			fallback(group, statusNotCached)
			continue
		}

		ids, status := db.lookup(group)
		if !group.appendResults(ids) {
			status = statusResultLimit
		}

		set(group, status)
	}
}
