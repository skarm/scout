package evaluation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/skarm/scout/internal/textmatch"
)

const MaxLabelReviewBytes = 2 << 20

// LabelReviewDocument is a separately supplied operator-trusted record. Its
// independence and reviewer identities are declarations, not authentication.
type LabelReviewDocument struct {
	Schema       string            `json:"schema"`
	CorpusSHA256 string            `json:"corpus_sha256"`
	Independent  bool              `json:"independent"`
	Reviews      []CaseLabelReview `json:"reviews"`
}

type CaseLabelReview struct {
	CaseID     string   `json:"case_id"`
	Label      string   `json:"label"`
	ReviewerID string   `json:"reviewer_id"`
	ReviewedAt string   `json:"reviewed_at"`
	Rationale  string   `json:"rationale"`
	Evidence   []string `json:"evidence"`
}

type LabelReviewSummary struct {
	DocumentSHA256 string   `json:"document_sha256"`
	CorpusSHA256   string   `json:"corpus_sha256"`
	InputKind      string   `json:"input_kind"`
	Independent    bool     `json:"independent_declared"`
	ReviewedCases  int      `json:"reviewed_cases"`
	Reviewers      []string `json:"trusted_reviewers"`
}

// LabelReview can only acquire usable labels through ValidateLabelReview. It
// retains no rationale, evidence URL or source content in the measurement report.
type LabelReview struct {
	summary LabelReviewSummary
	labels  map[string]string
}

// LabelReviewTemplate binds pending manual decisions to the exact corpus bytes.
// It never infers labels from scanner output or declares reviewer independence.
func LabelReviewTemplate(data []byte) ([]byte, error) {
	corpus, err := Parse(data)
	if err != nil {
		return nil, err
	}

	if corpus.SchemaVersion != 2 {
		return nil, errors.New("label reviews require corpus schema 2 with source provenance")
	}

	document := LabelReviewDocument{Schema: "scout.corpus-review/v1", CorpusSHA256: labelReviewHash(data), Reviews: make([]CaseLabelReview, len(corpus.Cases))}
	for i, tc := range corpus.Cases {
		document.Reviews[i] = CaseLabelReview{CaseID: tc.ID, Label: "pending", Evidence: []string{}}
	}

	result, err := json.MarshalIndent(document, "", "  ")

	result = append(result, '\n')
	if len(result) > MaxLabelReviewBytes {
		return nil, errors.New("label review template exceeds byte budget")
	}

	return result, err
}

// ValidateLabelReview checks full case coverage, immutable corpus binding and an
// explicit reviewer allowlist before any scan or optional provider is called.
func ValidateLabelReview(corpusData, reviewData []byte, trusted []string, now time.Time) (*LabelReview, error) {
	corpus, err := Parse(corpusData)
	if err != nil {
		return nil, err
	}

	if corpus.SchemaVersion != 2 {
		return nil, errors.New("label reviews require corpus schema 2 with source provenance")
	}

	allowlist, err := labelReviewers(trusted)
	if err != nil {
		return nil, err
	}

	document, err := parseLabelReview(reviewData)
	if err != nil {
		return nil, err
	}

	if document.CorpusSHA256 != labelReviewHash(corpusData) {
		return nil, errors.New("label review does not match the exact corpus bytes")
	}

	if document.Independent && corpus.Kind == "authored_regression_not_holdout" {
		return nil, errors.New("an authored regression corpus cannot become independent through a label review")
	}

	if len(document.Reviews) != len(corpus.Cases) || now.IsZero() {
		return nil, errors.New("label review must cover every corpus case at a known validation time")
	}

	labels, reviewers, err := reviewLabels(corpus, document.Reviews, allowlist, now)
	if err != nil {
		return nil, err
	}

	return &LabelReview{labels: labels, summary: LabelReviewSummary{
		DocumentSHA256: labelReviewHash(reviewData), CorpusSHA256: document.CorpusSHA256,
		InputKind: corpus.Kind, Independent: document.Independent, ReviewedCases: len(labels), Reviewers: reviewers,
	}}, nil
}

func parseLabelReview(data []byte) (LabelReviewDocument, error) {
	var document LabelReviewDocument
	if len(data) > MaxLabelReviewBytes {
		return document, errors.New("label review exceeds byte budget")
	}

	if err := validateJSONFields(data, []string{"schema", "corpus_sha256", "independent", "reviews", "case_id", "label", "reviewer_id", "reviewed_at", "rationale", "evidence"}, false); err != nil {
		return document, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&document); err != nil {
		return document, errors.New("invalid label review document")
	}

	if document.Schema != "scout.corpus-review/v1" || !textmatch.LowerHex(document.CorpusSHA256, 64) || len(document.Reviews) == 0 || len(document.Reviews) > 4096 {
		return document, errors.New("invalid label review identity or case count")
	}

	return document, nil
}

func labelReviewers(ids []string) (map[string]bool, error) {
	if len(ids) == 0 || len(ids) > 32 {
		return nil, errors.New("label review requires 1..32 explicitly trusted reviewer IDs")
	}

	result := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !textmatch.Token(id, 128, "._@-") || result[id] {
			return nil, errors.New("trusted label reviewer IDs must be unique bounded ASCII tokens")
		}

		result[id] = true
	}

	return result, nil
}

func reviewLabels(corpus Corpus, reviews []CaseLabelReview, trusted map[string]bool, now time.Time) (map[string]string, []string, error) {
	cases := make(map[string]bool, len(corpus.Cases))
	for _, tc := range corpus.Cases {
		cases[tc.ID] = true
	}

	labels := make(map[string]string, len(reviews))

	var reviewers []string

	for _, review := range reviews {
		if !cases[review.CaseID] || labels[review.CaseID] != "" {
			return nil, nil, errors.New("label review contains an unknown or duplicate case")
		}

		if !trusted[review.ReviewerID] {
			return nil, nil, errors.New("label review contains a reviewer not explicitly trusted by the operator")
		}

		if err := review.validate(now); err != nil {
			return nil, nil, err
		}

		labels[review.CaseID] = review.Label
		if !slices.Contains(reviewers, review.ReviewerID) {
			reviewers = append(reviewers, review.ReviewerID)
		}
	}

	slices.Sort(reviewers)

	return labels, reviewers, nil
}

func (r CaseLabelReview) validate(now time.Time) error {
	if !slices.Contains([]string{"signal", "benign", "ambiguous"}, r.Label) || !boundedText(r.Rationale, 2048) {
		return errors.New("label review requires a completed label and a bounded rationale")
	}

	at, err := time.Parse(time.RFC3339, r.ReviewedAt)
	if err != nil || at.IsZero() || at.After(now) {
		return errors.New("label review requires a nonfuture RFC3339 review time")
	}

	if len(r.Evidence) == 0 || len(r.Evidence) > 8 {
		return errors.New("label review requires 1..8 evidence URLs per case")
	}

	for _, address := range r.Evidence {
		if !boundedText(address, 2048) {
			return errors.New("label review evidence requires bounded HTTPS URLs")
		}

		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" {
			return errors.New("label review evidence requires bounded credential-free HTTPS URLs without queries")
		}
	}

	return nil
}

func (r *LabelReview) apply(corpus Corpus, data []byte) (Corpus, *LabelReviewSummary, error) {
	if r == nil {
		return corpus, nil, nil
	}

	if r.summary.CorpusSHA256 != labelReviewHash(data) || len(r.labels) != len(corpus.Cases) {
		return corpus, nil, errors.New("validated label review belongs to a different corpus")
	}

	corpus.Cases = slices.Clone(corpus.Cases)
	for i := range corpus.Cases {
		label := r.labels[corpus.Cases[i].ID]
		if label == "" {
			return corpus, nil, errors.New("validated label review has incomplete case coverage")
		}

		corpus.Cases[i].Label = label
	}

	if r.summary.Independent {
		corpus.Kind = "independent_labelled_corpus"
	} else if corpus.Kind != "authored_regression_not_holdout" {
		corpus.Kind = "external_labelled_corpus"
	}

	summary := r.summary
	summary.Reviewers = slices.Clone(r.summary.Reviewers)

	return corpus, &summary, nil
}

func labelReviewHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
