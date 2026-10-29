package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/skarm/scout/knowledge"
	scanreport "github.com/skarm/scout/report"
)

const fixtureModel = "scripted-fixture-no-live-model"

type knowledgeCase struct {
	ID, Label, Topic, Path, Content string
	StaticExpected                  string `json:"static_expected"`
	StaticForbidden                 string `json:"static_forbidden"`
	RequiresPython                  bool   `json:"requires_python"`
}
type fixtureReviewer struct {
	mu                  sync.Mutex
	current             knowledgeCase
	topics              map[string]object
	prompts             map[string]string
	calls, verification int
	err                 error
}

func checkKnowledgeRuntime(ctx context.Context, o options, w io.Writer) error {
	if err := o.require("binary", "output"); err != nil {
		return err
	}

	binary, err := filepath.Abs(o.get("binary"))
	if err != nil {
		return err
	}

	var corpus struct{ Cases []knowledgeCase }
	if err = readJSON(filepath.Join(o.root, "testdata/knowledge-runtime/cases.json"), &corpus); err != nil {
		return err
	}

	pack, _, err := invokeJSON(ctx, binary, "knowledge")
	if err != nil {
		return err
	}

	reviewer, err := newFixtureReviewer(ctx, binary, pack)
	if err != nil {
		return err
	}

	if err = newOutput(o.get("output")); err != nil {
		return err
	}

	rows, err := runKnowledgeCases(ctx, o, binary, reviewer, corpus.Cases)
	if err != nil {
		return err
	}

	return writeKnowledgeRuntimeSummary(o, binary, pack, corpus.Cases, rows, w)
}

func writeKnowledgeRuntimeSummary(o options, binary string, pack object, cases []knowledgeCase, rows []object, w io.Writer) error {
	binarySHA, err := fileDigest(binary)
	if err != nil {
		return err
	}

	summary := object{
		"scope":                "Actual static scans and scripted semantic transport integration. Not model quality or SQL detection accuracy.",
		"public_network":       false,
		"live_model":           false,
		"target_code_executed": false,
		"pack_sha256":          at(pack, "manifest", "sha256"),
		"binary_sha256":        binarySHA,
		"cases":                rows,
	}

	destination := filepath.Join(o.get("output"), "summary.json")
	if err = writeJSON(destination, summary); err != nil {
		return err
	}

	risk := 0

	for _, tc := range cases {
		if tc.Label == "risk" {
			risk++
		}
	}

	return printJSON(w, object{
		"cases":                   len(rows),
		"scripted_risk_responses": risk,
		"live_model":              false,
		"summary":                 destination,
	})
}

func newFixtureReviewer(ctx context.Context, binary string, pack object) (*fixtureReviewer, error) {
	reviewer := &fixtureReviewer{topics: map[string]object{}, prompts: map[string]string{}}
	for _, topic := range array(pack["review_topics"]) {
		reviewer.topics[text(at(topic, "id"))] = obj(topic)
	}

	for _, prompt := range array(at(pack, "manifest", "prompts")) {
		mode := text(at(prompt, "mode"))

		data, _, err := invokeCLI(ctx, binary, "knowledge", "--mode", mode)
		if err != nil {
			return nil, err
		}

		reviewer.prompts[mode] = string(data)
	}

	return reviewer, nil
}

func invokeCLI(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
	call, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	cmd := exec.CommandContext(call, binary, args...) //nolint:gosec // G204: explicitly selected trusted Scout binary; scanned artifact bytes are never executed.

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code, err := cliProcessExit(err)
	if err != nil {
		return nil, code, err
	}

	if err := validateCLIStderr(stdout.Bytes(), stderr.Bytes(), args, code); err != nil {
		return nil, code, err
	}

	return stdout.Bytes(), code, nil
}

func invokeJSON(ctx context.Context, binary string, args ...string) (object, int, error) {
	data, code, err := invokeCLI(ctx, binary, args...)
	if err != nil {
		return nil, code, err
	}

	var report object

	err = json.Unmarshal(data, &report)

	return report, code, err
}

func (s *fixtureReviewer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	body, err := s.answer(r)
	if err != nil {
		s.err = err

		http.Error(w, "fixture protocol check failed", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err = json.NewEncoder(w).Encode(body); err != nil {
		s.err = err
	}
}

func (s *fixtureReviewer) answer(r *http.Request) (object, error) {
	body, request, err := decodeFixtureRequest(r)
	if err != nil {
		return nil, err
	}

	mode, err := s.fixturePrompt(request, array(body["messages"]))
	if err != nil {
		return nil, err
	}

	reason := "knowledge:" + s.current.Topic

	values := stringsOf(at(body, "response_format", "json_schema", "schema", "properties", "proposals", "items", "properties", "reason", "enum"))
	if !slices.Contains(values, reason) {
		return nil, errors.New("knowledge reason is absent from response schema")
	}

	response, err := s.fixtureResponse(request, mode, reason)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}

	s.calls++

	return object{
		"model": fixtureModel,
		"choices": []any{object{
			"index":         0,
			"finish_reason": "stop",
			"message": object{
				"role":    "assistant",
				"content": string(encoded),
			},
		}},
	}, nil
}

func (s *fixtureReviewer) fixtureResponse(request object, mode, reason string) (object, error) {
	proposals, assessments := make([]any, 0), make([]any, 0)

	if mode == knowledge.ModeDiscovery && s.current.Label == "risk" {
		var evidence object

		for _, ex := range array(request["excerpts"]) {
			if text(at(ex, "path")) == s.current.Path {
				evidence = object{"excerpt_id": at(ex, "id"), "sha256": at(ex, "sha256")}
				break
			}
		}

		if evidence == nil {
			return nil, errors.New("fixture source excerpt missing")
		}

		proposals = append(proposals, object{"reason": reason, "severity": "high", "evidence": []any{evidence}})
	}

	for _, finding := range array(request[findingsKey]) {
		if mode == knowledge.ModeProposalAssessment {
			if err := s.checkFindingGuidance(obj(finding), reason); err != nil {
				return nil, err
			}

			s.verification++
		}

		assessments = append(assessments, object{
			"finding_id": at(finding, "id"),
			"verdict":    "confirmed",
			"reason":     "supported_by_context",
			"evidence":   at(finding, "evidence"),
		})
	}

	return object{
		"schema_version": request["schema_version"],
		"request_id":     request["request_id"],
		"proposals":      proposals,
		"assessments":    assessments,
	}, nil
}

func (s *fixtureReviewer) checkFindingGuidance(finding object, reason string) error {
	topic, exists := s.topics[s.current.Topic]
	if !exists || text(finding["reason"]) != reason || !reflect.DeepEqual(at(finding, "guidance", "review_checks"), topic["review_checks"]) || !reflect.DeepEqual(at(finding, "guidance", "remediation"), topic["remediation"]) || len(array(at(finding, "guidance", "sources"))) != len(array(topic["sources"])) {
		return errors.New("fixture knowledge guidance differs")
	}

	return nil
}

func (s *fixtureReviewer) validateCase(static, semantic object, tc knowledgeCase) error {
	if s.err != nil {
		return s.err
	}

	if !reflect.DeepEqual(semantic[findingsKey], static[findingsKey]) {
		return errors.New("semantic review changed static findings")
	}

	sem := obj(semantic["semantic"])

	expected := tc.expectedProposals()

	if number(sem["completed_requests"]) != len(array(sem["tasks"])) || len(array(sem["proposals"])) != expected || len(array(sem["proposal_assessments"])) != expected || s.verification != expected {
		return errors.New("fixture requests or assessments incomplete")
	}

	if expected == 1 {
		return validateKnowledgeProposal(semantic, tc)
	}

	return nil
}

func (s *fixtureReviewer) fixturePrompt(request object, messages []any) (string, error) {
	mode := text(request["mode"])

	prompt, exists := s.prompts[mode]
	if !exists || text(at(messages[0], "role")) != "system" || text(at(messages[0], "content")) != prompt || text(request["prompt_sha256"]) != digest([]byte(prompt)) {
		return "", errors.New("fixture prompt binding differs")
	}

	return mode, nil
}

func checkKnowledgeCase(ctx context.Context, o options, binary, folder, endpoint string, s *fixtureReviewer, tc knowledgeCase) (object, error) {
	target, err := prepareKnowledgeInput(folder, tc)
	if err != nil {
		return nil, err
	}

	static, staticCode, err := knowledgeScan(ctx, o, binary, target, tc.ID+"-static.json", []string{"--profile", "standard"})
	if err != nil {
		return nil, err
	}

	found, applicable, err := checkStaticKnowledge(static, tc)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.current, s.calls, s.verification, s.err = tc, 0, 0, nil
	s.mu.Unlock()

	configPath, err := safeJoin(o.get("output"), tc.ID+"-review-config.json")
	if err != nil {
		return nil, err
	}

	configuration := object{
		"schema":  "scout.config/v1",
		"profile": "review",
		"review": object{
			"provider":       "chat-completions",
			"endpoint":       endpoint,
			"model":          fixtureModel,
			"allow_loopback": true,
		},
	}
	if err = writeJSON(configPath, configuration); err != nil {
		return nil, err
	}

	semanticFlags := []string{"--config", configPath, "--allow-source-upload"}

	semantic, semanticCode, err := knowledgeScan(ctx, o, binary, target, tc.ID+"-fixture.json", semanticFlags)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err = s.validateCase(static, semantic, tc); err != nil {
		return nil, err
	}

	expected := tc.expectedProposals()

	return object{
		"id":                        tc.ID,
		"label":                     tc.Label,
		"topic":                     tc.Topic,
		"static_rule_ids":           found,
		"static_control_applicable": applicable,
		"static_coverage":           at(static, coverageKey, "completeness"),
		"static_exit":               staticCode,
		"fixture_topic_proposals":   expected,
		"fixture_verifications":     s.verification,
		"fixture_calls":             s.calls,
		"semantic_completeness":     at(semantic, "semantic", "completeness"),
		"semantic_exit":             semanticCode,
	}, nil
}

func knowledgeScan(ctx context.Context, o options, binary, target, name string, flags []string) (object, int, error) {
	args := append([]string{"scan", "--format", "json"}, flags...)
	args = append(args, "--", target)

	data, code, err := invokeCLI(ctx, binary, args...)
	if err != nil {
		return nil, code, err
	}

	if err = os.WriteFile(filepath.Join(o.get("output"), name), data, 0o600); err != nil {
		return nil, code, err
	}

	document, err := decodeScoutDocument(data)
	if err != nil {
		return nil, code, err
	}

	result, err := asObject(document.Run.Targets[0].Analysis)
	if err == nil {
		result["evaluation"], err = asObject(document.Evaluation)
	}

	return result, code, err
}

func checkStaticKnowledge(report object, tc knowledgeCase) ([]string, bool, error) {
	if boolean(at(report, "semantic", "enabled")) {
		return nil, false, errors.New("static scan enabled semantic review")
	}

	found, available := staticKnowledgeFacts(report)

	applicable := !tc.RequiresPython || available
	if tc.StaticForbidden != "" && found[tc.StaticForbidden] {
		return nil, false, errors.New("forbidden static rule was reported")
	}

	if tc.StaticExpected != "" && applicable {
		if !found[tc.StaticExpected] {
			return nil, false, errors.New("expected static rule missing")
		}

		if !staticGuidanceContains(report, tc.StaticExpected, tc.Topic) {
			return nil, false, errors.New("static rule knowledge source missing")
		}
	}

	return sortedKeys(found), applicable, nil
}

func staticGuidanceContains(report object, rule, topic string) bool {
	for _, entry := range array(report["rules"]) {
		if text(at(entry, "id")) != rule {
			continue
		}

		for _, source := range array(at(entry, "guidance", "sources")) {
			if text(at(source, "symbol")) == topic {
				return true
			}
		}
	}

	return false
}

func cliProcessExit(err error) (int, error) {
	if err == nil {
		return 0, nil
	}

	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 0, err
	}

	code := exit.ExitCode()
	if code < 0 || code > 2 {
		return code, err
	}

	return code, nil
}

func validateCLIStderr(stdout, stderr []byte, args []string, code int) error {
	if len(stderr) == 0 {
		return nil
	}

	document, err := decodeScoutDocument(stdout)
	if len(args) == 0 || args[0] != "scan" || code != 2 || err != nil || document.Run.State == scanreport.RunComplete {
		return errors.New("scout wrote unexpected stderr")
	}

	return nil
}

func decodeFixtureRequest(r *http.Request) (object, object, error) {
	if r.Method != http.MethodPost || r.ContentLength <= 0 || r.ContentLength >= 256<<10 {
		return nil, nil, errors.New("unexpected fixture request")
	}

	var body object
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		return nil, nil, err
	}

	messages := array(body["messages"])
	if len(messages) < 2 {
		return nil, nil, errors.New("missing fixture messages")
	}

	var request object
	if err := json.Unmarshal([]byte(text(at(messages[1], "content"))), &request); err != nil {
		return nil, nil, err
	}

	return body, request, nil
}

func prepareKnowledgeInput(folder string, tc knowledgeCase) (string, error) {
	target, err := safeJoin(folder, tc.ID)
	if err != nil {
		return "", err
	}

	path, err := safeJoin(target, tc.Path)
	if err != nil {
		return "", err
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}

	if err = os.WriteFile(path, []byte(tc.Content), 0o600); err != nil {
		return "", err
	}

	return target, nil
}

func staticKnowledgeFacts(report object) (map[string]bool, bool) {
	found := map[string]bool{}
	for _, finding := range array(report[findingsKey]) {
		found[text(at(finding, "rule_id"))] = true
	}

	available := false

	for _, check := range array(at(report, "inspection", "checks")) {
		if text(at(check, "id")) == "python" {
			available = boolean(at(check, "available"))
		}
	}

	return found, available
}

func validateKnowledgeProposal(semantic object, tc knowledgeCase) error {
	sem := obj(semantic["semantic"])

	proposal := array(sem["proposals"])[0]
	if text(at(proposal, "knowledge_topic_id")) != tc.Topic || len(array(at(proposal, "guidance", "sources"))) == 0 || text(at(semantic, "evaluation", decisionKey)) == decisionAllow {
		return errors.New("fixture proposal lost knowledge or policy evidence")
	}

	return nil
}

func runKnowledgeCases(ctx context.Context, o options, binary string, reviewer *fixtureReviewer, cases []knowledgeCase) ([]object, error) {
	server := httptest.NewServer(http.HandlerFunc(reviewer.serve))
	defer server.Close()

	folder, err := os.MkdirTemp("", "scout-authored-knowledge-")
	if err != nil {
		return nil, err
	}

	defer func() { _ = os.RemoveAll(folder) }()

	rows := make([]object, 0, len(cases))
	for _, tc := range cases {
		row, err := checkKnowledgeCase(ctx, o, binary, folder, server.URL+"/v1/chat/completions", reviewer, tc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tc.ID, err)
		}

		rows = append(rows, row)
	}

	return rows, nil
}

func (tc knowledgeCase) expectedProposals() int {
	if tc.Label == "risk" {
		return 1
	}

	return 0
}
