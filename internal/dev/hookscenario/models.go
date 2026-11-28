package hookscenario

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

const (
	ralphState      = ".claude/ralph-loop.local.md"
	ralphTranscript = "{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"still working\"}]}}\n"
	recapOutput     = "scenario response\n"
)

func (m *hookScenarioModel) prepare(files map[string]string) error {
	for _, dir := range []string{"work/.claude/knowledge", "bin", "home"} {
		if err := m.root.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	for name, content := range files {
		path := filepath.Join("plugin", name)
		if err := m.root.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}

		if err := m.root.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}

	switch m.spec.id {
	case "hook-09":
		state := fmt.Sprintf("---\niteration: 1\nmax_iterations: %d\ncompletion_promise: null\nsession_id: scenario-session\n---\nVerify example.\n", m.spec.iterations)
		if err := m.root.WriteFile(filepath.Join("work", ralphState), []byte(state), 0o600); err != nil {
			return err
		}

		return m.root.WriteFile("work/transcript.jsonl", []byte(ralphTranscript), 0o600)
	case "hook-10":
		// command -v sees this marker, but every invocation goes to the Go model.
		return m.root.WriteFile("bin/python3.13", nil, 0o700)
	case "hook-12":
		transcript := strings.Repeat("{\"type\":\"user\"}\n", m.spec.userMessages) + "{\"type\":\"tool_use\"}\n"

		return m.root.WriteFile("work/transcript.jsonl", []byte(transcript), 0o600)
	default:
		return errors.New("unknown scenario fixture")
	}
}

type modeledCall struct {
	model *hookScenarioModel
	hc    interp.HandlerContext
	args  []string
}

func (m *hookScenarioModel) command(ctx context.Context, args []string) error {
	c := modeledCall{model: m, hc: interp.HandlerCtx(ctx), args: args[1:]}
	switch args[0] {
	case "cat":
		return c.copyInput()
	case "grep":
		return c.grep()
	case "sed":
		return c.sed()
	case "jq":
		return c.jq()
	case "awk":
		return c.awk()
	case "tail":
		return c.tail()
	case "tr":
		if slices.Equal(c.args, []string{`\n`, " "}) {
			data, err := c.input(nil)
			if err != nil {
				return err
			}

			return c.print(strings.ReplaceAll(data, "\n", " "))
		}
	case "python3.13":
		return c.python()
	case "claude":
		return c.claude()
	default:
		return c.utility(args[0])
	}

	return c.unmodeled()
}

func (c modeledCall) unmodeled() error {
	return fmt.Errorf("unmodeled arguments at shell line %d", c.hc.Pos.Line())
}

func (c modeledCall) print(s string) error {
	_, err := io.WriteString(c.hc.Stdout, s)

	return err
}

func (c modeledCall) input(paths []string) (string, error) {
	switch len(paths) {
	case 0:
		const limit = 1 << 20

		data, err := io.ReadAll(io.LimitReader(c.hc.Stdin, limit+1))
		if len(data) > limit {
			return "", errors.New("modeled stdin exceeds byte limit")
		}

		return string(data), err
	case 1:
		path, err := c.model.relative(c.hc.Dir, paths[0])
		if err != nil {
			return "", err
		}

		data, err := c.model.root.ReadFile(path)

		return string(data), err
	default:
		return "", c.unmodeled()
	}
}

func (c modeledCall) copyInput() error {
	data, err := c.input(c.args)
	if err != nil {
		return err
	}

	return c.print(data)
}

func (c modeledCall) grep() error {
	args := c.args

	mode := ""
	if len(args) > 0 && slices.Contains([]string{"-q", "-c"}, args[0]) {
		mode, args = args[0], args[1:]
	}

	if len(args) < 1 || !slices.Contains([]string{
		"^iteration:", "^max_iterations:", "^completion_promise:", "^session_id:",
		`"role":"assistant"`, `"type":"user"`, `"type":"tool_use"`,
	}, args[0]) {
		return c.unmodeled()
	}

	data, err := c.input(args[1:])
	if err != nil {
		return err
	}

	anchor, prefix := strings.CutPrefix(args[0], "^")

	var matches []string

	for line := range strings.SplitSeq(strings.TrimSuffix(data, "\n"), "\n") {
		if (prefix && strings.HasPrefix(line, anchor)) || (!prefix && strings.Contains(line, anchor)) {
			matches = append(matches, line)
		}
	}

	if mode == "-c" {
		err = c.print(fmt.Sprintln(len(matches)))
	} else if mode == "" && len(matches) > 0 {
		err = c.print(strings.Join(matches, "\n") + "\n")
	}

	if err == nil && len(matches) == 0 {
		return interp.ExitStatus(1)
	}

	return err
}

func (c modeledCall) sed() error {
	if len(c.args) == 3 && c.args[0] == "-n" && c.args[1] == "/^---$/,/^---$/{ /^---$/d; p; }" {
		data, err := c.input(c.args[2:])
		if err != nil {
			return err
		}

		_, rest, found := strings.Cut(data, "---\n")

		frontmatter, _, closed := strings.Cut(rest, "\n---\n")
		if !found || !closed {
			return errors.New("missing modeled frontmatter")
		}

		return c.print(frontmatter + "\n")
	}

	if len(c.args) == 2 && c.args[0] == "s/^iteration: .*/iteration: 2/" {
		data, err := c.input(c.args[1:])
		if err != nil {
			return err
		}

		return c.print(strings.Replace(data, "\niteration: 1\n", "\niteration: 2\n", 1))
	}

	if len(c.args) != 1 {
		return c.unmodeled()
	}

	data, err := c.input(nil)
	if err != nil {
		return err
	}

	if c.args[0] == `s/^"\(.*\)"$/\1/` {
		line := strings.TrimSuffix(data, "\n")
		if len(line) >= 2 && strings.HasPrefix(line, `"`) && strings.HasSuffix(line, `"`) {
			return c.print(line[1:len(line)-1] + "\n")
		}

		return c.print(data)
	}

	for _, key := range []string{"iteration:", "max_iterations:", "completion_promise:", "session_id:"} {
		if c.args[0] == "s/"+key+" *//" {
			return c.print(strings.TrimLeft(strings.TrimPrefix(data, key), " "))
		}
	}

	return c.unmodeled()
}

func (c modeledCall) jq() error {
	args := c.args
	switch {
	case len(args) == 2 && args[0] == "-r":
		key, _, _ := strings.Cut(args[1], " // ")
		if !slices.Contains([]string{".session_id", ".transcript_path", ".cwd"}, key) {
			return c.unmodeled()
		}

		var input map[string]string
		if err := json.NewDecoder(c.hc.Stdin).Decode(&input); err != nil {
			return err
		}

		return c.print(input[key[1:]] + "\n")
	case len(args) == 2 && args[0] == "-rs":
		data, err := c.input(nil)
		if err != nil {
			return err
		}

		if data != ralphTranscript || !strings.Contains(args[1], `select(.type == "text")`) {
			return c.unmodeled()
		}

		return c.print("still working\n")
	case len(args) == 8 && args[0] == "-n" && slices.Equal(args[1:3], []string{"--arg", "prompt"}) &&
		slices.Equal(args[4:6], []string{"--arg", "msg"}) && strings.Contains(args[7], `"decision": "block"`):
		return json.NewEncoder(c.hc.Stdout).Encode(map[string]string{"decision": "block", "reason": args[3], "systemMessage": args[6]})
	default:
		return c.unmodeled()
	}
}

func (c modeledCall) awk() error {
	if len(c.args) == 2 && c.args[0] == "/^---$/{i++; next} i>=2" {
		state, err := c.input(c.args[1:])
		if err != nil {
			return err
		}

		_, body, found := strings.Cut(state, "\n---\n")
		if !found {
			return c.unmodeled()
		}

		return c.print(body)
	}

	names := []string{"tp", "kd", "ps", "ts", "dh", "sid", "um", "tc"}
	placeholders := []string{"TRANSCRIPT_PATH", "KNOWLEDGE_DIR", "PROJECT_SLUG", "TIMESTAMP", "DATE_HUMAN", "SESSION_ID", "USER_MSGS", "TOOL_CALLS"}

	if len(c.args) != 2*len(names)+2 {
		return c.unmodeled()
	}

	program := c.args[len(c.args)-2]

	pairs := make([]string, 0, 2*len(names))
	for i, name := range names {
		value, ok := strings.CutPrefix(c.args[2*i+1], name+"=")
		if c.args[2*i] != "-v" || !ok || !strings.Contains(program, `gsub(/\{\{`+placeholders[i]+`\}\}/, `+name+")") {
			return c.unmodeled()
		}

		pairs = append(pairs, "{{"+placeholders[i]+"}}", value)
	}

	template, err := c.input(c.args[len(c.args)-1:])
	if err != nil {
		return err
	}

	return c.print(strings.NewReplacer(pairs...).Replace(template))
}

func (c modeledCall) tail() error {
	var (
		count int
		paths []string
	)

	switch {
	case slices.Equal(c.args, []string{"-n", "100"}):
		count = 100
	case len(c.args) == 2 && c.args[0] == "-20":
		count, paths = 20, c.args[1:]
	default:
		return c.unmodeled()
	}

	data, err := c.input(paths)
	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(lines) <= count {
		return c.print(data)
	}

	return c.print(strings.Join(lines[len(lines)-count:], "\n") + "\n")
}

func (c modeledCall) python() error {
	if _, err := c.input([]string{c.model.target}); err != nil {
		return err
	}

	if slices.Equal(c.args, []string{c.model.target}) {
		c.model.recordBoundary("dispatch")

		return nil
	}

	if len(c.args) == 3 && c.args[0] == "-c" && strings.Contains(c.args[1], "sys.version_info") && c.args[2] == c.model.target {
		c.model.recordBoundary("probe")

		return c.print("3.13\n")
	}

	return c.unmodeled()
}

func (m *hookScenarioModel) recordBoundary(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.boundary = append(m.boundary, name)
}

func (c modeledCall) claude() error {
	if len(c.args) != 11 || !slices.Equal(c.args[:10], []string{
		"-p", "--model", "claude-sonnet-4-6", "--allowed-tools", "Read,Write,Edit,Glob",
		"--permission-mode", "acceptEdits", "--no-session-persistence", "--max-budget-usd", "1.00",
	}) {
		return c.unmodeled()
	}

	return c.recap(c.args[len(c.args)-1])
}

func (c modeledCall) recap(prompt string) error {
	if !strings.Contains(prompt, filepath.Join(c.model.work, "transcript.jsonl")) || !strings.Contains(prompt, "scenario-session") ||
		strings.Contains(prompt, "{{TRANSCRIPT_PATH}}") || c.hc.Env.Get("CLAUDE_RECAP_RUNNING").Str != "1" {
		return c.unmodeled()
	}

	c.model.recordBoundary("ingest")

	if err := c.print(recapOutput); err != nil {
		return err
	}

	if c.model.spec.claudeStatus != 0 {
		return interp.ExitStatus(c.model.spec.claudeStatus)
	}

	return nil
}

func (c modeledCall) utility(name string) error {
	switch name {
	case "dirname", "basename":
		if len(c.args) != 1 {
			return c.unmodeled()
		}

		if name == "dirname" {
			return c.print(filepath.Dir(c.args[0]) + "\n")
		}

		return c.print(filepath.Base(c.args[0]) + "\n")
	case "git":
		if slices.Equal(c.args, []string{"-C", c.model.work, "rev-parse", "--git-dir"}) {
			return c.print(".git\n")
		}
	case "date":
		if len(c.args) != 1 {
			return c.unmodeled()
		}

		formats := map[string]string{"+%Y-%m-%d-%H%M": "2026-01-01-0000", "+%Y-%m-%d %H:%M": "2026-01-01 00:00", "+%Y-%m-%d %H:%M:%S": "2026-01-01 00:00:00"}
		if formatted, ok := formats[c.args[0]]; ok {
			return c.print(formatted + "\n")
		}
	case "mktemp":
		if slices.Equal(c.args, []string{"-t", "claude-recap.XXXXXX"}) {
			if err := c.model.root.WriteFile("work/recap.tmp", nil, 0o600); err != nil {
				return err
			}

			return c.print(filepath.Join(c.model.work, "recap.tmp") + "\n")
		}
	case "mkdir", "rm", "mv":
		return c.fileUtility(name)
	}

	return fmt.Errorf("unmodeled external command %q at line %d", name, c.hc.Pos.Line())
}

func (c modeledCall) fileUtility(name string) error {
	args := c.args
	if len(args) > 0 && ((name == "mkdir" && args[0] == "-p") || (name == "rm" && args[0] == "-f")) {
		args = args[1:]
	}

	paths := make([]string, 0, len(args))
	for _, arg := range args {
		path, err := c.model.relative(c.hc.Dir, arg)
		if err != nil {
			return err
		}

		paths = append(paths, path)
	}

	switch {
	case name == "mv" && len(paths) == 2:
		return c.model.root.Rename(paths[0], paths[1])
	case name == "rm" && len(paths) == 1:
		return c.model.root.Remove(paths[0])
	case name == "mkdir" && len(paths) > 0:
		for _, path := range paths {
			if err := c.model.root.MkdirAll(path, 0o700); err != nil {
				return err
			}
		}

		return nil
	default:
		return c.unmodeled()
	}
}

func (m *hookScenarioModel) verify(stdout []byte) error {
	switch m.spec.id {
	case "hook-09":
		return m.verifyRalph(stdout)
	case "hook-10":
		targets := []string{"ensure_agent_sdk.py", "security_reminder_hook.py"}
		if len(stdout) != 0 || filepath.Base(m.target) != targets[m.spec.commandIndex] || !slices.Equal(m.boundary, []string{"probe", "dispatch"}) {
			return errors.New("could not verify the Python probe or dispatch")
		}

		return m.requireLines(111, 339)
	case "hook-12":
		return m.verifyRecap(stdout)
	default:
		return errors.New("unknown scenario result")
	}
}

func (m *hookScenarioModel) verifyRalph(stdout []byte) error {
	state, err := m.root.ReadFile(filepath.Join("work", ralphState))
	if m.spec.iterations == 1 {
		if !errors.Is(err, os.ErrNotExist) || !bytes.Contains(stdout, []byte("Max iterations (1) reached.")) {
			return errors.New("could not verify the Ralph iteration limit and cleanup")
		}

		return m.requireLines(62, 63, 64)
	}

	var output map[string]string
	if err != nil || json.Unmarshal(stdout, &output) != nil || output["decision"] != "block" ||
		output["reason"] != "Verify example." || !strings.Contains(output["systemMessage"], "Ralph iteration 2") ||
		!bytes.Contains(state, []byte("\niteration: 2\n")) {
		return errors.New("could not verify the Ralph block output and state advance")
	}

	return m.requireLines(112, 150, 169, 170, 181)
}

func (m *hookScenarioModel) verifyRecap(stdout []byte) error {
	if len(stdout) != 0 {
		return errors.New("unexpected recap output")
	}

	switch {
	case m.spec.userMessages == 1:
		if len(m.boundary) != 0 || !m.fileContains("work/.claude/knowledge/log.md", "skipped (below threshold: 1 user msgs, 1 tool calls") {
			return errors.New("short-session skip was not verified")
		}

		return m.requireLines(37, 45, 46, 50, 54)
	case !slices.Equal(m.boundary, []string{"ingest"}):
		return errors.New("recap did not reach the modeled ingest call")
	}

	if _, err := m.root.Stat("work/recap.tmp"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("recap scratch file cleanup was not verified")
	}

	if m.spec.claudeStatus == 0 {
		if !m.fileContains("work/.claude/knowledge/log.md", "recap written (session=scenario-session, msgs="+strconv.Itoa(m.spec.userMessages)) {
			return errors.New("successful recap log was not verified")
		}

		return m.requireLines(77, 101, 108, 111)
	}

	if !m.fileContains("home/.claude/knowledge/_errors.log", "claude -p failed (session=scenario-session") ||
		!m.fileContains("home/.claude/knowledge/_errors.log", strings.TrimSpace(recapOutput)) {
		return errors.New("failed recap log was not verified")
	}

	return m.requireLines(77, 101, 113, 114)
}

func (m *hookScenarioModel) fileContains(path, needle string) bool {
	data, err := m.root.ReadFile(path)

	return err == nil && bytes.Contains(data, []byte(needle))
}

func (m *hookScenarioModel) requireLines(lines ...int) error {
	for _, line := range lines {
		if !m.lines[line] {
			return fmt.Errorf("expected handler line %d was not reached", line)
		}
	}

	return nil
}
