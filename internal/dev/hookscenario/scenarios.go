// Package hookscenario analyzes pinned Bash hooks under explicit finite conditions.
package hookscenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/skarm/scout/report"
)

type Result struct {
	ID            string                   `json:"id"`
	Name          string                   `json:"scenario"`
	HandlerSHA256 string                   `json:"handler_sha256,omitempty"`
	Assumptions   []string                 `json:"assumptions"`
	Coverage      report.ShellHookCoverage `json:"coverage"`
	ReachedLines  []int                    `json:"reached_handler_lines,omitempty"`
	Problem       string                   `json:"problem,omitempty"`
}

type hookScenario struct {
	id, name, handler string
	assumptions       []string
	commandIndex      int
	iterations        int
	userMessages      int
	claudeStatus      uint8
}

func hookScenarios() []hookScenario {
	ralph := func(name string, limit int) hookScenario {
		return hookScenario{
			id: "hook-09", name: name, handler: "hooks/stop-hook.sh", iterations: limit,
			assumptions: []string{"LC_ALL=C", "synthetic state starts at iteration 1 with no completion promise", "session IDs match", fmt.Sprintf("iteration limit is %d", limit)},
		}
	}

	guidance := func(name string, command int) hookScenario {
		return hookScenario{
			id: "hook-10", name: name, handler: "hooks/sg-python.sh", commandIndex: command,
			assumptions: []string{"POSIX launcher, no cygpath or Windows cache", "the first Python 3.13 probe succeeds", "dispatch ends at the captured Python entry point"},
		}
	}

	luca := func(name string, messages int, status uint8) hookScenario {
		return hookScenario{
			id: "hook-12", name: name, handler: "hooks/session-recap.sh", userMessages: messages, claudeStatus: status,
			assumptions: []string{
				"absolute plugin root without splitting or glob characters", "absolute readable transcript", "Git probe succeeds",
				fmt.Sprintf("transcript has %d user messages and one tool call", messages), fmt.Sprintf("Claude boundary returns %d if reached", status),
			},
		}
	}

	return []hookScenario{
		ralph("continue-loop", 10), ralph("iteration-limit", 1),
		guidance("posix-python-sdk", 0), guidance("posix-python-guidance", 1),
		luca("short-session", 1, 0), luca("ingest-success", 5, 0), luca("ingest-failure", 5, 17),
	}
}

// Analyze partially interprets the pinned Bash AST against finite input and
// command models. It starts no shell or external process.
func Analyze(ctx context.Context, cases map[string]map[string]string) []Result {
	scenarios := hookScenarios()
	results := make([]Result, 0, len(scenarios))

	for _, spec := range scenarios {
		item := Result{ID: spec.id, Name: spec.name, Assumptions: spec.assumptions}
		if err := analyzeHookScenario(ctx, cases[spec.id], spec, &item); err != nil {
			item.Coverage = report.ShellHookCoverage{Completeness: report.Partial, Gaps: []string{"hook_scenario_unverified"}}
			item.Problem = err.Error()
		} else {
			item.Coverage = report.ShellHookCoverage{Completeness: report.Complete}
		}

		results = append(results, item)
	}

	return results
}

// The analysis accepts only these source bytes. No commands from an arbitrary
// capture can reach the interpreter.
func pinnedFiles(id string, files map[string]string) (map[string]string, error) {
	var expected map[string]string

	switch id {
	case "hook-09":
		expected = map[string]string{
			"hooks/hooks.json":   "cd60eabe587794c00c873c6f36d340f970c4b57ab9c5664d80c5a22915e74302",
			"hooks/stop-hook.sh": "13c547e77956e44f6af41d1be140f55da0e1ee3c55a540b530f48ee7c7ba9a11",
		}
	case "hook-10":
		expected = map[string]string{
			"hooks/hooks.json":                "149880b26f53aa30093aa18be021459f2b34d90539abdaa218c68bbb3d737571",
			"hooks/sg-python.sh":              "32566effaa22f22a35f3e40f6f7c10b3ff1eb1402a7dcff2381a3636063cd841",
			"hooks/ensure_agent_sdk.py":       "45b01caf19cd8dca6102ed0876b77fc20ffdf19aa504e888e7f7b81683ccc4e2",
			"hooks/security_reminder_hook.py": "98bde872e2757d9e08f4046b4ec92e22536649284c122d148556a88c61edd1f3",
		}
	case "hook-12":
		expected = map[string]string{
			"hooks/hooks.json":              "342759753de9db73970dbaeb0ce1ac49a71651399a24b9686c9d95a96e578cdf",
			"hooks/session-recap.sh":        "d6680761a1fc754487f32026bd8db3c52b9d52b87666a25e76a5612ac70faa35",
			"hooks/session-recap-prompt.md": "d2e1780f3a0a8a3679487ada9912bb56b794a6c5bbcc45be4895284c1ee30b0c",
		}
	default:
		return nil, errors.New("unknown scenario")
	}

	pinned := make(map[string]string, len(expected))
	for name, want := range expected {
		if digest(files[name]) != want {
			return nil, fmt.Errorf("scenario file SHA-256 mismatch: %s", name)
		}

		pinned[name] = files[name]
	}

	return pinned, nil
}

func digest(data string) string {
	sum := sha256.Sum256([]byte(data))

	return hex.EncodeToString(sum[:])
}

type hookScenarioModel struct {
	spec                               hookScenario
	root                               *os.Root
	dir, work, plugin, handler, target string
	ast                                *syntax.File
	functions                          map[string]bool
	mu                                 sync.Mutex
	lines                              map[int]bool
	boundary                           []string
	modelErr                           error
}

func analyzeHookScenario(ctx context.Context, capture map[string]string, spec hookScenario, result *Result) error {
	files, err := pinnedFiles(spec.id, capture)
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "scout-hook-model-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if !filepath.IsAbs(dir) || strings.ContainsAny(dir, " \t\n[]*?") {
		return errors.New("scenario requires an absolute temporary path without splitting or glob characters")
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	m := &hookScenarioModel{
		spec: spec, root: root, dir: dir, work: filepath.Join(dir, "work"), plugin: filepath.Join(dir, "plugin"),
		handler: filepath.Join(dir, "plugin", spec.handler), functions: map[string]bool{}, lines: map[int]bool{},
	}
	body := files[spec.handler]
	result.HandlerSHA256 = digest(body)

	m.ast, err = syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(body), spec.handler)
	if err != nil {
		return err
	}

	syntax.Walk(m.ast, func(n syntax.Node) bool {
		if fn, ok := n.(*syntax.FuncDecl); ok {
			m.functions[fn.Name.Value] = true
		}

		return true
	})

	if err := m.prepare(files); err != nil {
		return err
	}

	command, err := scenarioRegistration(files["hooks/hooks.json"], spec.commandIndex)
	if err != nil {
		return err
	}

	launch, err := syntax.NewParser().Parse(strings.NewReader(command), "hooks/hooks.json")
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]string{
		"cwd": m.work, "session_id": "scenario-session", "transcript_path": filepath.Join(m.work, "transcript.jsonl"),
	})
	if err != nil {
		return err
	}

	env := expand.ListEnviron("LC_ALL=C", "OSTYPE=darwin", "BASH_SUBSHELL=1", "EPOCHREALTIME=1700000000.000001",
		"HOME="+filepath.Join(dir, "home"), "PATH="+filepath.Join(dir, "bin"), "CLAUDE_PLUGIN_ROOT="+m.plugin,
		"CLAUDE_RECAP_RUNNING=")

	var stdout, stderr bytes.Buffer

	r, err := m.runner(env, bytes.NewReader(payload), &stdout, &stderr, true)
	if err != nil {
		return err
	}

	if err := r.Run(ctx, launch); err != nil {
		return fmt.Errorf("registration: %w", err)
	}

	if m.modelErr != nil {
		return m.modelErr
	}

	if stderr.Len() != 0 {
		return errors.New("unexpected stderr in modeled Bash path")
	}

	if err := m.verify(stdout.Bytes()); err != nil {
		return err
	}

	for line := range m.lines {
		result.ReachedLines = append(result.ReachedLines, line)
	}

	slices.Sort(result.ReachedLines)

	return nil
}

func scenarioRegistration(data string, index int) (string, error) {
	var config struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type, Command string
			}
		}
	}
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return "", err
	}

	commands := map[string]bool{}

	for _, groups := range config.Hooks {
		for _, group := range groups {
			for _, entry := range group.Hooks {
				if entry.Type == "command" && entry.Command != "" {
					commands[entry.Command] = true
				}
			}
		}
	}

	var unique []string
	for command := range commands {
		unique = append(unique, command)
	}

	slices.Sort(unique)

	if index >= len(unique) {
		return "", errors.New("scenario registration missing")
	}

	return unique[index], nil
}

func (m *hookScenarioModel) relative(dir, name string) (string, error) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(dir, name)
	}

	rel, err := filepath.Rel(m.dir, name)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.New("path escapes the scenario filesystem")
	}

	return rel, nil
}

func (m *hookScenarioModel) runner(env expand.Environ, stdin io.Reader, stdout, stderr io.Writer, entry bool) (*interp.Runner, error) {
	return interp.New(interp.Dir(m.work), interp.Env(env), interp.StdIO(stdin, stdout, stderr),
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			rewritten, err := m.call(ctx, args, entry)
			m.recordModelError(err)

			return rewritten, err
		}),
		interp.ExecHandlers(func(_ interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, args []string) error {
				if entry {
					return m.launch(ctx, args)
				}

				err := m.command(ctx, args)
				m.recordModelError(err)

				return err
			}
		}),
		interp.OpenHandler(func(ctx context.Context, name string, flags int, mode os.FileMode) (io.ReadWriteCloser, error) {
			if name == "/dev/null" {
				return os.OpenFile(os.DevNull, flags, mode)
			}

			rel, err := m.relative(interp.HandlerCtx(ctx).Dir, name)
			if err != nil {
				return nil, err
			}

			return m.root.OpenFile(rel, flags, mode)
		}),
		interp.StatHandler(func(ctx context.Context, name string, follow bool) (os.FileInfo, error) {
			rel, err := m.relative(interp.HandlerCtx(ctx).Dir, name)
			if err != nil {
				return nil, err
			}

			if follow {
				return m.root.Stat(rel)
			}

			return m.root.Lstat(rel)
		}),
		interp.ReadDirHandler2(func(ctx context.Context, name string) ([]os.DirEntry, error) {
			rel, err := m.relative(interp.HandlerCtx(ctx).Dir, name)
			if err != nil {
				return nil, err
			}

			dir, err := m.root.Open(rel)
			if err != nil {
				return nil, err
			}
			defer func() { _ = dir.Close() }()

			entries, err := dir.ReadDir(-1)
			slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

			return entries, err
		}),
		interp.AccessHandler(func(ctx context.Context, name string, _ interp.AccessMode) error {
			rel, err := m.relative(interp.HandlerCtx(ctx).Dir, name)
			if err != nil {
				return err
			}

			_, err = m.root.Stat(rel)

			return err
		}))
}

// Keep model failures visible even when the Bash program handles a failed
// command. A modeled exit status is part of the path, so it needs no gap.
func (m *hookScenarioModel) recordModelError(err error) {
	if err == nil {
		return
	}

	if _, ok := errors.AsType[interp.ExitStatus](err); ok {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.modelErr == nil {
		m.modelErr = err
	}
}

func (m *hookScenarioModel) call(ctx context.Context, args []string, entry bool) ([]string, error) {
	name := args[0]
	if entry {
		if name != "bash" {
			return nil, errors.New("unexpected launcher")
		}

		return args, nil
	}

	if !m.functions[name] && !slices.Contains([]string{
		":", "[", "cat", "set", "exit", "sed", "grep", "echo", "jq", "rm", "tail", "awk", "mv", "true", "printf",
		"export", "unset", "command", "local", "return", "exec", "mkdir", "dirname", "git", "date", "mktemp", "cd", "basename", "claude", "tr",
	}, name) {
		return nil, fmt.Errorf("unmodeled shell call %q", name)
	}

	if name == "command" && (len(args) != 3 || args[1] != "-v" || !slices.Contains([]string{"cygpath", "python3.13"}, args[2])) {
		return nil, errors.New("unmodeled PATH lookup")
	}

	m.mu.Lock()
	m.lines[int(interp.HandlerCtx(ctx).Pos.Line())] = true
	m.mu.Unlock()

	return args, nil
}

func (m *hookScenarioModel) launch(ctx context.Context, args []string) error {
	if len(args) < 2 || len(args) > 3 || args[0] != "bash" || args[1] != m.handler {
		return errors.New("handler argv differs from the scenario")
	}

	if m.spec.id == "hook-10" {
		if len(args) != 3 || !slices.Contains([]string{
			filepath.Join(m.plugin, "hooks/ensure_agent_sdk.py"), filepath.Join(m.plugin, "hooks/security_reminder_hook.py"),
		}, args[2]) {
			return errors.New("unexpected Python target")
		}

		m.target = args[2]
	} else if len(args) != 2 {
		return errors.New("unexpected arguments to handler")
	}

	hc := interp.HandlerCtx(ctx)

	child, err := m.runner(hc.Env, hc.Stdin, hc.Stdout, hc.Stderr, false)
	if err != nil {
		return err
	}

	child.Params = args[2:]

	return child.Run(ctx, m.ast)
}
