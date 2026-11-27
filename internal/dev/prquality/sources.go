package main

import (
	"crypto/sha256"
	"fmt"
	"path"
	"strings"

	"go.yaml.in/yaml/v4"
)

type workflow struct {
	Triggers yaml.Node              `yaml:"on"`
	Defaults workflowDefaults       `yaml:"defaults"`
	Jobs     map[string]workflowJob `yaml:"jobs"`
}

type workflowDefaults struct {
	Run struct{ Shell string } `yaml:"run"`
}

type workflowJob struct {
	If       yaml.Node        `yaml:"if"`
	RunsOn   yaml.Node        `yaml:"runs-on"`
	Defaults workflowDefaults `yaml:"defaults"`
	Steps    []workflowStep   `yaml:"steps"`
}

type workflowStep struct {
	ID, Name, Shell string
	If              yaml.Node
	Run             yaml.Node
}

func (i inventory) readWorkflow(name string, data []byte) error {
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return fmt.Errorf("parse workflow %q: %w", name, err)
	}

	hasTests := false

	for id, job := range wf.Jobs {
		found, err := i.readJob(name, id, wf.Defaults.Run.Shell, job)
		if err != nil {
			return err
		}

		hasTests = hasTests || found
	}

	if line := triggerLine(wf.Triggers); hasTests && line != 0 {
		i.prRuns[name] = location{name, line}
	}

	return nil
}

func (i inventory) readJob(name, id, shell string, job workflowJob) (bool, error) {
	if job.Defaults.Run.Shell != "" {
		shell = job.Defaults.Run.Shell
	}

	if shell == "" && windowsRunner(job.RunsOn) {
		shell = "pwsh"
	}

	hasTests := false

	for _, step := range job.Steps {
		label := step.ID
		if label == "" {
			label = step.Name
		}

		scope := id
		if label != "" {
			scope += " / " + label
		}

		if step.Run.Kind != yaml.ScalarNode || !bashStep(step.Shell, shell) {
			continue
		}

		line := step.Run.Line
		if step.Run.Style == yaml.LiteralStyle {
			line++
		}

		found, err := i.readShell(commandKey{name, scope}, line, maskExpressions(step.Run.Value))
		if err != nil {
			return false, err
		}

		i.addDisabledStep(name, scope, step.If, found)
		hasTests = hasTests || found
	}

	i.addDisabledStep(name, id, job.If, hasTests)

	return hasTests, nil
}

func windowsRunner(node yaml.Node) bool {
	if node.Kind == yaml.ScalarNode {
		return strings.HasPrefix(node.Value, "windows-") || node.Value == "windows"
	}

	if node.Kind == yaml.SequenceNode {
		for _, label := range node.Content {
			if label.Kind == yaml.ScalarNode && windowsRunner(*label) {
				return true
			}
		}
	}

	return false
}

func bashStep(step, defaults string) bool {
	if step == "" {
		step = defaults
	}

	fields := strings.Fields(step)

	return len(fields) == 0 || path.Base(fields[0]) == "bash" || path.Base(fields[0]) == "sh"
}

func triggerLine(node yaml.Node) int {
	if node.Kind == yaml.ScalarNode && node.Value == "pull_request" {
		return node.Line
	}

	if node.Kind != yaml.MappingNode && node.Kind != yaml.SequenceNode {
		return 0
	}

	stride := 1
	if node.Kind == yaml.MappingNode {
		stride = 2
	}

	for index := 0; index < len(node.Content); index += stride {
		child := node.Content[index]
		if child.Kind == yaml.ScalarNode && child.Value == "pull_request" {
			return child.Line
		}
	}

	return 0
}

func (i inventory) addDisabledStep(name, scope string, node yaml.Node, hasTests bool) {
	value := strings.TrimSpace(node.Value)
	if strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}") {
		value = strings.TrimSpace(value[3 : len(value)-2])
	}

	if hasTests && value == "false" {
		key := name + "\x00" + "workflow job or step " + scope + "\x01if:false"
		i.skips[key] = append(i.skips[key], location{name, node.Line})
	}
}

// Replace unevaluated GitHub expressions with inert text while retaining lines.
func maskExpressions(script string) string {
	var out strings.Builder

	for {
		prefix, rest, ok := strings.Cut(script, "${{")
		if !ok {
			out.WriteString(script)
			break
		}

		expression, tail, ok := cutExpression(rest)
		if !ok {
			out.WriteString(script)
			break
		}

		out.WriteString(prefix)

		id := sha256.Sum256([]byte(strings.TrimSpace(expression)))
		fmt.Fprintf(&out, "github-expression-%x", id[:8])
		out.WriteString(strings.Repeat("\\\n", strings.Count(expression, "\n")))

		script = tail
	}

	return out.String()
}

// GitHub expressions use single-quoted literals with doubled quotes.
func cutExpression(text string) (string, string, bool) {
	quoted := false

	for index := range len(text) {
		if text[index] == '\'' {
			quoted = !quoted
		}

		if !quoted && strings.HasPrefix(text[index:], "}}") {
			return text[:index], text[index+2:], true
		}
	}

	return "", "", false
}

func (i inventory) readMakefile(name, text string) error {
	scope := ""

	lines := strings.Split(text, "\n")
	for index := 0; index < len(lines); index++ {
		raw := lines[index]

		recipe, isRecipe := strings.CutPrefix(raw, "\t")
		if !isRecipe {
			if target, _, ok := strings.Cut(raw, ":"); ok && simpleTarget(target) {
				scope = target
			}

			continue
		}

		start := index + 1

		var script strings.Builder
		script.WriteString(strings.TrimLeft(recipe, "@+-"))

		for strings.HasSuffix(lines[index], "\\") && index+1 < len(lines) {
			index++

			script.WriteByte('\n')
			script.WriteString(strings.TrimPrefix(lines[index], "\t"))
		}

		expanded := strings.NewReplacer("$(GO)", "go", "$(NATIVE)", "scout-native", "$$", "$").Replace(script.String())
		if _, err := i.readShell(commandKey{name, scope}, start, expanded); err != nil {
			return err
		}
	}

	return nil
}

func simpleTarget(name string) bool {
	return name != "" && !strings.ContainsFunc(name, func(r rune) bool {
		return !asciiLetter(r) && !asciiDigit(r) && r != '_' && r != '-'
	})
}
