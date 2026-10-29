// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Adapted SC10 shell declarations, with bounded literal-only shell ownership.

package shell

import (
	"context"
	"maps"
	"path"
	"regexp"
	"strings"

	"github.com/skarm/scout/internal/analysis/analysisbudget"
	"github.com/skarm/scout/internal/analysis/document"
	"github.com/skarm/scout/internal/analysis/sourcepolicy"
	"github.com/skarm/scout/internal/syntax/parse"
	"github.com/skarm/scout/internal/syntax/shellsyntax"
	"github.com/skarm/scout/internal/syntax/source"
	"github.com/skarm/scout/report"
)

var shellConfigVariable = regexp.MustCompile(`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var sourceFlowBarriers = stringSet("&& || &")

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var sourceTransparentCommands = stringSet("cat tee printf echo")

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var sourceWrapperPolicies = map[string]sourceWrapperPolicy{
	"command": {terminal: stringSet("-v -V"), values: stringSet("-u --unset -C --chdir")},
	"sudo": {
		terminal:    stringSet("-V -l --version --list"),
		values:      stringSet("-u --unset -C --chdir -g -h -p"),
		assignments: true,
	},
	"env": {
		terminal:    stringSet("-S --split-string --help --version"),
		values:      stringSet("-u --unset -C --chdir"),
		assignments: true,
	},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	sourceRegistryKeys = stringSet("registry npmRegistryServer")
	poetrySourceRules  = []sourceArgumentRule{
		{prefix: []string{"poetry", "source", "add"}, minimum: 5, target: -1, ecosystem: report.EcosystemPyPI},
		{
			prefix:    []string{"poetry", "config"},
			minimum:   4,
			target:    3,
			keyIndex:  2,
			ecosystem: report.EcosystemPyPI,
			key:       func(key string) bool { return strings.HasPrefix(key, "repositories.") },
		},
	}
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var installSourceRules = []sourceArgumentRule{
	{
		prefix:    []string{"npm", "config", "set"},
		minimum:   5,
		target:    4,
		keyIndex:  3,
		ecosystem: report.EcosystemNPM,
		key:       func(key string) bool { return sourceRegistryKeys[key] },
	},
	{
		prefix:    []string{"pnpm", "config", "set"},
		minimum:   5,
		target:    4,
		keyIndex:  3,
		ecosystem: report.EcosystemNPM,
		key:       func(key string) bool { return sourceRegistryKeys[key] },
	},
	{
		prefix:    []string{"yarn", "config", "set"},
		minimum:   5,
		target:    4,
		keyIndex:  3,
		ecosystem: report.EcosystemNPM,
		key:       func(key string) bool { return sourceRegistryKeys[key] },
	},
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	pythonInstallCommands    = stringSet("pip pip3 uv")
	pythonIndexFlags         = stringSet("--index-url --extra-index-url --find-links -i -f")
	mavenSourceCommands      = stringSet("mvn mvnw")
	mavenDefaultRepositories = stringSet("https://repo.maven.apache.org/maven2 https://repo1.maven.org/maven2")
)

// A literal config basename in an output redirection owns the heredoc body.
// This observes a possible declaration, without opening a file or running cat.
//
//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var sourceHeredocProducers = stringSet("cat tee")

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var (
	sourceInputFD             = map[string]bool{"": true, "0": true}
	sourceOutputFD            = map[string]bool{"": true, "1": true}
	sourceInputOperators      = stringSet("< <&")
	sourceOutputOperators     = stringSet("> >> >&")
	sourceFileOutputOperators = stringSet("> >>")
)

type shellSourceWalker struct {
	ctx        context.Context
	unit       document.Unit
	emit       func(source.Span)
	operations int
	truncated  bool
	generated  func([]document.DerivedInput)
	variables  map[string]string
	functions  map[string]*shellsyntax.File
}

type sourceWrapperPolicy struct {
	terminal    map[string]bool
	values      map[string]bool
	assignments bool
}

type sourceArgumentRule struct {
	prefix                    []string
	minimum, target, keyIndex int
	ecosystem                 string
	key                       func(string) bool
}

// SourceDeclarations observes bounded declarations and generated configuration inputs.
func SourceDeclarations(ctx context.Context, d document.File, emit func(source.Span), generated func([]document.DerivedInput)) (limited bool) {
	for _, unit := range d.Units() {
		t, ok := unit.Tree.(parse.ShellTree)
		if !ok {
			continue
		}

		if t.Tree == nil && t.Declarations == nil {
			continue
		}

		tree := t.Tree

		if unit.Status != report.UnitParsedLimited && t.Declarations != nil {
			tree = t.Declarations
			limited = limited || t.DeclarationError != nil
		}

		w := shellSourceWalker{
			ctx:       ctx,
			unit:      unit,
			emit:      emit,
			variables: map[string]string{},
			functions: map[string]*shellsyntax.File{},
			generated: generated,
		}
		w.walk(tree, 0)
		limited = limited || w.truncated
	}

	return limited
}

func sourceEnvKind(key string) string {
	key = strings.ToUpper(key)
	switch key {
	case "NPM_CONFIG_REGISTRY":
		return report.EcosystemNPM
	case "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX":
		return report.EcosystemPyPI
	}

	if strings.HasPrefix(key, "CARGO_REGISTRIES_") && strings.HasSuffix(key, "_INDEX") {
		return "cargo"
	}

	return ""
}

func (w *shellSourceWalker) walk(tree *shellsyntax.File, depth int) {
	if tree == nil {
		return
	}

	if depth > 32 {
		w.truncated = true
		return
	}

	for _, statement := range tree.Statements {
		for _, command := range statement.Commands {
			if !w.step() {
				return
			}

			w.command(command, depth)
		}

		if sourceFlowBarriers[statement.Next] || len(statement.Commands) > 1 {
			clear(w.variables)
		}
	}
}

func (w *shellSourceWalker) step() bool {
	w.operations++
	if w.operations > 8192 || !analysisbudget.Consume(w.ctx, 1) {
		w.truncated = true
	}

	return !w.truncated
}

func (w *shellSourceWalker) command(command *shellsyntax.Command, depth int) {
	u, emit := w.unit, w.emit
	mark := func(span source.Span) {
		if at, e := u.View.Original(span); e == nil {
			emit(at)
		}
	}

	if command.FunctionName != "" {
		w.functions[command.FunctionName] = command.FunctionBody
		// Observe potential declarations without committing effects of
		// an uncalled function to the surrounding script.
		w.isolated(command.FunctionBody, depth+1)

		return
	}

	for _, key := range command.Invalidates {
		if key == "*" {
			clear(w.variables)
		} else {
			delete(w.variables, key)
		}
	}

	if command.Group != nil {
		w.walk(command.Group, depth+1)
		return
	}

	if command.Prelude != nil {
		w.walk(command.Prelude, depth+1)
	}

	if len(command.Alternatives) > 0 {
		w.alternatives(command.Alternatives, depth)
		return
	}

	w.simpleCommand(command, depth, mark)
}

func (w *shellSourceWalker) isolated(tree *shellsyntax.File, depth int) {
	saved, savedFunctions := w.variables, w.functions
	w.variables, w.functions = maps.Clone(saved), maps.Clone(savedFunctions)
	w.walk(tree, depth)
	w.variables, w.functions = saved, savedFunctions
}

func (w *shellSourceWalker) alternatives(branches []*shellsyntax.File, depth int) {
	before := w.variables
	beforeFunctions := w.functions

	var (
		merged          map[string]string
		mergedFunctions map[string]*shellsyntax.File
	)

	for _, branch := range branches {
		w.variables = maps.Clone(before)
		w.functions = maps.Clone(beforeFunctions)
		w.walk(branch, depth+1)

		if merged == nil {
			merged = maps.Clone(w.variables)
			mergedFunctions = maps.Clone(w.functions)
		} else {
			for key, value := range merged {
				if other, ok := w.variables[key]; !ok || other != value {
					delete(merged, key)
				}
			}

			for key, body := range mergedFunctions {
				if w.functions[key] != body {
					delete(mergedFunctions, key)
				}
			}
		}
	}

	w.variables = merged
	w.functions = mergedFunctions
}

func (w *shellSourceWalker) simpleCommand(command *shellsyntax.Command, depth int, mark func(source.Span)) {
	variables := w.variables
	assignment := func(key, value string, known bool, span source.Span) {
		observeSourceAssignment(key, value, known, span, mark)
	}
	w.sourceAssignments(command, assignment)
	words, known := w.sourceWords(command, depth)

	binding := bindSourceArguments(command, words, known, assignment)

	at := sourceWrapperOffset(command, words, binding)
	if at < len(words) && w.sourceArguments(command, words[at:], known[at:], depth, mark) {
		return
	}

	if !w.prepareGeneratedSources(command) {
		return
	}

	if len(command.Words) > 0 {
		first, ok := command.Words[0].Literal()
		if !ok || !sourceTransparentCommands[first] {
			clear(variables)
		}
	}

	if command.Subshell != nil {
		w.isolated(command.Subshell, depth+1)
	}
}

func observeSourceAssignment(key, value string, known bool, span source.Span, mark func(source.Span)) {
	kind := sourceEnvKind(key)
	if kind != "" && (!known || !sourcepolicy.ShellDefault(value, kind)) {
		mark(span)
	}
}

func (w *shellSourceWalker) sourceAssignments(command *shellsyntax.Command, observe func(string, string, bool, source.Span)) {
	for _, assignment := range command.Assignments {
		value, known := sourceWord(assignment.Value, w.variables)
		observe(assignment.Name, value, known, assignment.Span)

		if known && len(command.Words) == 0 && len(w.variables) < 256 {
			w.variables[assignment.Name] = value
		} else {
			delete(w.variables, assignment.Name)
		}
	}
}

func (w *shellSourceWalker) sourceWords(command *shellsyntax.Command, depth int) ([]string, []bool) {
	words := make([]string, 0, len(command.Words))

	known := make([]bool, 0, len(command.Words))
	for _, word := range command.Words {
		value, literal := sourceWord(word, w.variables)
		words, known = append(words, value), append(known, literal)

		for _, part := range word.Parts {
			if part.Tree != nil {
				w.isolated(part.Tree, depth+1)
			}
		}
	}

	return words, known
}

func (w *shellSourceWalker) prepareGeneratedSources(command *shellsyntax.Command) bool {
	if w.generated == nil {
		return true
	}

	inputs := generatedShellInputs(command, w.unit.View.Text(), w.variables)
	for i := range inputs {
		mapped, err := w.unit.View.Original(inputs[i].Span)
		if err != nil {
			w.truncated = true
			return false
		}

		inputs[i].Span = mapped
	}

	w.generated(inputs)

	return true
}

func bindSourceArguments(command *shellsyntax.Command, words []string, known []bool, assignment func(string, string, bool, source.Span)) func(int) {
	bind := func(index int) {
		key, value, ok := strings.Cut(words[index], "=")
		if (!ok || key == "") && len(command.Words[index].Parts) > 0 {
			key, _, ok = strings.Cut(command.Words[index].Parts[0].Text, "=")
		}

		if ok {
			assignment(key, value, known[index], command.Span)
		}
	}
	if len(words) > 0 && words[0] == "export" {
		for index := 1; index < len(words); index++ {
			bind(index)
		}
	}

	return bind
}

func sourceWrapperOffset(command *shellsyntax.Command, words []string, binding func(int)) int {
	at := 0
	for steps := 0; at < len(words) && steps < 16; steps++ {
		head := words[at]
		if head != "env" && head != "command" && head != "sudo" {
			break
		}

		at = sourceWrapperArguments(command, words, at+1, head, binding)
	}

	return at
}

func sourceWrapperArguments(command *shellsyntax.Command, words []string, at int, head string, binding func(int)) int {
	policy := sourceWrapperPolicies[head]

	for at < len(words) {
		value := words[at]
		if policy.terminal[value] {
			return len(words)
		}

		switch {
		case value == "--":
			return at + 1
		case policy.values[value]:
			at += 2
		case strings.HasPrefix(value, "-"):
			at++
		case policy.assignments && sourceWrapperBinding(command, at, value):
			binding(at)
			at++
		default:
			return at
		}
	}

	return at
}

func sourceWrapperBinding(command *shellsyntax.Command, at int, value string) bool {
	if strings.Contains(value, "=") {
		return true
	}

	parts := command.Words[at].Parts

	return len(parts) > 0 && strings.Contains(parts[0].Text, "=")
}

func (w *shellSourceWalker) sourceArguments(command *shellsyntax.Command, args []string, known []bool, depth int, mark func(source.Span)) bool {
	for _, rule := range poetrySourceRules {
		if rule.observes(args, known) {
			mark(command.Span)
		}
	}

	if mavenSourceCommands[args[0]] {
		observeMavenSources(command.Span, args[1:], mark)
	}

	if body := w.functions[args[0]]; body != nil && known[0] {
		w.walk(body, depth+1)
		return true
	}

	observeInstallSources(command.Span, args, known, mark)

	return false
}

func observeMavenSources(span source.Span, args []string, mark func(source.Span)) {
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "-Dmaven.repo.remote="); ok && !strings.ContainsAny(value, " \t\r\n") && !mavenDefaultRepositories[strings.TrimRight(value, "/")] {
			mark(span)
		}
	}
}

func observeInstallSources(span source.Span, args []string, known []bool, mark func(source.Span)) {
	if len(args) >= 3 && pythonModuleCommand(args[0]) && args[1] == "-m" && args[2] == "pip" {
		args = append([]string{"pip"}, args[3:]...)
		known = append([]bool{true}, known[3:]...)
	}

	for _, rule := range installSourceRules {
		if rule.observes(args, known) {
			mark(span)
		}
	}

	if len(args) > 1 && pythonInstallCommands[args[0]] {
		observePythonInstallSources(span, args, known, mark)
	}
}

func observePythonInstallSources(span source.Span, args []string, known []bool, mark func(source.Span)) {
	for i, arg := range args {
		flag, value, attached := strings.Cut(arg, "=")
		if !pythonIndexFlags[flag] {
			continue
		}

		if !attached {
			if i+1 >= len(args) {
				continue
			}

			value = args[i+1]
			if !known[i+1] {
				mark(span)
				continue
			}
		}

		if !sourcepolicy.ShellDefault(value, report.EcosystemPyPI) {
			mark(span)
		}
	}

	rule := sourceArgumentRule{
		prefix:    []string{args[0], "config", "set"},
		minimum:   5,
		target:    4,
		keyIndex:  3,
		ecosystem: report.EcosystemPyPI,
		key:       pythonConfigIndexKey,
	}
	if rule.observes(args, known) {
		mark(span)
	}
}

func sourceConfigProducer(command *shellsyntax.Command) (string, bool) {
	if len(command.Words) == 0 {
		return "", false
	}

	executable, known := command.Words[0].Literal()
	if !known || !sourceHeredocProducers[executable] {
		return "", false
	}

	return executable, executable != "cat" || sourceCatReadsStdin(command.Words[1:])
}

func sourceConfigOutputName(output *shellsyntax.Redirect) string {
	if output == nil || !sourceFileOutputOperators[output.Op] || output.Target == nil {
		return ""
	}

	var name strings.Builder

	for _, part := range output.Target.Parts {
		if part.Kind == "literal" {
			name.WriteString(part.Text)
		} else {
			name.WriteByte('$')
		}
	}

	return generatedConfigName(name.String())
}

func generatedShellInputs(command *shellsyntax.Command, text string, variables map[string]string) []document.DerivedInput {
	executable, admitted := sourceConfigProducer(command)
	if !admitted {
		return nil
	}

	names := generatedConfigNames(command, executable, variables)

	input, output := generatedRedirects(command)
	if input == nil || input.Body == nil {
		return nil
	}

	if name := sourceConfigOutputName(output); name != "" {
		names = append(names, name)
	}

	if input.Body.Span.Start < 0 || input.Body.Span.End > len(text) {
		return nil
	}

	body := text[input.Body.Span.Start:input.Body.Span.End]
	if !input.QuotedDelimiter {
		body = expandShellConfig(body, variables)
	}

	var inputs []document.DerivedInput
	for _, name := range names {
		inputs = append(inputs, document.DerivedInput{Name: name, Text: body, Span: input.Body.Span})
	}

	return inputs
}

func sourceCatReadsStdin(words []*shellsyntax.Word) bool {
	stdin, operand := false, false

	for _, word := range words {
		value, literal := word.Literal()
		if !literal {
			return false
		}

		if value == "-" {
			stdin = true
		}

		if value != "--" && !strings.HasPrefix(value, "-") {
			operand = true
		}
	}

	return !operand || stdin
}

func generatedConfigNames(command *shellsyntax.Command, exe string, vars map[string]string) []string {
	names := make([]string, 0)

	if exe == "tee" {
		for _, word := range command.Words[1:] {
			value, known := sourceWord(word, vars)
			if known && !strings.HasPrefix(value, "-") {
				if name := generatedConfigName(value); name != "" {
					names = append(names, name)
				}
			}
		}
	}

	return names
}

func generatedConfigName(value string) string {
	name := strings.ToLower(path.Base(value))
	if name == "config.toml" && !strings.Contains(value, ".cargo/") {
		return ""
	}

	switch name {
	case ".npmrc", ".yarnrc", "pip.conf", "pip.ini", "pyproject.toml", ".yarnrc.yml", ".yarnrc.yaml", "settings.xml", "pom.xml", "nuget.config", "config.toml", "pipfile", "pipfile.lock", "uv.lock", "poetry.lock":
		// Retain .cargo/ for the existing namespace-aware config analyzer.
		if name == "config.toml" {
			name = ".cargo/config.toml"
		}

		return name
	}

	return ""
}

func generatedRedirects(command *shellsyntax.Command) (*shellsyntax.Redirect, *shellsyntax.Redirect) {
	var input, output *shellsyntax.Redirect

	for _, redirect := range command.Redirects {
		if sourceInputFD[redirect.FD] && (redirect.Body != nil || sourceInputOperators[redirect.Op]) {
			input = redirect
		}

		if sourceOutputFD[redirect.FD] && sourceOutputOperators[redirect.Op] {
			output = redirect
		}
	}

	return input, output
}

func expandShellConfig(original string, vars map[string]string) string {
	var expanded strings.Builder

	previous := 0
	for _, at := range shellConfigVariable.FindAllStringIndex(original, -1) {
		expanded.WriteString(original[previous:at[0]])
		token := original[at[0]:at[1]]

		backslashes := 0
		for i := at[0] - 1; i >= 0 && original[i] == '\\'; i-- {
			backslashes++
		}

		key := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(token, "$"), "{"), "}")
		if v, ok := vars[key]; ok && backslashes%2 == 0 {
			expanded.WriteString(v)
		} else {
			expanded.WriteString(token)
		}

		previous = at[1]
	}

	expanded.WriteString(original[previous:])

	return expanded.String()
}

func sourceWord(word *shellsyntax.Word, variables map[string]string) (string, bool) {
	if word == nil || word.Expands {
		return "", false
	}

	var b strings.Builder

	for _, p := range word.Parts {
		switch p.Kind {
		case "literal":
			b.WriteString(p.Text)
		case "parameter":
			value, ok := variables[p.Text]
			if !ok {
				return "", false
			}

			b.WriteString(value)
		default:
			return "", false
		}

		if b.Len() > 8192 {
			return "", false
		}
	}

	return b.String(), true
}

func (r sourceArgumentRule) observes(args []string, known []bool) bool {
	if len(args) < r.minimum {
		return false
	}

	for i, word := range r.prefix {
		if args[i] != word {
			return false
		}
	}

	if r.key != nil && !r.key(args[r.keyIndex]) {
		return false
	}

	at := r.target
	if at < 0 {
		at = len(args) - 1
	}

	return !known[at] || !sourcepolicy.ShellDefault(args[at], r.ecosystem)
}
