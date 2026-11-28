//go:build !coreonly

package frontend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skarm/scout/internal/syntax/jsonconfig"

	"github.com/pelletier/go-toml/v2"
	"go.yaml.in/yaml/v4"
)

const (
	codeInvalid        = "invalid"
	codeUnsupportedTag = "unsupported_tag"
)

const (
	yamlTagMapping  = "!!map"
	yamlTagSequence = "!!seq"
	yamlTagString   = "!!str"
	yamlTagBool     = "!!bool"
	yamlTagInt      = "!!int"
	yamlTagFloat    = "!!float"
	yamlTagNull     = "!!null"
)

// Config conversion owns its budget independently of either decoder. It never
// follows aliases or accepts values outside the explicit scalar vocabulary.
type configProjection struct {
	ctx   context.Context
	text  string
	count int
}

type yamlProjection struct {
	configProjection
	positions yamlPositions
}

// YAML line starts are indexed in Unicode code points. Only multibyte runes
// need an entry to convert a decoder column to an original byte offset.
type yamlPositions struct {
	lineStarts          []int
	multibyte           []yamlOffset
	bomBytes, runeCount int
}

type yamlOffset struct {
	position, extraBytes int
}

func (p *configProjection) step(depth int) error {
	p.count++

	if p.count > maxNodes || depth > MaxDepth {
		return &Failure{Category: CodeLimit}
	}

	if p.ctx.Err() != nil {
		return &Failure{Category: CodeDeadline}
	}

	return nil
}

func (p *configProjection) tomlNode(value any, depth int) (*ConfigNode, error) {
	if err := p.step(depth); err != nil {
		return nil, err
	}

	out := &ConfigNode{Start: 0, End: len(p.text)}

	var err error

	switch v := value.(type) {
	case map[string]any:
		err = p.tomlMapping(out, v, depth)
	case []any:
		err = p.tomlSequence(out, v, depth)
	default:
		err = tomlScalar(out, value)
	}

	if err != nil {
		return nil, err
	}

	return out, nil
}

func (p *configProjection) tomlMapping(out *ConfigNode, values map[string]any, depth int) error {
	out.Kind = jsonconfig.KindObject
	keys := make([]string, 0, len(values))

	for k := range values {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, key := range keys {
		child, err := p.tomlNode(values[key], depth+1)
		if err != nil {
			return err
		}

		out.Members = append(out.Members, Member{Key: key, Start: 0, End: len(p.text), Value: child})
	}

	return nil
}

func (p *configProjection) tomlSequence(out *ConfigNode, values []any, depth int) error {
	out.Kind = jsonconfig.KindArray

	for _, x := range values {
		child, err := p.tomlNode(x, depth+1)
		if err != nil {
			return err
		}

		out.Elements = append(out.Elements, child)
	}

	return nil
}

// yaml.Node has starts, but no end offsets. We report a conservative enclosing
// range from its real start to the end of the unit. We do not invent token ends.
func parseYAML(ctx context.Context, text string) (*ConfigNode, error) {
	d := yaml.NewDecoder(strings.NewReader(text))

	var document yaml.Node
	if err := d.Decode(&document); errors.Is(err, io.EOF) {
		return &ConfigNode{Kind: jsonconfig.KindNull}, nil
	} else if err != nil {
		return nil, &Failure{Category: codeInvalid}
	}

	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &Failure{Category: codeMultipleDocuments}
	}

	if ctx.Err() != nil {
		return nil, &Failure{Category: CodeDeadline}
	}

	p := yamlProjection{configProjection: configProjection{ctx: ctx, text: text}, positions: indexYAMLPositions(text)}

	return p.node(&document, 0)
}

func indexYAMLPositions(text string) yamlPositions {
	const bom = "\ufeff"

	var positions yamlPositions
	if strings.HasPrefix(text, bom) {
		positions.bomBytes = len(bom) // The decoder does not count the stream BOM.
	}

	positions.lineStarts = []int{0}
	for i, r := range text[positions.bomBytes:] {
		positions.runeCount++

		if width := utf8.RuneLen(r); width > 1 {
			// The extra bytes apply to every column after this rune.
			positions.multibyte = append(positions.multibyte, yamlOffset{
				position: positions.runeCount, extraBytes: i + width - positions.runeCount,
			})
		}

		switch r {
		case '\r':
			at := positions.bomBytes + i
			if at+1 < len(text) && text[at+1] == '\n' {
				continue
			}

			positions.lineStarts = append(positions.lineStarts, positions.runeCount)
		case '\n', '\u0085', '\u2028', '\u2029':
			// Match the selected decoder's line break conventions.
			positions.lineStarts = append(positions.lineStarts, positions.runeCount)
		}
	}

	return positions
}

func (p *yamlProjection) offset(line, column int) (int, error) {
	positions := p.positions
	if line <= 0 || column <= 0 || line > len(positions.lineStarts) {
		return 0, &Failure{Category: codeInvalidTree}
	}

	start, end := positions.lineStarts[line-1], positions.runeCount
	if line < len(positions.lineStarts) {
		end = positions.lineStarts[line]
	}

	if column-1 > end-start {
		return 0, &Failure{Category: codeInvalidTree}
	}

	position := start + column - 1
	at := positions.bomBytes + position

	i := sort.Search(len(positions.multibyte), func(i int) bool { return positions.multibyte[i].position > position })
	if i > 0 {
		at += positions.multibyte[i-1].extraBytes
	}

	return at, nil
}

func (p *yamlProjection) node(n *yaml.Node, depth int) (*ConfigNode, error) {
	if err := p.step(depth); err != nil {
		return nil, err
	}

	if n == nil {
		return nil, &Failure{Category: codeInvalidTree}
	}

	if n.Kind == yaml.DocumentNode {
		if len(n.Content) != 1 {
			return nil, &Failure{Category: codeInvalidTree}
		}

		return p.node(n.Content[0], depth)
	}

	return p.positionedNode(n, depth)
}

func (p *yamlProjection) positionedNode(n *yaml.Node, depth int) (*ConfigNode, error) {
	start, err := p.offset(n.Line, n.Column)
	if err != nil {
		return nil, err
	}

	out := &ConfigNode{Start: start, End: len(p.text)}

	switch n.Kind {
	case yaml.AliasNode:
		return nil, &Failure{Category: codeUnsupportedAlias}
	case yaml.MappingNode:
		err = p.mapping(out, n, depth)
	case yaml.SequenceNode:
		err = p.sequence(out, n, depth)
	case yaml.ScalarNode:
		err = p.scalar(out, n)
	default:
		err = &Failure{Category: codeInvalidTree}
	}

	if err != nil {
		return nil, err
	}

	return out, nil
}

func (p *yamlProjection) mapping(out *ConfigNode, n *yaml.Node, depth int) error {
	if n.ShortTag() != yamlTagMapping || len(n.Content)%2 != 0 {
		return &Failure{Category: codeUnsupportedTag}
	}

	out.Kind = jsonconfig.KindObject
	seen := map[string]bool{}

	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		p.count++

		if p.count > maxNodes {
			return &Failure{Category: CodeLimit}
		}

		if seen[k.Value] {
			return &Failure{Category: CodeAmbiguousKey}
		}

		seen[k.Value] = true

		member, err := p.member(k, v, depth)
		if err != nil {
			return err
		}

		out.Members = append(out.Members, member)
	}

	return nil
}

func (p *yamlProjection) member(key, value *yaml.Node, depth int) (Member, error) {
	if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlTagString || key.Value == "<<" {
		return Member{}, &Failure{Category: CodeAmbiguousKey}
	}

	start, err := p.offset(key.Line, key.Column)
	if err != nil {
		return Member{}, err
	}

	child, err := p.node(value, depth+1)
	if err != nil {
		return Member{}, err
	}

	end := child.Start
	if end < start {
		end = len(p.text)
	}

	return Member{Key: key.Value, Start: start, End: end, Value: child}, nil
}

func (p *yamlProjection) sequence(out *ConfigNode, n *yaml.Node, depth int) error {
	if n.ShortTag() != yamlTagSequence {
		return &Failure{Category: codeUnsupportedTag}
	}

	out.Kind = jsonconfig.KindArray

	for _, x := range n.Content {
		child, err := p.node(x, depth+1)
		if err != nil {
			return err
		}

		out.Elements = append(out.Elements, child)
	}

	return nil
}

func (p *yamlProjection) scalar(out *ConfigNode, n *yaml.Node) error {
	switch n.ShortTag() {
	case yamlTagString:
		out.Kind, out.Text = jsonconfig.KindString, n.Value
	case yamlTagBool:
		if !strings.EqualFold(n.Value, "true") && !strings.EqualFold(n.Value, "false") {
			return &Failure{Category: codeUnsupportedScalar}
		}

		out.Kind, out.Bool = jsonconfig.KindBool, strings.EqualFold(n.Value, "true")
	case yamlTagInt, yamlTagFloat, yamlTagNull:
		var scalar any
		if err := n.Decode(&scalar); err != nil {
			return &Failure{Category: codeInvalidScalar}
		}

		out.Kind = jsonconfig.KindNull

		if n.ShortTag() != yamlTagNull {
			out.Kind, out.Text = jsonconfig.KindNumber, fmt.Sprint(scalar)
		}
	default:
		return &Failure{Category: codeUnsupportedTag}
	}

	return nil
}

// go-toml validates grammar/redefinitions; its decoder does not provide scalar
// positions. TOML evidence conservatively covers the full unit.
func parseTOML(ctx context.Context, text string) (*ConfigNode, error) {
	var values map[string]any

	if err := toml.Unmarshal([]byte(text), &values); err != nil {
		return nil, &Failure{Category: codeInvalid}
	}

	p := configProjection{ctx: ctx, text: text}

	return p.tomlNode(values, 0)
}

func tomlScalar(out *ConfigNode, value any) error {
	switch v := value.(type) {
	case string:
		out.Kind, out.Text = jsonconfig.KindString, v
	case bool:
		out.Kind, out.Bool = jsonconfig.KindBool, v
	case int64, uint64, float64:
		out.Kind, out.Text = jsonconfig.KindNumber, fmt.Sprint(v)
	case time.Time:
		out.Kind, out.Text = jsonconfig.KindString, v.Format(time.RFC3339Nano)
	case toml.LocalDate, toml.LocalTime, toml.LocalDateTime:
		out.Kind, out.Text = jsonconfig.KindString, fmt.Sprint(v)
	default:
		return &Failure{Category: codeUnsupportedValue}
	}

	return nil
}
