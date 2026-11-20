// Package registry captures bounded MCP Registry snapshots and compares their
// untrusted records. It never installs packages or treats registry claims as trust.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/skarm/scout/fetch"
	"github.com/skarm/scout/internal/syntax/jsonconfig"
)

const (
	fieldServers    = "servers"
	fieldMetadata   = "metadata"
	fieldNextCursor = "nextCursor"
	fieldName       = "name"
	fieldServer     = "server"
	fieldMeta       = "_meta"
	fieldIsLatest   = "isLatest"
	fieldVersion    = "version"
)

const (
	Schema          = "scout.registry-snapshot/v1"
	defaultEndpoint = "https://registry.modelcontextprotocol.io/v0/servers"
)

const (
	defaultPages         = 32
	defaultRecords       = 8192
	defaultResponseBytes = 8 << 20
	maxPages             = 128
	maxRecords           = 32768
	maxResponseBytes     = 32 << 20
	maxServerNameBytes   = 512
)

type Options struct {
	Endpoint, Name       string
	LatestOnly           bool
	MaxPages, MaxRecords int
	MaxBytes             int64
	Download             fetch.Options
}
type page struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type Snapshot struct {
	Schema         string            `json:"schema"`
	EndpointSHA256 string            `json:"endpoint_sha256"`
	Complete       bool              `json:"complete"`
	Pages          []page            `json:"pages"`
	Servers        []json.RawMessage `json:"servers"`
}
type change struct {
	IdentitySHA256 string `json:"identity_sha256"`
	BeforeSHA256   string `json:"before_sha256,omitempty"`
	AfterSHA256    string `json:"after_sha256,omitempty"`
}
type comparison struct {
	Schema  string   `json:"schema"`
	Changes []change `json:"changes"`
}

type captureState struct {
	options  Options
	snapshot Snapshot
	consumed int64
	seen     map[string]bool
	keys     map[string]bool
}

func DefaultOptions() Options {
	return Options{
		Endpoint:   defaultEndpoint,
		MaxPages:   defaultPages,
		MaxRecords: defaultRecords,
		MaxBytes:   defaultResponseBytes,
		Download:   fetch.DefaultOptions(),
	}
}

func Fetch(ctx context.Context, o Options) (Snapshot, error) {
	state := captureState{
		options: o,
		snapshot: Snapshot{
			Schema:         Schema,
			EndpointSHA256: hash([]byte(o.Endpoint)),
			Pages:          []page{},
			Servers:        []json.RawMessage{},
		},
		seen: map[string]bool{},
		keys: map[string]bool{},
	}
	if err := validateOptions(ctx, o); err != nil {
		return state.snapshot, err
	}

	cursor := ""
	for page := 0; page < o.MaxPages; page++ {
		next, err := state.page(ctx, cursor)
		if err != nil {
			return state.snapshot, err
		}

		if next == "" {
			state.snapshot.Complete = true
			break
		}

		if state.seen[next] {
			return state.snapshot, errors.New("repeated registry cursor")
		}

		state.seen[next] = true
		cursor = next
	}

	if !state.snapshot.Complete {
		return state.snapshot, errors.New("registry page limit")
	}

	if o.LatestOnly {
		selected, err := latestRecords(ctx, state.snapshot.Servers)
		if err != nil {
			state.snapshot.Complete = false
			return state.snapshot, err
		}

		state.snapshot.Servers = selected
	}

	if o.Name != "" && len(state.snapshot.Servers) == 0 {
		return state.snapshot, errors.New("registry server not found")
	}

	if err := ctx.Err(); err != nil {
		state.snapshot.Complete = false
		return state.snapshot, err
	}

	return state.snapshot, nil
}

func Compare(ctx context.Context, before, after Snapshot) (comparison, error) {
	out := comparison{Schema: "scout.registry-comparison/v1", Changes: []change{}}
	if ctx == nil {
		return out, errors.New("registry comparison requires a context")
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}

	a, err := recordIndex(ctx, before)
	if err != nil {
		return out, err
	}

	b, err := recordIndex(ctx, after)
	if err != nil {
		return out, err
	}

	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}

	for k := range b {
		keys[k] = true
	}

	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}

	sort.Strings(sorted)

	for _, k := range sorted {
		if a[k] != b[k] {
			out.Changes = append(out.Changes, change{IdentitySHA256: k, BeforeSHA256: a[k], AfterSHA256: b[k]})
		}
	}

	return out, ctx.Err()
}

func validateOptions(ctx context.Context, o Options) error {
	if ctx == nil || o.MaxPages < 1 || o.MaxPages > maxPages ||
		o.MaxRecords < 1 || o.MaxRecords > maxRecords ||
		o.MaxBytes < 1 || o.MaxBytes > maxResponseBytes || len(o.Name) > maxServerNameBytes {
		return errors.New("invalid registry options")
	}

	if !o.Download.Enabled {
		return errors.New("registry download permission required")
	}

	return o.Download.Validate()
}

func (s *captureState) page(ctx context.Context, cursor string) (string, error) {
	options := s.options.Download

	options.MaxBytes = min(options.MaxBytes, int64(jsonconfig.MaxBytes), s.options.MaxBytes-s.consumed)
	if options.MaxBytes < 1 {
		return "", errors.New("registry aggregate byte limit")
	}

	data, err := fetch.GetPage(ctx, s.options.Endpoint, cursor, options)
	if err != nil {
		return "", err
	}

	s.consumed += int64(len(data))

	root, err := jsonconfig.Parse(ctx, string(data))
	if err != nil {
		return "", errors.New("invalid registry page")
	}

	servers := root.Get(fieldServers)
	if servers == nil || servers.Kind != jsonconfig.KindArray {
		return "", errors.New("registry servers array required")
	}

	next, err := nextCursor(root.Get(fieldMetadata))
	if err != nil {
		return "", err
	}

	s.snapshot.Pages = append(s.snapshot.Pages, page{SHA256: hash(data), Bytes: len(data)})

	if err := s.records(servers, data); err != nil {
		return "", err
	}

	return next, nil
}

func nextCursor(metadata *jsonconfig.Node) (string, error) {
	if metadata != nil && metadata.Kind != jsonconfig.KindNull && metadata.Kind != jsonconfig.KindObject {
		return "", errors.New("invalid registry pagination metadata")
	}

	next := metadata.Get(fieldNextCursor)
	if next == nil || next.Kind == jsonconfig.KindNull {
		return "", nil
	}

	if next.Kind != jsonconfig.KindString || len(next.String) > fetch.MaxPageCursorBytes {
		return "", errors.New("invalid registry cursor")
	}

	return next.String, nil
}

func (s *captureState) records(servers *jsonconfig.Node, data []byte) error {
	for _, entry := range servers.Elements {
		server := serverNode(entry)

		name, ok := server.Get(fieldName).Text()
		if !ok || name == "" {
			return errors.New("registry server identity unavailable")
		}

		if s.options.Name != "" && name != s.options.Name {
			continue
		}

		if len(s.snapshot.Servers) >= s.options.MaxRecords {
			return errors.New("registry record limit")
		}

		if !s.options.LatestOnly || isLatest(entry) {
			id, err := recordKey(name, server)
			if err != nil {
				return err
			}

			if s.keys[id] {
				return errors.New("duplicate registry record identity")
			}

			s.keys[id] = true
		}

		s.snapshot.Servers = append(s.snapshot.Servers, json.RawMessage(strings.Clone(string(data[entry.Span.Start:entry.Span.End]))))
	}

	return nil
}

func latestRecords(ctx context.Context, records []json.RawMessage) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0)

	for _, raw := range records {
		root, err := jsonconfig.Parse(ctx, string(raw))
		if err != nil {
			return nil, err
		}

		if isLatest(root) {
			out = append(out, raw)
		}
	}

	return out, nil
}

func serverNode(n *jsonconfig.Node) *jsonconfig.Node {
	if server := n.Get(fieldServer); server != nil {
		return server
	}

	return n
}

func isLatest(n *jsonconfig.Node) bool {
	value := n.Get(fieldMeta).Get("io.modelcontextprotocol.registry/official").Get(fieldIsLatest)
	return value != nil && value.Kind == jsonconfig.KindBool && value.Bool
}

func recordIndex(ctx context.Context, s Snapshot) (map[string]string, error) {
	if s.Schema != Schema || !s.Complete || len(s.Servers) > maxRecords {
		return nil, errors.New("complete registry snapshot required")
	}

	index := map[string]string{}

	for _, raw := range s.Servers {
		root, err := jsonconfig.Parse(ctx, string(raw))
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, contextErr
			}

			return nil, errors.New("invalid registry record")
		}

		server := serverNode(root)

		name, ok := server.Get(fieldName).Text()
		if !ok || name == "" {
			return nil, errors.New("registry record lacks identity")
		}

		id, err := recordKey(name, server)
		if err != nil {
			return nil, err
		}

		if _, exists := index[id]; exists {
			return nil, errors.New("duplicate registry record identity")
		}

		var decoded any

		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()

		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}

		canonical, err := json.Marshal(decoded)
		if err != nil {
			return nil, err
		}

		index[id] = hash(canonical)
	}

	return index, nil
}

func recordKey(name string, server *jsonconfig.Node) (string, error) {
	version, ok := server.Get(fieldVersion).Text()
	if !ok || version == "" || strings.ContainsRune(name, 0) || strings.ContainsRune(version, 0) {
		return "", errors.New("invalid registry record identity")
	}

	return hash([]byte(name + "\x00" + version)), nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
