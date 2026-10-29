//go:build !coreonly && cgo

// Package treeparse owns synchronous, cancellable Tree-sitter parsing.
package treeparse

/*
#cgo CFLAGS: -std=c11 -D_POSIX_C_SOURCE=200112L
#include "native.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Parser owns an official Tree-sitter parser. Operations are serialized. Close
// waits for an active Parse and its cancellation callback; cancel the context
// first to interrupt that Parse. A closed parser cannot be reopened.
type Parser struct {
	mu    sync.Mutex
	inner *C.ScoutParser
}

func NewParser() *Parser { return &Parser{inner: C.scout_parser_new()} }

func (p *Parser) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	C.scout_parser_delete(p.inner)
	p.inner = nil
}

func (p *Parser) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.inner != nil {
		C.scout_parser_reset(p.inner)
	}
}

func (p *Parser) SetLanguage(language *sitter.Language) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if language == nil || !bool(C.scout_parser_language(p.inner, (*C.TSLanguage)(unsafe.Pointer(language.Inner)))) {
		return errors.New("tree-sitter parser allocation or grammar ABI")
	}

	return nil
}

// Parse returns an owned tree or nil on interruption. The official engine calls
// a C progress callback during parsing and balancing, including between input
// reads. All callback state is C-owned and released with Parser.Close.
func Parse(ctx context.Context, parser *Parser, text []byte, deadline time.Time) *Tree {
	parser.mu.Lock()
	defer parser.mu.Unlock()

	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	remaining := time.Until(deadline)
	if parser.inner == nil || ctx.Err() != nil || remaining <= 0 {
		return nil
	}

	if !bool(C.scout_parser_prepare(parser.inner, C.uint64_t(remaining.Nanoseconds()))) {
		return nil
	}

	done := make(chan struct{})
	state := parser.inner
	stop := context.AfterFunc(ctx, func() { C.scout_parser_cancel(state); close(done) })
	// The engine may retain its last input chunk until reset. Give it C-owned
	// storage so no Go pointer can survive the synchronous native call.
	input := C.CBytes(text)
	defer C.free(input)
	inner := C.scout_parser_parse(parser.inner, (*C.char)(input), C.size_t(len(text)))
	// Join a running cancellation callback before Close or reuse can free C state.
	if !stop() {
		<-done
	}

	if inner == nil {
		return nil
	}

	if ctx.Err() != nil || !time.Now().Before(deadline) {
		C.ts_tree_delete(inner)
		C.scout_parser_reset(state)

		return nil
	}

	return &Tree{inner: inner}
}

// Tree owns native nodes until Close. Consumers copy them into Go-owned IR.
type Tree struct{ inner *C.TSTree }

func (t *Tree) Close()          { C.ts_tree_delete(t.inner); t.inner = nil }
func (t *Tree) RootNode() *Node { return &Node{inner: C.ts_tree_root_node(t.inner)} }

// Node borrows its tree's storage and must not outlive that tree.
type Node struct{ inner C.TSNode }

func (n *Node) Kind() string     { return C.GoString(C.ts_node_type(n.inner)) }
func (n *Node) StartByte() uint  { return uint(C.ts_node_start_byte(n.inner)) }
func (n *Node) EndByte() uint    { return uint(C.ts_node_end_byte(n.inner)) }
func (n *Node) ChildCount() uint { return uint(C.ts_node_child_count(n.inner)) }
func (n *Node) IsNamed() bool    { return bool(C.ts_node_is_named(n.inner)) }
func (n *Node) IsError() bool    { return bool(C.ts_node_is_error(n.inner)) }
func (n *Node) IsMissing() bool  { return bool(C.ts_node_is_missing(n.inner)) }
func (n *Node) HasError() bool   { return bool(C.ts_node_has_error(n.inner)) }
func (n *Node) FieldNameForChild(index uint32) string {
	return C.GoString(C.ts_node_field_name_for_child(n.inner, C.uint32_t(index)))
}

func (n *Node) Child(index uint) *Node {
	child := C.scout_node_child(n.inner, C.size_t(index))
	if child.id == nil {
		return nil
	}

	return &Node{inner: child}
}
