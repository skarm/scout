package filetype_test

import (
	"strings"
	"testing"

	"github.com/skarm/scout/internal/syntax/filetype"
)

func TestContentHints(t *testing.T) {
	for _, tc := range []struct {
		name, data, format, category string
		conflict                     bool
	}{
		{name: "SKILL.md", data: "normal text", format: "text", category: "text", conflict: false},
		{name: "blob.random", data: "ordinary bytes", format: "unknown", category: "unknown", conflict: false},
		{name: ".hidden/payload", data: "\x7fELF\x00data", format: "elf", category: "executable", conflict: false},
		{name: "logo.png", data: "MZ\x00data", format: "pe-candidate", category: "executable", conflict: true},
		{name: "readme.txt", data: "PK\x03\x04\x00", format: "zip", category: "archive", conflict: true},
		{name: "photo.png", data: "\x89PNG\r\n\x1a\n", format: "png", category: "image", conflict: false},
		{name: "photo.png", data: "\xff\xd8\xff", format: "jpeg", category: "image", conflict: true},
		{name: "report.pdf", data: "%PDF-1.7", format: "pdf", category: "document", conflict: false},
		{name: "template.docx", data: "PK\x03\x04\x00", format: "zip", category: "archive", conflict: false},
		{name: "unknown", data: "SQLite format 3\x00", format: "sqlite", category: "database", conflict: false},
		{name: ".cache/a.py", data: "#!/bin/sh\ntrue", format: "text", category: "source-or-config", conflict: true},
		{name: "a.js", data: "const a = 1;", format: "text", category: "source-or-config", conflict: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := filetype.Inspect(tc.name, tc.data, false)
			if d.Format != tc.format || d.Category != tc.category || d.Conflict != tc.conflict {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestBinaryEncodings(t *testing.T) {
	for _, tc := range []struct{ data, encoding string }{{data: "Привет", encoding: "utf-8"}, {
		data:     "\x00text",
		encoding: "bytes",
	}, {
		data:     "\xfftext",
		encoding: "bytes",
	}, {
		data:     "\xff\xfeh\x00i\x00",
		encoding: "utf-16le-or-utf-32le",
	}, {
		data:     "\xfe\xff\x00a",
		encoding: "utf-16be",
	}, {
		data:     "\x00\x00\xfe\xff",
		encoding: "utf-32be",
	}} {
		if got := filetype.Inspect("x", tc.data, false).Encoding; got != tc.encoding {
			t.Fatalf("%q => %s", tc.data, got)
		}
	}
}

func TestSignaturesAndNamedContainers(t *testing.T) {
	for _, prefix := range []string{"\x1f\x8b", "BZh", "\xfd7zXZ\x00", "7z\xbc\xaf\x27\x1c", "Rar!\x1a\x07", "\x28\xb5\x2f\xfd", strings.Repeat("\x00", 257) + "ustar"} {
		if d := filetype.Inspect("payload.dat", prefix, false); d.Category != "archive" {
			t.Fatalf("missed archive candidate: %+v", d)
		}
	}
	for _, name := range []string{"x.png", "x.pdf", "x.zip", "x.docx", "x.sqlite", "x.mp4"} {
		if d := filetype.Inspect(name, "", false); d.Category == "text" || d.Category == "unknown" {
			t.Fatalf("lost named candidate: %+v", d)
		}
	}
}

func FuzzInspect(f *testing.F) {
	for _, s := range []string{"", "\x00", "PK\x03\x04", "#!/usr/bin/env python3\n", "\xff\xfe", "package p\n", "<?php"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 65536 {
			return
		}
		d := filetype.Inspect("sample.unknown", data, false)
		if d.Format == "" || d.Category == "" || d.Encoding == "" {
			t.Fatal("missing classification")
		}
		for _, h := range d.Languages {
			if h.Language == "" || h.Basis == "" {
				t.Fatal("empty hint")
			}
		}
	})
}
