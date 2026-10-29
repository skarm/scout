// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
// Modified direct curl/wget/scp/rsync BH2 argument proofs.

package analyzer

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	absoluteHome   = regexp.MustCompile(`^/(?:Users/[^/]+|home/[^/]+|root)(/.*)$`)
	sshDestination = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):[^\s]+$`)
)

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var httpUploadCommands = map[string]bool{"curl": true, "wget": true}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var uploadSourceFlags = map[string]map[string]uploadSourceKind{
	"curl": {
		"-d":            uploadData,
		"--data":        uploadData,
		"--data-ascii":  uploadData,
		"--data-binary": uploadData,
		"-T":            uploadFile,
		"--upload-file": uploadFile,
	},
	"wget": {"--post-file": uploadPostFile, "--body-file": uploadPostFile},
}

//nolint:gochecknoglobals // Read-only language and command classification shared by scans.
var curlUploadOptions = map[string]string{
	"-s":           "skip",
	"--silent":     "skip",
	"-S":           "skip",
	"--show-error": "skip",
	"-sS":          "skip",
	"--fail":       "skip",
	"-X":           "method",
	"--url":        "url",
}

//nolint:gochecknoglobals // Read-only rule and command classification tables are shared by scans.
var uploadSourceRules = map[uploadSourceKind]struct{ prefix, stdin string }{
	uploadData: {prefix: "@", stdin: "@-"}, uploadFile: {stdin: "-"}, uploadPostFile: {},
}

type uploadProof struct {
	event, command  string
	remote, sources int
	sensitive       bool
}

type uploadSourceKind uint8

const (
	uploadData uploadSourceKind = iota + 1
	uploadFile
	uploadPostFile
)

func sensitiveAbsoluteFile(name string) bool {
	if strings.ContainsAny(name, "\x00\r\n$*?[]{}!\\") {
		return false
	}

	m := absoluteHome.FindStringSubmatch(path.Clean(name))
	if m == nil {
		return false
	}

	suffix := m[1]
	for _, dir := range []string{"/.ssh", "/.aws", "/.kube", "/.config/gcloud"} {
		if suffix == dir || strings.HasPrefix(suffix, dir+"/") {
			return true
		}
	}

	return slices.Contains([]string{"/.claude/settings.json", "/.claude/settings.local.json", "/.claude/.credentials.json", "/.docker/config.json", "/.netrc", "/.npmrc"}, suffix)
}

func directUploadArguments(event string, argv []string) bool {
	if len(argv) < 2 {
		return false
	}

	command := path.Base(argv[0])

	args := argv[1:]
	if command == "scp" || command == "rsync" {
		return directSSHUpload(args)
	}

	if !httpUploadCommands[command] {
		return false
	}

	proof := uploadProof{event: event, command: command}
	for i := 0; i < len(args); i++ {
		next, ok := proof.argument(args, i)
		if !ok {
			return false
		}

		i = next
	}

	return proof.sensitive && proof.remote == 1 && proof.sources == 1
}

func directSSHUpload(args []string) bool {
	if len(args) != 2 || !sensitiveAbsoluteFile(args[0]) || strings.HasPrefix(args[1], "-") {
		return false
	}

	match := sshDestination.FindStringSubmatch(args[1])

	return match != nil && closedRemoteHost(strings.Trim(match[1], "[]"))
}

func (p *uploadProof) argument(args []string, i int) (int, bool) {
	if p.command != "curl" {
		return p.sourceArgument(args, i)
	}

	kind := curlUploadOptions[args[i]]
	switch kind {
	case "skip":
		return i, true
	case "method", "url":
		if i+1 >= len(args) {
			return i, false
		}

		value := args[i+1]
		if kind == "method" {
			if value != "POST" {
				return i, false
			}

			return i + 1, true
		}

		if !externalHTTP(value) {
			return i, false
		}

		p.remote++

		return i + 1, true
	default:
		return p.sourceArgument(args, i)
	}
}

func (p *uploadProof) sourceArgument(args []string, i int) (int, bool) {
	arg := args[i]
	flag, value, inline := uploadFlagValue(arg)

	kind, source := uploadSourceFlags[p.command][flag]
	if !source {
		if externalHTTP(arg) {
			p.remote++
			return i, true
		}

		return i, false
	}

	p.sources++

	if !inline {
		if i+1 >= len(args) {
			return i, false
		}

		i++
		value = args[i]
	}

	p.sensitive = sensitiveUploadSource(kind, value, p.event)

	return i, true
}

func uploadFlagValue(arg string) (string, string, bool) {
	if strings.HasPrefix(arg, "--") {
		if flag, value, inline := strings.Cut(arg, "="); inline {
			return flag, value, true
		}
	}

	return arg, "", false
}

func sensitiveUploadSource(kind uploadSourceKind, value, event string) bool {
	rule, known := uploadSourceRules[kind]
	if !known {
		return false
	}

	if rule.stdin != "" && value == rule.stdin {
		return sensitiveEvents[event]
	}

	if !strings.HasPrefix(value, rule.prefix) {
		return false
	}

	return sensitiveAbsoluteFile(strings.TrimPrefix(value, rule.prefix))
}
