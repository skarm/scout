#!/usr/bin/env python3
"""Build the native Tree-sitter lifecycle harness with the official Go modules.

Usage: python3 internal/dev/maintenance/treeparse_sanitize.py --sanitizer address --output /tmp/ts-asan
Sanitizers: address (with UBSan), thread, none (for the platform leak detector).
No module sources are patched; only the application adapter is compiled here.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sanitizer', choices=['address', 'thread', 'none'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=500)
    parser.add_argument('--adapter', type=Path, help='Explicit alternate adapter for detector positive controls')
    args = parser.parse_args()
    root = next((parent for parent in Path(__file__).resolve().parents
                 if (parent / 'go.mod').is_file()), None)
    if root is None:
        parser.error('cannot locate the Scout module root')
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    build = output.parent / (output.name + '-objects')
    build.mkdir(exist_ok=True)

    def module(name):
        return Path(subprocess.check_output(['go', 'list', '-mod=readonly', '-m', '-f', '{{.Dir}}', name], cwd=root, text=True).strip())

    engine = module('github.com/tree-sitter/go-tree-sitter')
    grammars = [module('github.com/tree-sitter/' + name) / subdir for name, subdir in [
        ('tree-sitter-python', 'src'), ('tree-sitter-javascript', 'src'),
        ('tree-sitter-typescript', 'typescript/src'), ('tree-sitter-typescript', 'tsx/src')]]
    adapter = root / 'internal/syntax/treeparse'
    sources = [args.adapter.resolve() if args.adapter else adapter / 'native.c',
               engine / 'src/lib.c', adapter / 'testdata/lifecycle.c']
    for grammar in grammars:
        sources.extend([grammar / 'parser.c', grammar / 'scanner.c'])
    flags = ['-std=c11', '-D_POSIX_C_SOURCE=200112L', '-D_DEFAULT_SOURCE', '-g', '-O1', '-fno-omit-frame-pointer', '-pthread']
    if args.sanitizer != 'none':
        flags += ['-fsanitize=address,undefined' if args.sanitizer == 'address' else '-fsanitize=thread', '-fno-sanitize-recover=all']
    include = ['-I' + str(p) for p in [adapter, engine / 'include', engine / 'src']]
    cc = shlex.split(os.environ.get('CC', 'clang'))
    commands = []
    objects = []
    for i, source in enumerate(sources):
        obj = build / (str(i) + '.o')
        command = cc + flags + include + ['-I' + str(source.parent), '-c', str(source), '-o', str(obj)]
        commands.append(command)
        subprocess.run(command, check=True)
        objects.append(str(obj))
    command = cc + flags + objects + ['-o', str(output)]
    commands.append(command)
    subprocess.run(command, check=True)
    (output.parent / (output.name + '-build.json')).write_text(json.dumps({'commands': commands, 'sanitizer': args.sanitizer}, indent=2) + '\n')
    subprocess.run([str(output), str(args.rounds)], check=True)


if __name__ == '__main__':
    main()
