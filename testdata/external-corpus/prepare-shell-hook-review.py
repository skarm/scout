#!/usr/bin/env python3
"""Build a source-only review archive from pinned Shell-hook inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent
UPSTREAM_IDS = {"gh-cli": "hook-02", "superpowers-session-start": "hook-05"}


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def verify_upstream(manifest_path, upstream, case_ids):
    manifest = json.loads(manifest_path.read_bytes())
    corpus = json.loads(upstream.read_bytes())
    if (corpus["schema_version"], corpus["kind"], corpus["sources"]) != (
        2, manifest["kind"], manifest["sources"]
    ):
        raise ValueError("upstream corpus provenance does not match the pinned manifest")

    upstream_cases = {case["id"]: case for case in corpus["cases"]}
    pinned_ids = {case["id"] for case in manifest["cases"]}
    if len(corpus["cases"]) != len(pinned_ids) or set(upstream_cases) != pinned_ids:
        raise ValueError("upstream corpus must contain exactly the pinned cases")
    if case_ids is not None and pinned_ids != case_ids.keys():
        raise ValueError("pilot case IDs do not match the pinned manifest")

    cases = []
    evidence = {}
    for entry in manifest["cases"]:
        case = upstream_cases[entry["id"]]
        if case["source_id"] != entry["source_id"]:
            raise ValueError(f"source ID does not match the pin for {entry['id']}")
        manifest_files = {file["path"]: file for file in entry["files"]}
        actual_paths = {file["path"] for file in case["files"]}
        if len(case["files"]) != len(manifest_files) or actual_paths != set(manifest_files):
            raise ValueError(f"file set does not match the pinned manifest for {entry['id']}")
        case_id = case_ids[entry["id"]] if case_ids is not None else entry["id"]
        evidence[case_id] = {}
        for file in case["files"]:
            pin = manifest_files[file["path"]]
            digest = hashlib.sha256(file["content"].encode("utf-8")).hexdigest()
            if digest != pin["sha256"] or file.get("executable", False) != pin.get("executable", False):
                raise ValueError(f"file bytes or mode do not match the pin for {entry['id']}/{file['path']}")
            evidence[case_id][file["path"]] = pin["url"]
        cases.append(make_case(case_id, entry["source_id"], case["files"]))

    return manifest["sources"], cases, evidence


def prepare(scout_dev, upstream, archive, extra_manifest=None, extra_corpus=None):
    sources, cases, evidence = verify_upstream(ROOT / "shell-hooks.sources.json", upstream, UPSTREAM_IDS)
    if extra_manifest is not None:
        extra_sources, extra_cases, extra_evidence = verify_upstream(extra_manifest, extra_corpus, None)
        if evidence.keys() & extra_evidence.keys() or {s["id"] for s in sources} & {s["id"] for s in extra_sources}:
            raise ValueError("additional cases or sources overlap the pilot")
        sources += extra_sources
        cases += extra_cases
        evidence.update(extra_evidence)

    fixture_bytes = (ROOT / "shell-hooks.blind-fixtures.json").read_bytes()
    fixtures = json.loads(fixture_bytes)
    source = {
        "id": "scout-review-fixtures",
        "origin": "authored:scout-shell-hook-review",
        "revision": hashlib.sha256(fixture_bytes).hexdigest(),
        "license": "MIT",
        "label_review": "Pending source review.",
    }
    for case in fixtures:
        cases.append(make_case(case["id"], source["id"], case["files"]))

    corpus = {
        "schema_version": 2,
        "kind": "external_unreviewed_corpus",
        "sources": sources + [source],
        "cases": sorted(cases, key=lambda case: case["id"]),
    }
    with tempfile.TemporaryDirectory(prefix="scout-shell-hook-review-") as directory:
        temp = Path(directory)
        write_json(temp / "corpus.json", corpus)
        write_json(temp / "upstream-sources.json", evidence)
        subprocess.run(
            [
                scout_dev, "corpus", "review-template",
                "--corpus", str(temp / "corpus.json"),
                "--output", str(temp / "review.json"),
            ],
            check=True,
        )
        with zipfile.ZipFile(archive, mode="x", compression=zipfile.ZIP_DEFLATED) as output:
            for name in ("corpus.json", "review.json", "upstream-sources.json"):
                output.write(temp / name, name)
            output.write(ROOT / "shell-hooks.reviewer.md", "README.md")
            output.write(ROOT.parent.parent / "LICENSE", "LICENSE-fixtures")


def make_case(case_id, source_id, files):
    return {
        "id": case_id,
        "category": "shell_hooks",
        "label": "ambiguous",
        "expected_rules": [],
        "source_id": source_id,
        "split": "holdout",
        "files": sorted(files, key=lambda file: file["path"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scout-dev", type=Path, required=True)
    parser.add_argument("--upstream-corpus", type=Path, required=True)
    parser.add_argument("--additional-manifest", type=Path)
    parser.add_argument("--additional-corpus", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.additional_manifest is None) != (args.additional_corpus is None):
        parser.error("--additional-manifest and --additional-corpus must be supplied together")
    prepare(
        str(args.scout_dev.resolve()), args.upstream_corpus, args.output,
        args.additional_manifest, args.additional_corpus,
    )
