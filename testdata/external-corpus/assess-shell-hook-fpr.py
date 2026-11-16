#!/usr/bin/env python3
"""Measure false positives on newly reviewed external Shell-hook cases."""

import argparse
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit


def exact_upper_95(events, total):
    if events == total:
        return 1.0
    if events == 0:
        return -math.expm1(math.log(0.05) / total)

    low, high = 0.0, 1.0
    for _ in range(48):
        p = (low + high) / 2
        log_p, log_q = math.log(p), math.log1p(-p)
        cdf = math.fsum(
            math.exp(
                math.lgamma(total + 1) - math.lgamma(k + 1) - math.lgamma(total - k + 1)
                + k * log_p + (total - k) * log_q
            )
            for k in range(events + 1)
        )
        if cdf > 0.05:
            low = p
        else:
            high = p
    return high


def assess(corpus_bytes, baseline, report, threshold):
    corpus_hash = hashlib.sha256(corpus_bytes).hexdigest()
    corpus = json.loads(corpus_bytes)
    review = report.get("label_review") or {}
    gate = report.get("gate") or {}
    if (
        report.get("selected_split") != "holdout"
        or not report.get("completed")
        or not gate.get("passed")
        or not gate.get("requirements", {}).get("require_independent_holdout")
        or not review.get("independent_declared")
        or report.get("corpus_sha256") != corpus_hash
        or review.get("corpus_sha256") != corpus_hash
    ):
        raise ValueError("expected a completed independent holdout report bound to the corpus")

    old = {case["id"]: case for case in baseline["cases"]} if baseline else {}
    present = {case["id"]: case for case in corpus["cases"]}
    if any(present.get(case_id) != case for case_id, case in old.items()):
        raise ValueError("baseline cases differ from the expanded corpus")

    labels = {result["id"]: result["label"] for result in report["results"]}
    observations = {case["id"]: case for case in report["shell_hooks"]["cases"]}
    external = {
        source["id"] for source in corpus["sources"]
        if urlsplit(source["origin"]).scheme == "https"
    }
    cases = [
        case for case in present.values()
        if case["id"] not in old and case["source_id"] in external
        and case["category"] == "shell_hooks" and case["split"] == "holdout"
    ]
    if any(case["id"] not in labels or case["id"] not in observations for case in cases):
        raise ValueError("holdout report omitted a new external Shell-hook case")

    negatives = [case for case in cases if labels[case["id"]] == "benign"]
    positives = [case for case in cases if labels[case["id"]] == "signal"]
    false_positives, covered_negatives, unresolved = [], [], []
    for case in negatives:
        case_id = case["id"]
        outcome = observations[case_id]
        if outcome["observed_signals"]:
            false_positives.append(case_id)
        elif outcome["completeness"] == "complete":
            covered_negatives.append(case_id)
        else:
            unresolved.append({"id": case_id, "gaps": outcome.get("gaps", [])})

    total = len(negatives)
    errors = len(false_positives)
    maximum_errors = errors + len(unresolved)
    complete = total > 0 and not unresolved
    optimistic = exact_upper_95(errors, total) if total else None
    upper = optimistic if complete else None
    pessimistic = exact_upper_95(maximum_errors, total) if unresolved else optimistic
    assessment = {
        "corpus_sha256": corpus_hash,
        "review_sha256": review["document_sha256"],
        "new_external_cases": len(cases),
        "source_groups": len({case["source_id"] for case in cases}),
        "negative_source_groups": len({case["source_id"] for case in negatives}),
        "covered_negative_source_groups": len({
            case["source_id"] for case in negatives if case["id"] in covered_negatives
        }),
        "negative_cases": total,
        "false_positives": false_positives,
        "covered_negatives": covered_negatives,
        "unresolved_negatives": unresolved,
        "positive_cases": len(positives),
        "detected_positives": sum(bool(observations[case["id"]]["observed_signals"]) for case in positives),
        "ambiguous_cases": len(cases) - len(negatives) - len(positives),
        "false_positive_rate": errors / total if complete else None,
        "corpus_false_positive_rate_bounds": {
            "lower": errors / total,
            "upper": maximum_errors / total,
        } if total else None,
        "target": threshold,
        "one_sided_95_upper_if_iid": upper,
        "optimistic_one_sided_95_upper_if_iid": optimistic,
        "pessimistic_one_sided_95_upper_if_iid": pessimistic,
        "minimum_negative_cases_at_zero_false_positives_if_iid": math.ceil(math.log(0.05) / math.log1p(-threshold)),
        "target_met_under_iid_assumption": upper <= threshold if upper is not None else None,
        "inference_assumptions": (
            "The exact upper bounds assume independent, representative cases. "
            "The archive uses curated cases and may contain multiple cases per repository. "
            "The corpus rate bounds keep resolved outcomes fixed. The optimistic and pessimistic scenarios "
            "assign all unresolved cases to true negatives and false positives, respectively."
        ),
    }
    root_assumption = report["shell_hooks"].get("root_assumption")
    if root_assumption is not None:
        if not isinstance(root_assumption, dict):
            raise ValueError("invalid Shell-hook root assumption")
        assessment["root_assumption"] = root_assumption
        assessment["inference_assumptions"] += (
            " The result for the stated cases is conditional on their plugin root assumption."
        )
        if root_assumption.get("lc_all"):
            assessment["inference_assumptions"] += (
                " The evaluation also assumes the stated LC_ALL at entry to the first captured script."
            )
    return assessment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, help="pilot corpus to exclude from an expanded sample")
    parser.add_argument("--report", type=Path, required=True, help="completed scout-dev --shell-hooks report")
    parser.add_argument("--target", type=float, default=0.05)
    parser.add_argument(
        "--require-target", action="store_true",
        help="exit 1 if coverage or the exact bound cannot support the target",
    )
    args = parser.parse_args()
    if not 0 < args.target < 1:
        parser.error("--target must be between 0 and 1")
    try:
        result = assess(
            args.corpus.read_bytes(), json.loads(args.baseline.read_bytes()) if args.baseline else None,
            json.loads(args.report.read_bytes()), args.target,
        )
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return int(args.require_target and result["target_met_under_iid_assumption"] is not True)


if __name__ == "__main__":
    raise SystemExit(main())
