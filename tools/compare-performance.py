"""Compare two builds of tools/benchmark with identical measurement code."""
import argparse
import json
import statistics
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    cases = {
        "normal-100k": ["-lines", "100000"],
        "long-ua-10k": ["-lines", "10000", "-padding", "3000"],
        "mixed-10k": ["-lines", "10000", "-mixed"],
    }
    result = {"repeats": args.repeats, "runs": [], "summary": {}}
    output = Path(args.output)
    # Save after each invocation so an interrupted comparison is reviewable.
    for repeat in range(args.repeats):
        for case, flags in cases.items():
            order = ("before", "after") if repeat % 2 == 0 else ("after", "before")
            for build in order:
                run = json.loads(subprocess.check_output(
                    [getattr(args, build), *flags], text=True, encoding="utf-8"))
                if run["parsed"] != run["lines"] or run["unparsed"]:
                    raise RuntimeError(f"incomplete measurement: {case}/{build}")
                run.update(case=case, build=build, repeat=repeat + 1)
                result["runs"].append(run)
                output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                print(f"{case} {build} #{repeat+1}: {run['elapsed_seconds']:.3f}s", flush=True)
    for case in cases:
        runs = [r for r in result["runs"] if r["case"] == case]
        if len({r["report_sha256"] for r in runs}) != 1:
            raise RuntimeError(f"report mismatch: {case}")
        summary = {"report_equal": True, "report_sha256": runs[0]["report_sha256"],
                   "partial": runs[0]["partial"], "warnings": runs[0]["warnings"]}
        for build in ("before", "after"):
            selected = [r for r in runs if r["build"] == build]
            summary[build] = {
                key: statistics.median(r[key] for r in selected)
                for key in ("elapsed_seconds", "analysis_alloc_bytes", "analysis_allocs")
            }
        summary["speedup"] = summary["before"]["elapsed_seconds"] / summary["after"]["elapsed_seconds"]
        summary["allocation_reduction"] = 1 - summary["after"]["analysis_alloc_bytes"] / summary["before"]["analysis_alloc_bytes"]
        result["summary"][case] = summary
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
