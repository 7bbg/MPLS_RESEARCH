import json
import os
import typing as t

from main import analyze_and_flag_path, load_trace_from_json
from techniques import Hop

def summarize_path(path: t.List[Hop]) -> t.Dict[str, int]:
    counts: t.Dict[str, int] = {}
    for h in path:
        counts[h.tunnel_type] = counts.get(h.tunnel_type, 0) + 1
    return counts

def main() -> None:
    data_dir = "data"

    files = []
    
    for fn in os.listdir(data_dir):
        if fn.endswith(".json") and ("clean" in fn or fn == "results.json" or 'run' in fn):
            files.append(os.path.join(data_dir, fn))
        if fn.endswith("_runs"):
                for fn2 in os.listdir(os.path.join(data_dir, fn)):
                    if fn2.endswith(".json") and ("clean" in fn2 or fn2 == "results.json" or 'run' in fn2):
                        files.append(os.path.join(data_dir, fn, fn2))
    
    per_trace: t.List[dict] = []
    tunnel_type_totals: t.Dict[str, int] = {}
    traces_with_any_tunnel = 0

    for fp in sorted(files):
        try:
            path = load_trace_from_json(fp)
        except Exception as e:
            per_trace.append({"file": fp, "error": str(e)})
            continue

        results = analyze_and_flag_path(path)
        print(results)
        counts = summarize_path(path)

        any_tunnel = any(k != "IP Router" for k in counts.keys())
        if any_tunnel:
            traces_with_any_tunnel += 1

        for k, v in counts.items():
            tunnel_type_totals[k] = tunnel_type_totals.get(k, 0) + v

        per_trace.append({
            "file": fp,
            "hop_count": len(path),
            "any_tunnel": any_tunnel,
            "hop_type_counts": counts,
            "detector_results": results,
        })

    out = {
        "trace_count": len([x for x in per_trace if "error" not in x]),
        "trace_count_including_errors": len(per_trace),
        "traces_with_any_tunnel": traces_with_any_tunnel,
        "tunnel_type_totals_by_hop": tunnel_type_totals,
        "per_trace": per_trace,
    }

    with open(os.path.join(data_dir, "aggregate_analysis.json"), "w") as f:
        json.dump(out, f, indent=2)

    print("Wrote data/aggregate_analysis.json")

if __name__ == "__main__":
    main()