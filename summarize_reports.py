"""
summarize_reports.py

Walks reports/<repo>/<sha>/results.json + meta.json produced by the
scan workflow, and builds a single history.json file consumed by the
static dashboard (dashboard.html).

NOTE: scanoss-py's results.json structure can evolve between versions.
This script defensively handles a few common shapes. If your installed
scanoss-py version emits different field names, adjust the
`extract_summary()` function below -- run one scan locally and inspect
results.json to confirm exact keys before relying on this in production.

Usage:
    python summarize_reports.py --reports-dir reports --output history.json
"""

import argparse
import json
import os
from pathlib import Path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_summary(results):
    """
    Reduce a raw SCANOSS results.json into a flat summary:
      - component list (name, version, licenses, vulnerabilities, match %)
      - aggregate counts (by license, by vuln severity)
    Handles the common case where results.json is a dict keyed by file path,
    each value a list of match objects.
    """
    components = {}

    def add_component(comp_name, version, licenses, vulns, match_pct):
        key = f"{comp_name}@{version}"
        if key not in components:
            components[key] = {
                "component": comp_name,
                "version": version,
                "licenses": set(),
                "vulnerabilities": [],
                "max_match_pct": 0,
            }
        entry = components[key]
        entry["licenses"].update(licenses)
        for v in vulns:
            if v not in entry["vulnerabilities"]:
                entry["vulnerabilities"].append(v)
        entry["max_match_pct"] = max(entry["max_match_pct"], match_pct)

    if isinstance(results, dict):
        for _file_path, matches in results.items():
            if not isinstance(matches, list):
                continue
            for match in matches:
                comp_name = (
                    match.get("component")
                    or match.get("purl", [None])[0]
                    or match.get("vendor", "")
                )
                version = match.get("version", "unknown")

                licenses_raw = match.get("licenses", [])
                licenses = []
                for lic in licenses_raw:
                    if isinstance(lic, dict):
                        licenses.append(lic.get("name", "unknown"))
                    else:
                        licenses.append(str(lic))

                vulns_raw = match.get("vulnerabilities", [])
                vulns = []
                for v in vulns_raw:
                    if isinstance(v, dict):
                        vulns.append(
                            {
                                "id": v.get("ID") or v.get("id", "unknown"),
                                "severity": v.get("severity", "unknown"),
                            }
                        )

                match_pct_raw = match.get("matched", "0%")
                try:
                    match_pct = float(str(match_pct_raw).replace("%", ""))
                except ValueError:
                    match_pct = 0.0

                if comp_name:
                    add_component(comp_name, version, licenses, vulns, match_pct)

    # finalize sets -> lists
    component_list = []
    for entry in components.values():
        entry["licenses"] = sorted(entry["licenses"])
        component_list.append(entry)

    severity_counts = {}
    for c in component_list:
        for v in c["vulnerabilities"]:
            sev = v.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    license_counts = {}
    for c in component_list:
        for lic in c["licenses"]:
            license_counts[lic] = license_counts.get(lic, 0) + 1

    avg_match_pct = (
        sum(c["max_match_pct"] for c in component_list) / len(component_list)
        if component_list
        else 0
    )

    return {
        "component_count": len(component_list),
        "vulnerability_count": sum(len(c["vulnerabilities"]) for c in component_list),
        "severity_counts": severity_counts,
        "license_counts": license_counts,
        "avg_snippet_match_pct": round(avg_match_pct, 2),
        "components": component_list,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--output", default="history.json")
    args = parser.parse_args()

    reports_root = Path(args.reports_dir)
    history = []

    if not reports_root.exists():
        print(f"No reports directory found at {reports_root}, writing empty history.")
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
        return

    # Structure: reports/<org>/<repo>/<sha>/{results.json,meta.json}
    for meta_path in reports_root.glob("*/*/*/meta.json"):
        commit_dir = meta_path.parent
        results_path = commit_dir / "results.json"
        if not results_path.exists():
            continue

        meta = load_json(meta_path)
        results = load_json(results_path)
        summary = extract_summary(results)

        history.append({**meta, "summary": summary})

    history.sort(key=lambda entry: entry.get("timestamp", ""))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    print(f"Wrote {len(history)} commit entries to {args.output}")


if __name__ == "__main__":
    main()
