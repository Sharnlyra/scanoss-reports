"""
summarize_reports.py

Walks reports/<repo>/<sha>/results.json + meta.json (+ optional cbom.json)
produced by the scan workflow, and builds a single history.json file
consumed by the static dashboard (dashboard.html).

NOTE: scanoss-py's results.json structure, and SCANOSS Crypto Finder's
CBOM structure, can evolve between versions. This script defensively
handles the commonly documented shapes for each. If your installed
tool versions emit different field names, adjust extract_summary()
(for results.json) or extract_crypto_summary() (for cbom.json) below --
run one scan locally and inspect the raw files to confirm exact keys
before relying on this in production.

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


def extract_crypto_summary(cbom):
    """
    Reduce a SCANOSS Crypto Finder CycloneDX CBOM into a flat summary:
      - list of crypto assets (name, primitive, algorithm family, key size,
        quantum risk level, file locations)
      - aggregate counts by primitive and by quantum-risk category

    CBOM structure (CycloneDX 1.6 cryptographic-asset components):
      {
        "type": "cryptographic-asset",
        "name": "RSA-PKCS1-1.5-SHA-256-2048",
        "evidence": {"occurrences": [{"line": 51, "location": "src/File.java"}]},
        "cryptoProperties": {
          "assetType": "algorithm",
          "algorithmProperties": {
            "primitive": "signature",
            "algorithmFamily": "RSASSA-PKCS1",
            "parameterSetIdentifier": "2048",
            "nistQuantumSecurityLevel": 0
          }
        }
      }

    nistQuantumSecurityLevel of 0 means quantum-vulnerable (per the CBOM
    spec). Assets missing this field fall back to a name-based heuristic.
    """
    QUANTUM_VULNERABLE_HINTS = ["rsa", "dsa", "dh", "ecdh", "ecdsa", "diffie-hellman", "elliptic"]
    POST_QUANTUM_HINTS = ["kyber", "dilithium", "sphincs", "falcon", "ml-kem", "ml-dsa"]

    assets = []
    components = cbom.get("components", []) if isinstance(cbom, dict) else []

    for comp in components:
        if comp.get("type") != "cryptographic-asset":
            continue

        crypto_props = comp.get("cryptoProperties", {}) or {}
        algo_props = crypto_props.get("algorithmProperties", {}) or {}

        name = comp.get("name", "unknown")
        primitive = algo_props.get("primitive", crypto_props.get("assetType", "unknown"))
        algorithm_family = algo_props.get("algorithmFamily", "")
        param_size = algo_props.get("parameterSetIdentifier", "")

        nist_level = algo_props.get("nistQuantumSecurityLevel")
        name_lower = name.lower()
        if nist_level is not None:
            risk = "quantum-vulnerable" if nist_level == 0 else "quantum-safe"
        elif any(h in name_lower for h in POST_QUANTUM_HINTS):
            risk = "quantum-safe"
        elif any(h in name_lower for h in QUANTUM_VULNERABLE_HINTS):
            risk = "quantum-vulnerable"
        else:
            risk = "review"

        occurrences = []
        for occ in (comp.get("evidence", {}) or {}).get("occurrences", []):
            occurrences.append({
                "file": occ.get("location", "unknown"),
                "line": occ.get("line"),
            })

        assets.append({
            "name": name,
            "primitive": primitive,
            "algorithm_family": algorithm_family,
            "parameter_size": param_size,
            "quantum_risk": risk,
            "occurrences": occurrences,
        })

    primitive_counts = {}
    risk_counts = {}
    for a in assets:
        primitive_counts[a["primitive"]] = primitive_counts.get(a["primitive"], 0) + 1
        risk_counts[a["quantum_risk"]] = risk_counts.get(a["quantum_risk"], 0) + 1

    return {
        "asset_count": len(assets),
        "primitive_counts": primitive_counts,
        "risk_counts": risk_counts,
        "assets": assets,
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

    # Structure: reports/<org>/<repo>/<sha>/{results.json,meta.json,cbom.json?}
    for meta_path in reports_root.glob("*/*/*/meta.json"):
        commit_dir = meta_path.parent
        results_path = commit_dir / "results.json"
        if not results_path.exists():
            continue

        meta = load_json(meta_path)
        results = load_json(results_path)
        summary = extract_summary(results)

        cbom_path = commit_dir / "cbom.json"
        crypto_summary = None
        if cbom_path.exists():
            try:
                cbom = load_json(cbom_path)
                crypto_summary = extract_crypto_summary(cbom)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: could not parse {cbom_path}: {e}")

        entry = {**meta, "summary": summary}
        if crypto_summary is not None:
            entry["crypto"] = crypto_summary
        history.append(entry)

    history.sort(key=lambda entry: entry.get("timestamp", ""))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

    print(f"Wrote {len(history)} commit entries to {args.output}")


if __name__ == "__main__":
    main()
