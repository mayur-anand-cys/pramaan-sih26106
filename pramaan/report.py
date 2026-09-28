# pramaan/report.py
"""CLI entry point: python -m pramaan.report --case PRAMAAN-001"""

import argparse
import json
import os
import sys


def _load_case_input(case_id):
    """Load case data from a JSON file or return a minimal stub.

    Looks for a file named <case_id>.json in the current directory.
    If not found, returns a minimal placeholder so the CLI can be
    exercised end-to-end without requiring real case data.
    """
    candidates = [case_id + ".json", case_id.lower() + ".json"]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), path

    # Minimal fallback so the CLI produces output for any --case value.
    stub = {
        "sha256_hash": "0" * 64,
        "risk_score": 50,
        "risk_level": "MEDIUM",
        "headers_dict": {"From": "unknown@example.com"},
        "urls": [],
        "ips": [],
        "geo_data": [],
        "risk_factors": [],
        "ml_prob": 0.5,
        "merkle_root": "0" * 64,
        "classification": "",
    }
    return stub, None


def _split_kwargs(data):
    """Split a flat case dict into (required, optional) keyword groups."""
    known_required = {
        "sha256_hash", "risk_score", "risk_level", "headers_dict",
        "urls", "ips", "geo_data", "risk_factors", "ml_prob", "merkle_root",
    }
    known_optional = {
        "case_metadata", "auth_results", "relay_hops", "xai_weights",
        "contradictions", "blockchain_tx", "etherscan_url",
        "custody_timeline", "classification",
    }
    required = {k: v for k, v in data.items() if k in known_required}
    optional = {k: v for k, v in data.items() if k in known_optional}
    return required, optional


def _generate_all(case_id, data, out_dir, formats):
    os.makedirs(out_dir, exist_ok=True)
    required, optional = _split_kwargs(data)
    kwargs = dict(required)
    kwargs.update(optional)

    written = []

    if "pdf" in formats:
        from report_gen import generate_pdf_report
        path = os.path.join(out_dir, case_id + ".pdf")
        with open(path, "wb") as f:
            f.write(generate_pdf_report(**kwargs))
        written.append(path)

    if "md" in formats or "markdown" in formats:
        from report_markdown import write_markdown_report
        path = os.path.join(out_dir, case_id + ".md")
        write_markdown_report(path, **kwargs)
        written.append(path)

    if "html" in formats:
        from report_html import write_html_report
        path = os.path.join(out_dir, case_id + ".html")
        write_html_report(path, **kwargs)
        written.append(path)

    if "stix" in formats:
        from report_stix import write_stix_report
        path = os.path.join(out_dir, case_id + ".stix.json")
        write_stix_report(path, **kwargs)
        written.append(path)

    return written


def main():
    parser = argparse.ArgumentParser(
        prog="pramaan.report",
        description="Generate forensic reports (PDF, Markdown, HTML, STIX) for a case.",
    )
    parser.add_argument("--case", required=True, help="Case ID, e.g. PRAMAAN-001")
    parser.add_argument(
        "--format",
        default="all",
        choices=["all", "pdf", "md", "markdown", "html", "stix"],
        help="Which formats to produce (default: all)",
    )
    parser.add_argument(
        "--out",
        default="reports",
        help="Output directory (default: ./reports)",
    )
    args = parser.parse_args()

    data, source = _load_case_input(args.case)

    if source:
        print("Loaded case data from: " + source)
    else:
        print("No <case>.json found; using minimal stub for " + args.case)

    formats = {"pdf", "md", "html", "stix"} if args.format == "all" else {args.format}

    written = _generate_all(args.case, data, args.out, formats)

    if not written:
        print("No files written.", file=sys.stderr)
        sys.exit(1)

    print("Wrote:")
    for p in written:
        print("  " + p)


if __name__ == "__main__":
    main()