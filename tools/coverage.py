#!/usr/bin/env python3
"""Measure line and branch coverage of the minimosq headers.

Why this exists instead of a plain `gcovr` invocation
-----------------------------------------------------
minimosq is header-only and heavily templated. Every test binary is its
own translation unit, and every template instantiation inside it
(`Broker<SmallTraits>`, `Broker<TinyTraits>`, `StaticVector<OutMsg, 4>`,
...) produces its own set of gcov records for the *same* source lines.

Tools that sum those records instead of merging them report a number
that is badly wrong: broker.hpp shows up as ~4400 lines when the file is
~950, and a line exercised by one instantiation but not another counts
as a miss. Run naively, this project reports 58%; the true figure is
91%.

This script merges by source line: a line is covered if *any*
instantiation in *any* translation unit executed it, which is what
"line coverage" is normally understood to mean. It emits the same merged
data as Cobertura XML so Codecov reports the same number CI does.

Usage:
    tools/coverage.py --build-dir build [--root .]
                      [--xml coverage.xml] [--summary summary.md]
                      [--fail-under-line 90] [--fail-under-branch 78]

SPDX-License-Identifier: MIT
"""

import argparse
import collections
import glob
import gzip
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

FILTER = "include/minimosq/"

# Reporting groups, longest prefix first.
GROUPS = [
    ("include/minimosq/core/", "core (containers, spans)"),
    ("include/minimosq/protocol/", "protocol (parse/serialize)"),
    ("include/minimosq/broker/", "broker (sessions, routing, ACL)"),
    ("include/minimosq/transports/", "transports (POSIX, TLS seam)"),
    ("include/minimosq/", "top level"),
]


def run_gcov(build_dir):
    """Regenerate .gcov.json.gz next to every .gcda under build_dir."""
    gcda = []
    for dirpath, _dirnames, filenames in os.walk(build_dir):
        gcda.extend(os.path.join(dirpath, f) for f in filenames if f.endswith(".gcda"))
    if not gcda:
        sys.exit(f"coverage: no .gcda files under {build_dir!r} — "
                 "were the tests built with --coverage and then run?")
    for path in gcda:
        subprocess.run(
            ["gcov", "-b", "-j", "-o", os.path.dirname(path), path],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    return len(gcda)


def merge(build_dir, root):
    """Union coverage across translation units and instantiations."""
    lines = collections.defaultdict(dict)    # file -> {line: covered}
    branches = collections.defaultdict(dict)  # file -> {(line, idx): taken}
    reports = glob.glob(os.path.join(build_dir, "**", "*.gcov.json.gz"), recursive=True)
    if not reports:
        sys.exit("coverage: gcov produced no JSON reports")

    for report in reports:
        with gzip.open(report, "rt") as handle:
            data = json.load(handle)
        for entry in data.get("files", []):
            name = entry["file"]
            if os.path.isabs(name):
                name = os.path.relpath(name, root)
            name = os.path.normpath(name).replace(os.sep, "/")
            if not name.startswith(FILTER):
                continue
            line_map = lines[name]
            branch_map = branches[name]
            for line in entry.get("lines", []):
                number = line["line_number"]
                line_map[number] = line_map.get(number, False) or line["count"] > 0
                for index, branch in enumerate(line.get("branches", [])):
                    key = (number, index)
                    branch_map[key] = branch_map.get(key, False) or branch["count"] > 0
    if not lines:
        sys.exit(f"coverage: no data matched {FILTER!r}")
    return lines, branches


def group_of(name):
    for prefix, label in GROUPS:
        if name.startswith(prefix):
            return label
    return "other"


def table(lines, branches):
    rows = []
    for name in sorted(lines):
        hit = sum(lines[name].values())
        total = len(lines[name])
        rows.append((name, total, hit, 100.0 * hit / total if total else 100.0))

    totals = collections.Counter()
    for name, total, hit, _pct in rows:
        label = group_of(name)
        totals[label + ":total"] += total
        totals[label + ":hit"] += hit

    line_total = sum(r[1] for r in rows)
    line_hit = sum(r[2] for r in rows)
    branch_total = sum(len(b) for b in branches.values())
    branch_hit = sum(sum(b.values()) for b in branches.values())
    return rows, totals, line_total, line_hit, branch_total, branch_hit


def write_xml(path, lines, branches, root):
    """Cobertura XML built from the merged data, for Codecov."""
    line_total = sum(len(v) for v in lines.values())
    line_hit = sum(sum(v.values()) for v in lines.values())
    branch_total = sum(len(v) for v in branches.values())
    branch_hit = sum(sum(v.values()) for v in branches.values())

    cov = ET.Element("coverage", {
        "line-rate": f"{line_hit / line_total:.6f}" if line_total else "1",
        "branch-rate": f"{branch_hit / branch_total:.6f}" if branch_total else "1",
        "lines-covered": str(line_hit), "lines-valid": str(line_total),
        "branches-covered": str(branch_hit), "branches-valid": str(branch_total),
        "complexity": "0", "version": "minimosq-coverage", "timestamp": "0",
    })
    sources = ET.SubElement(cov, "sources")
    ET.SubElement(sources, "source").text = os.path.abspath(root)
    packages = ET.SubElement(cov, "packages")
    package = ET.SubElement(packages, "package", {
        "name": "minimosq", "line-rate": f"{line_hit / line_total:.6f}" if line_total else "1",
        "branch-rate": "1", "complexity": "0"})
    classes = ET.SubElement(package, "classes")

    for name in sorted(lines):
        hit = sum(lines[name].values())
        total = len(lines[name])
        cls = ET.SubElement(classes, "class", {
            "name": name.replace("/", ".").removesuffix(".hpp"),
            "filename": name,
            "line-rate": f"{hit / total:.6f}" if total else "1",
            "branch-rate": "1", "complexity": "0"})
        ET.SubElement(cls, "methods")
        line_elems = ET.SubElement(cls, "lines")
        per_line = collections.defaultdict(list)
        for (number, _idx), taken in branches.get(name, {}).items():
            per_line[number].append(taken)
        for number in sorted(lines[name]):
            covered = lines[name][number]
            attrs = {"number": str(number), "hits": "1" if covered else "0"}
            if number in per_line:
                taken = sum(per_line[number])
                total_br = len(per_line[number])
                attrs["branch"] = "true"
                attrs["condition-coverage"] = f"{100 * taken // total_br}% ({taken}/{total_br})"
            ET.SubElement(line_elems, "line", attrs)

    ET.ElementTree(cov).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--root", default=".")
    parser.add_argument("--xml")
    parser.add_argument("--summary", help="write a Markdown table here (GitHub job summary)")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--fail-under-line", type=float, default=0.0)
    parser.add_argument("--fail-under-branch", type=float, default=0.0)
    parser.add_argument("--show-missing", action="store_true")
    args = parser.parse_args()

    count = run_gcov(args.build_dir)
    lines, branches = merge(args.build_dir, args.root)
    rows, totals, l_total, l_hit, b_total, b_hit = table(lines, branches)
    line_pct = 100.0 * l_hit / l_total if l_total else 100.0
    branch_pct = 100.0 * b_hit / b_total if b_total else 100.0

    print(f"merged {count} translation units\n")
    print(f"{'file':<42}{'lines':>7}{'hit':>6}{'cover':>8}")
    print("-" * 63)
    for name, total, hit, pct in rows:
        print(f"{name.replace(FILTER, ''):<42}{total:>7}{hit:>6}{pct:>7.1f}%")
        if args.show_missing:
            missing = sorted(n for n, c in lines[name].items() if not c)
            if missing:
                print(f"    uncovered: {', '.join(map(str, missing))}")
    print("-" * 63)
    for _prefix, label in GROUPS:
        total = totals[label + ":total"]
        if total:
            hit = totals[label + ":hit"]
            print(f"{label:<42}{total:>7}{hit:>6}{100.0 * hit / total:>7.1f}%")
    print("-" * 63)
    print(f"{'TOTAL lines':<42}{l_total:>7}{l_hit:>6}{line_pct:>7.1f}%")
    print(f"{'TOTAL branches':<42}{b_total:>7}{b_hit:>6}{branch_pct:>7.1f}%")

    if args.xml:
        write_xml(args.xml, lines, branches, args.root)
        print(f"\nwrote {args.xml}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump({"line_percent": round(line_pct, 2),
                       "branch_percent": round(branch_pct, 2),
                       "lines_covered": l_hit, "lines_total": l_total,
                       "branches_covered": b_hit, "branches_total": b_total}, handle, indent=2)
        print(f"wrote {args.json_out}")
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as handle:
            handle.write("## Coverage\n\n")
            handle.write(f"**Lines {line_pct:.1f}%** ({l_hit}/{l_total}) &nbsp;·&nbsp; "
                         f"**Branches {branch_pct:.1f}%** ({b_hit}/{b_total})\n\n")
            handle.write("| Layer | Lines | Covered | Coverage |\n|---|---:|---:|---:|\n")
            for _prefix, label in GROUPS:
                total = totals[label + ":total"]
                if total:
                    hit = totals[label + ":hit"]
                    handle.write(f"| {label} | {total} | {hit} | {100.0 * hit / total:.1f}% |\n")
            handle.write("\n<details><summary>Per file</summary>\n\n")
            handle.write("| File | Lines | Covered | Coverage |\n|---|---:|---:|---:|\n")
            for name, total, hit, pct in rows:
                handle.write(f"| `{name.replace(FILTER, '')}` | {total} | {hit} | {pct:.1f}% |\n")
            handle.write("\n</details>\n")
        print(f"wrote {args.summary}")

    failed = False
    if line_pct + 1e-9 < args.fail_under_line:
        print(f"\n::error::line coverage {line_pct:.1f}% is below the "
              f"{args.fail_under_line:.1f}% floor")
        failed = True
    if branch_pct + 1e-9 < args.fail_under_branch:
        print(f"::error::branch coverage {branch_pct:.1f}% is below the "
              f"{args.fail_under_branch:.1f}% floor")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
