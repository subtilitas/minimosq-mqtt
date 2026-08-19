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
import shutil
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


def gcov_json_flag(gcov):
    """The JSON-output flag for this gcov.

    GCC 11 replaced -i with -j for JSON output but kept -i as an alias;
    older gcov only understands -i. Ask rather than assume, so this works
    across the range of runner images.
    """
    try:
        help_text = subprocess.run([gcov, "--help"], check=False,
                                   capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit(f"coverage: {gcov} not found on PATH")
    return "-j" if "--json-format" in help_text and "-j," in help_text else "-i"


def gcov_version(gcov):
    try:
        out = subprocess.run([gcov, "--version"], check=False,
                             capture_output=True, text=True).stdout
    except FileNotFoundError:
        sys.exit(f"coverage: {gcov!r} not found on PATH — name the gcov that "
                 "matches the compiler which built the tests (e.g. --gcov gcov-13)")
    return out.splitlines()[0].strip() if out else "unknown"


def run_gcov(build_dir, out_dir, gcov):
    """Generate one JSON report per .gcda under build_dir, into out_dir.

    gcov writes its output to the *current working directory* — `-o` only
    says where to look for the object files. So each invocation runs with
    cwd set to a private output directory; that also keeps reports from
    different targets that share an object basename from overwriting each
    other, and keeps the build tree clean.
    """
    gcda = []
    for dirpath, _dirnames, filenames in os.walk(build_dir):
        gcda.extend(os.path.join(dirpath, f) for f in filenames if f.endswith(".gcda"))
    if not gcda:
        sys.exit(f"coverage: no .gcda files under {build_dir!r} — "
                 "were the tests built with --coverage and then run?")

    flag = gcov_json_flag(gcov)
    failures = []
    for index, path in enumerate(sorted(gcda)):
        target = os.path.join(out_dir, str(index))
        os.makedirs(target, exist_ok=True)
        result = subprocess.run(
            [gcov, "-b", flag, "-o", os.path.dirname(os.path.abspath(path)),
             os.path.abspath(path)],
            check=False, capture_output=True, text=True, cwd=target,
        )
        if result.returncode != 0:
            failures.append((path, result.stderr.strip()))
    if len(failures) == len(gcda):
        for path, err in failures[:3]:
            print(f"coverage: gcov failed on {path}: {err[:200]}", file=sys.stderr)
        sys.exit(f"coverage: {gcov} failed on every .gcda — most likely a gcov/gcc "
                 "version mismatch (gcov must match the compiler that built the tests)")
    for path, err in failures[:3]:
        print(f"coverage: warning: gcov failed on {path}: {err[:200]}", file=sys.stderr)
    return len(gcda)


def load_report(path):
    """Read a gcov JSON report, compressed or not.

    Which one you get depends on the gcov version, so sniff the gzip
    magic instead of trusting the file extension.
    """
    with open(path, "rb") as handle:
        magic = handle.read(2)
    opener = gzip.open if magic == b"\x1f\x8b" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def merge(report_dir, root):
    """Union coverage across translation units and instantiations."""
    lines = collections.defaultdict(dict)    # file -> {line: covered}
    branches = collections.defaultdict(dict)  # file -> {(line, idx): taken}
    reports = (glob.glob(os.path.join(report_dir, "**", "*.gcov.json.gz"), recursive=True) +
               glob.glob(os.path.join(report_dir, "**", "*.gcov.json"), recursive=True))
    if not reports:
        sys.exit("coverage: gcov produced no JSON reports (looked for *.gcov.json[.gz] "
                 f"under {report_dir!r})")

    for report in reports:
        data = load_report(report)
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
    # The measured percentage depends on the compiler: different GCC
    # releases instrument a different number of lines in template-heavy
    # headers, so the same tree can read 94% under one and 87% under
    # another. Pin the compiler that builds the tests and name the
    # matching gcov here, or the number is not comparable run to run.
    parser.add_argument("--gcov", default=os.environ.get("GCOV", "gcov"),
                        help="gcov binary matching the compiler used to build (env: GCOV)")
    parser.add_argument("--root", default=".")
    parser.add_argument("--xml")
    parser.add_argument("--summary", help="write a Markdown table here (GitHub job summary)")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--fail-under-line", type=float, default=0.0)
    parser.add_argument("--fail-under-branch", type=float, default=0.0)
    parser.add_argument("--show-missing", action="store_true")
    args = parser.parse_args()

    # Reports go to a scratch directory that is emptied first: a stale
    # report left over from an earlier run would otherwise be merged in
    # and could make a broken run look like a working one.
    report_dir = os.path.join(args.build_dir, ".coverage-json")
    shutil.rmtree(report_dir, ignore_errors=True)
    os.makedirs(report_dir, exist_ok=True)

    print(f"using {args.gcov}: {gcov_version(args.gcov)}")
    count = run_gcov(args.build_dir, report_dir, args.gcov)
    lines, branches = merge(report_dir, args.root)
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
