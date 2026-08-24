#!/usr/bin/env python3
"""Generate the minimosq GitHub wiki from the repository.

Three kinds of page are produced:

  * curated  — Markdown under docs/ (and the README), with repository
               links rewritten so they work inside the wiki
  * derived  — the configuration reference, extracted from the comments
               in broker/config.hpp so it cannot drift, plus a memory
               footprint table measured by tools/footprint.cpp
  * extracted— the API reference, scanned from the public declarations
               of the headers

Everything is stdlib-only; the generator runs anywhere Python 3.8+ does.

Usage:
    tools/gen_docs.py --out build/wiki [--footprint build/footprint.tsv]
                      [--repo-url URL] [--commit SHA] [--check]

SPDX-License-Identifier: MIT
"""

import argparse
import os
import re
import sys

# ---------------------------------------------------------------- pages

# Curated sources: repository file -> (wiki page name, page title).
CURATED = [
    ("README.md", "Home", "minimosq"),
    ("docs/getting-started.md", "Getting-Started", "Getting started"),
    ("docs/security.md", "Security", "Security and ACLs"),
    ("docs/transports.md", "Transports", "Transports"),
    ("docs/tls.md", "TLS", "TLS integration"),
    ("docs/observability.md", "Observability", "Observability"),
    ("docs/porting.md", "Porting", "Porting guide"),
    ("docs/design.md", "Design-Notes", "Design notes"),
]

# Sidebar order; derived pages are inserted at their position.
SIDEBAR = [
    ("Home", "Home"),
    ("Getting-Started", "Getting started"),
    ("Configuration", "Configuration & footprint"),
    ("Security", "Security & ACLs"),
    ("Transports", "Transports"),
    ("TLS", "TLS"),
    ("Observability", "Observability"),
    ("Porting", "Porting"),
    ("API-Reference", "API reference"),
    ("Design-Notes", "Design notes"),
]

# Repository paths that become wiki pages, for link rewriting.
PATH_TO_PAGE = {src: page for src, page, _ in CURATED}

HEADER_ORDER = [
    ("Core", "include/minimosq/core"),
    ("Protocol", "include/minimosq/protocol"),
    ("Topics", "include/minimosq/topic.hpp"),
    ("Broker", "include/minimosq/broker"),
    ("Transports", "include/minimosq/transport.hpp"),
    ("Transport implementations", "include/minimosq/transports"),
    ("Umbrella header", "include/minimosq/minimosq.hpp"),
]


# ------------------------------------------------------- comment parsing


def leading_comment(text):
    """Return the file-level comment block as a list of stripped lines."""
    out = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("//"):
            body = line[2:]
            if body.startswith(" "):
                body = body[1:]
            if body.startswith("SPDX-License-Identifier"):
                continue
            out.append(body)
        elif line == "":
            if out:
                out.append("")
            continue
        else:
            break
    while out and out[-1] == "":
        out.pop()
    return out


def comment_to_markdown(lines):
    """Render a comment block as Markdown.

    Runs of indented lines become fenced code blocks, except when the run
    starts with a bullet, which stays a Markdown list.
    """
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent >= 2:
            run = []
            while i < len(lines) and (lines[i].strip() == "" or
                                      len(lines[i]) - len(lines[i].lstrip()) >= 2):
                run.append(lines[i])
                i += 1
            while run and run[-1].strip() == "":
                run.pop()
                i -= 1
            is_list = run[0].lstrip().startswith(("-", "*"))
            dedent = min(len(r) - len(r.lstrip()) for r in run if r.strip())
            body = [r[dedent:] if len(r) >= dedent else r for r in run]
            if is_list:
                out.extend(body)
            else:
                out.append("```cpp")
                out.extend(body)
                out.append("```")
            out.append("")
            continue
        out.append(line)
        i += 1
    # Collapse runs of blank lines.
    collapsed = []
    for line in out:
        if line == "" and collapsed and collapsed[-1] == "":
            continue
        collapsed.append(line)
    return "\n".join(collapsed).strip()


# ------------------------------------------------------- header scanning

DECL_END = re.compile(r"[;{]")
SKIP_PREFIXES = ("static_assert", "friend", "return", "#")


class HeaderScan:
    """A very small C++ scanner, sufficient for this codebase's style.

    It tracks namespace/class nesting and access specifiers, and records
    declarations that are reachable from outside (namespace scope, or
    public class members). Function bodies are skipped, so nothing inside
    an implementation is ever mistaken for API.
    """

    def __init__(self, text):
        self.lines = text.splitlines()
        self.i = 0
        self.ctx = []  # dicts: kind, name, access
        self.entities = []  # dicts: kind, name, sig, doc
        self.pending = []
        self.tail = ""

    # -- helpers ------------------------------------------------------

    def visible(self):
        for c in self.ctx:
            if c["kind"] == "class" and c["access"] != "public":
                return False
        return True

    def qualifier(self):
        return "::".join(c["name"] for c in self.ctx if c["kind"] == "class")

    def take_doc(self):
        """Take the pending comment, preserving the author's line breaks."""
        doc = list(self.pending)
        while doc and not doc[-1].strip():
            doc.pop()
        self.pending = []
        return doc

    def skip_body(self):
        """Skip a function body. The opening brace is already consumed."""
        depth = self.tail_depth(1)
        if depth <= 0:
            return  # the whole body was on the declaration's line
        while self.i < len(self.lines):
            line = strip_comment(self.lines[self.i])
            depth += line.count("{") - line.count("}")
            self.i += 1
            if depth <= 0:
                return

    def tail_depth(self, start):
        """Brace depth after accounting for text following a terminator."""
        return start + self.tail.count("{") - self.tail.count("}")

    def gather_enum_body(self):
        """Collect an enum's enumerators, rendered as a braced block."""
        depth = self.tail_depth(1)
        text = [self.tail.split("}")[0]] if self.tail.strip() else []
        while self.i < len(self.lines) and depth > 0:
            line = strip_comment(self.lines[self.i])
            self.i += 1
            depth += line.count("{") - line.count("}")
            if depth > 0:
                text.append(line.strip())
        entries = [e.strip() for e in " ".join(text).split(",") if e.strip()]
        if not entries:
            return ""
        return " {\n" + "".join(f"    {e},\n" for e in entries) + "}"

    def gather(self):
        """Collect a declaration; return (text, terminator).

        Any text following the terminator on the same line is kept in
        self.tail, so callers can account for braces that open and close
        on the declaration's own line.
        """
        parts = []
        paren = 0
        self.tail = ""
        while self.i < len(self.lines):
            line = strip_comment(self.lines[self.i]).rstrip()
            self.i += 1
            for pos, ch in enumerate(line):
                if ch in "([":
                    paren += 1
                elif ch in ")]":
                    paren -= 1
                elif ch in ";{" and paren <= 0:
                    parts.append(line[:pos])
                    self.tail = line[pos + 1:]
                    return " ".join(p.strip() for p in parts if p.strip()), ch
            parts.append(line)
        return " ".join(p.strip() for p in parts if p.strip()), ""

    # -- main loop ----------------------------------------------------

    def run(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            line = raw.strip()

            if line.startswith("//"):
                body = line[2:]
                if body.startswith(" "):
                    body = body[1:]
                self.pending.append(body)
                self.i += 1
                continue
            if line == "":
                self.pending = []
                self.i += 1
                continue
            if line.startswith("#"):
                self.pending = []
                self.i += 1
                continue
            if line in ("public:", "private:", "protected:"):
                if self.ctx and self.ctx[-1]["kind"] == "class":
                    self.ctx[-1]["access"] = line[:-1]
                self.pending = []
                self.i += 1
                continue
            if line.startswith("}"):
                if self.ctx:
                    self.ctx.pop()
                self.pending = []
                self.i += 1
                continue
            if line.startswith("namespace"):
                name = line.split()[1].rstrip("{").strip() if len(line.split()) > 1 else ""
                self.ctx.append({"kind": "namespace", "name": name, "access": "public"})
                self.pending = []
                self.i += 1
                continue

            doc = self.take_doc()
            decl, term = self.gather()
            if not decl:
                continue
            self.handle(decl, term, doc)
        return self.entities

    def handle(self, decl, term, doc):
        flat = re.sub(r"\s+", " ", decl).strip()
        if not flat or flat.startswith(SKIP_PREFIXES):
            return

        # Enums first: "enum class X" would otherwise look like a class.
        if flat.startswith("enum"):
            name = re.search(r"enum(?:\s+class)?\s+([A-Za-z_]\w*)", flat)
            body = self.gather_enum_body() if term == "{" else ""
            if self.visible() and name:
                self.record("enum", name.group(1), flat + body, doc)
            return

        m = re.search(r"\b(class|struct)\s+([A-Za-z_]\w*)", flat)
        is_type = m is not None and "(" not in flat.split(m.group(2))[0]
        if is_type and term == "{":
            if self.visible():
                self.record("class" if m.group(1) == "class" else "struct",
                            m.group(2), flat, doc)
            if self.tail_depth(1) <= 0:
                return  # empty one-liner, e.g. "struct Context {};"
            self.ctx.append({"kind": "class", "name": m.group(2),
                             "access": "private" if m.group(1) == "class" else "public"})
            return

        if term == "{":
            # A function (or other braced) definition: record, skip body.
            if self.visible():
                name = self.decl_name(flat)
                if name:
                    self.record("function", name, flat, doc)
            self.skip_body()
            return

        # Terminated by ';': declaration, alias or constant.
        if not self.visible():
            return
        name = self.decl_name(flat)
        if not name or name.endswith("_"):
            return
        kind = "alias" if flat.startswith("using") else (
            "constant" if "(" not in flat else "function")
        self.record(kind, name, flat, doc)

    @staticmethod
    def decl_name(flat):
        if flat.startswith("using"):
            m = re.match(r"using\s+([A-Za-z_]\w*)", flat)
            return m.group(1) if m else None
        # Operators, whose names are not plain identifiers.
        m = re.search(r"\boperator\s*([^\s(]*)\s*\(", flat)
        if m:
            return "operator" + m.group(1)
        # Function: identifier immediately before the argument list.
        m = re.search(r"([~A-Za-z_]\w*)\s*\(", flat)
        if m:
            return m.group(1)
        # Variable/constant: last identifier before '=' or end.
        head = flat.split("=")[0].strip()
        m = re.search(r"([A-Za-z_]\w*)\s*$", head)
        return m.group(1) if m else None

    def record(self, kind, name, sig, doc):
        if name.endswith("_"):
            return  # internal by this codebase's naming convention
        if kind == "function":
            sig = strip_init_list(sig)
        qual = self.qualifier()
        self.entities.append({
            "kind": kind,
            "name": f"{qual}::{name}" if qual else name,
            "sig": sig,
            "doc": doc,
            "depth": len([c for c in self.ctx if c["kind"] == "class"]),
        })


def strip_init_list(sig):
    """Drop a constructor's member-initializer list from a signature."""
    depth = 0
    i = 0
    while i < len(sig):
        ch = sig[i]
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        elif ch == ":" and depth == 0:
            if sig[i:i + 2] == "::":
                i += 2
                continue
            return sig[:i].rstrip()
        i += 1
    return sig


def wrap_comment(lines, pad):
    """Render a doc comment, keeping the author's line breaks."""
    return [(pad + "// " + line).rstrip() if line.strip() else pad + "//"
            for line in lines]


def strip_comment(line):
    idx = line.find("//")
    return line[:idx] if idx >= 0 else line


# --------------------------------------------------------- link rewriting


def rewrite_links(text, repo_url):
    """Point Markdown links at wiki pages or at files on GitHub.

    Fenced code blocks are left alone: C++ such as `operator[](size_t)`
    looks exactly like a Markdown link.
    """

    def repl(match):
        label, target = match.group(1), match.group(2)
        if target.startswith(("http://", "https://", "#")):
            return match.group(0)
        path = target.split("#")[0]
        anchor = target[len(path):]
        # Links between docs/ files, written relative to docs/.
        for candidate in (path, "docs/" + path):
            if candidate in PATH_TO_PAGE:
                page = PATH_TO_PAGE[candidate]
                # A label that is just the path reads badly in a wiki.
                if label in (path, candidate, os.path.basename(path)):
                    label = page.replace("-", " ")
                return f"[{label}]({page}{anchor})"
        return f"[{label}]({repo_url}/blob/main/{path}{anchor})"

    out, in_fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        out.append(line if in_fence else re.sub(r"\[([^\]]+)\]\(([^)]+)\)", repl, line))
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def demote_title(text, title):
    """Replace a leading '# ...' heading with the page's own title."""
    lines = text.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
        while lines and lines[0].strip() == "":
            lines.pop(0)
    return f"# {title}\n\n" + "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------- page builders


def build_configuration(root, footprint_path):
    """Configuration reference, extracted from broker/config.hpp."""
    src = read(os.path.join(root, "include/minimosq/broker/config.hpp"))
    body = src.split("struct DefaultTraits", 1)
    if len(body) != 2:
        die("config.hpp: DefaultTraits not found")

    rows = []
    pending = []
    for raw in body[1].splitlines():
        line = raw.strip()
        if line.startswith("//"):
            text = line[2:].strip()
            pending.append(text)
            continue
        m = re.match(r"static constexpr \w+ (\w+) = ([^;]+);", line)
        if m:
            rows.append((m.group(1), m.group(2).strip(), " ".join(pending)))
            pending = []
            continue
        if line.startswith("}"):
            break
        if line == "":
            pending = []
    if not rows:
        die("config.hpp: no traits parsed")

    out = [
        "# Configuration & footprint",
        "",
        "Every capacity in minimosq is a compile-time constant supplied by a",
        "traits type. All broker state is sized from these, so a configuration's",
        "cost is exactly `sizeof(minimosq::Broker<Traits, Transport>)` — a",
        "constant you can `static_assert` against your RAM budget.",
        "",
        "```cpp",
        "struct MyTraits {",
    ]
    for name, value, _ in rows:
        kind = "uint32_t" if name.endswith("_ms") else "size_t"
        out.append(f"    static constexpr {kind} {name} = {value};")
    out += [
        "};",
        "",
        "minimosq::Broker<MyTraits, MyTransport> broker{transport};",
        "```",
        "",
        "## Settings",
        "",
        "| Setting | Default | Meaning |",
        "| --- | --- | --- |",
    ]
    for name, value, doc in rows:
        out.append(f"| `{name}` | `{value}` | {doc or '&mdash;'} |")

    out += ["", "## Measured footprint", ""]
    if footprint_path and os.path.exists(footprint_path):
        configs, components = read_footprint(footprint_path)
        out += [
            "Produced by [`tools/footprint.cpp`](tools/footprint.cpp) during the",
            "documentation build, so these are real `sizeof` values, not estimates.",
            "",
            "| Configuration | Connections | Sessions | Max packet | Max payload | `sizeof(Broker)` |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
        for name, conns, sess, pkt, payload, size in configs:
            out.append(f"| {name} | {conns} | {sess} | {pkt} B | {payload} B | "
                       f"**{thousands(size)} B** |")
        if components:
            out += ["", "Where the bytes go in the default configuration:", "",
                    "| Component | Bytes |", "| --- | ---: |"]
            for name, size in components:
                out.append(f"| {name} | {thousands(size)} |")
        out += [
            "",
            "There is no heap use and no hidden growth: the broker never allocates",
            "after construction, so these numbers are also the peak.",
        ]
    else:
        out.append("_Footprint data unavailable in this build._")
    return "\n".join(out) + "\n"


def read_footprint(path):
    configs, components = [], []
    for line in read(path).splitlines():
        parts = line.rstrip("\n").split("\t")
        if parts[0] == "config" and len(parts) == 7:
            configs.append(tuple(parts[1:]))
        elif parts[0] == "component" and len(parts) == 3:
            components.append((parts[1], parts[2]))
    return configs, components


def thousands(value):
    try:
        return f"{int(value):,}"
    except ValueError:
        return value


def build_api_reference(root, repo_url):
    headers = []
    base = os.path.join(root, "include")
    for dirpath, _, files in os.walk(base):
        for name in sorted(files):
            if name.endswith(".hpp"):
                full = os.path.join(dirpath, name)
                headers.append(os.path.relpath(full, root).replace(os.sep, "/"))
    headers.sort()

    grouped = {title: [] for title, _ in HEADER_ORDER}
    for path in headers:
        for title, prefix in HEADER_ORDER:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                grouped[title].append(path)
                break
        else:
            grouped.setdefault("Other", []).append(path)

    out = [
        "# API reference",
        "",
        "Extracted from the public declarations of the headers. minimosq is",
        "header-only: add `include/` to your include path and include what you",
        "use, or `<minimosq/minimosq.hpp>` for the portable core.",
        "",
    ]

    problems = []
    for title, _ in HEADER_ORDER + [("Other", "")]:
        paths = grouped.get(title)
        if not paths:
            continue
        out += [f"## {title}", ""]
        for path in paths:
            text = read(os.path.join(root, path))
            doc = leading_comment(text)
            if not doc:
                problems.append(f"{path}: no file-level comment")
                summary, rest = "", ""
            else:
                summary = doc[0]
                summary = re.sub(r"^minimosq\s*[—-]\s*", "", summary).strip().rstrip(".")
                rest = comment_to_markdown(doc[1:])
            include = path[len("include/"):]
            out += [f"### `{include}`", ""]
            if summary:
                out += [f"**{summary[:1].upper()}{summary[1:]}.**", ""]
            if rest:
                out += [rest, ""]

            entities = HeaderScan(text).run()
            entities = [e for e in entities if not e["name"].startswith("_")]
            if entities:
                out += ["<details><summary>Public declarations</summary>", "", "```cpp"]
                previous_depth = 0
                open_types = []  # depths of type declarations still open
                for e in entities:
                    while open_types and e["depth"] <= open_types[-1]:
                        out.append("    " * open_types.pop() + "};")
                    pad = "    " * e["depth"]
                    if e["doc"] and e["depth"] <= previous_depth:
                        out.append("")
                    if e["doc"]:
                        out += wrap_comment(e["doc"], pad)
                    is_type = e["kind"] in ("class", "struct")
                    body = e["sig"] + (" {" if is_type else ";")
                    out += [pad + line if line else line for line in body.split("\n")]
                    if is_type:
                        open_types.append(e["depth"])
                    previous_depth = e["depth"]
                while open_types:
                    out.append("    " * open_types.pop() + "};")
                out += ["```", "</details>", ""]
            out += [f"[View source]({repo_url}/blob/main/{path})", ""]

    return "\n".join(out) + "\n", problems


def build_sidebar():
    out = ["### minimosq", ""]
    for page, label in SIDEBAR:
        out.append(f"* [{label}]({page})")
    return "\n".join(out) + "\n"


def build_footer(repo_url, commit):
    source = (f"[`{commit[:7]}`]({repo_url}/commit/{commit})" if commit
              else "a local working tree")
    return (f"_Generated from {source} by `tools/gen_docs.py`. Edits made "
            f"here are overwritten — send a pull request against `docs/` "
            f"instead._\n")


# ------------------------------------------------------------------ main


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def die(message):
    sys.stderr.write(f"gen_docs: {message}\n")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate the minimosq wiki.")
    parser.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    parser.add_argument("--out", required=True)
    parser.add_argument("--footprint")
    parser.add_argument("--repo-url", default="https://github.com/subtilitas/minimosq-mqtt")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--check", action="store_true",
                        help="fail on any extraction problem")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    repo_url = args.repo_url.rstrip("/")

    problems = []
    written = []

    for src, page, title in CURATED:
        path = os.path.join(root, src)
        if not os.path.exists(path):
            problems.append(f"missing curated source: {src}")
            continue
        text = demote_title(rewrite_links(read(path), repo_url), title)
        write(os.path.join(out_dir, page + ".md"), text)
        written.append(page)

    write(os.path.join(out_dir, "Configuration.md"),
          rewrite_links(build_configuration(root, args.footprint), repo_url))
    written.append("Configuration")

    api, api_problems = build_api_reference(root, repo_url)
    problems += api_problems
    write(os.path.join(out_dir, "API-Reference.md"), api)
    written.append("API-Reference")

    write(os.path.join(out_dir, "_Sidebar.md"), build_sidebar())
    write(os.path.join(out_dir, "_Footer.md"), build_footer(repo_url, args.commit))

    for page, _ in SIDEBAR:
        if page not in written:
            problems.append(f"sidebar references missing page: {page}")

    print(f"gen_docs: wrote {len(written) + 2} pages to {out_dir}")
    for problem in problems:
        sys.stderr.write(f"gen_docs: warning: {problem}\n")
    if problems and args.check:
        die(f"{len(problems)} problem(s) with --check enabled")


if __name__ == "__main__":
    main()
