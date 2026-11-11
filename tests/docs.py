#!/usr/bin/env python3
"""What the README claims about the code, held to the code (design WS16).

Usage: docs.py FACTS_JSON

FACTS_JSON (written by tests/docs.nix) names the two READMEs, the flake's check names,
the topology field paths of the template and the fixtures, and the source files and
directories read below. Every claim checked here is one a reader acts on: a check that
is not in the test table, a command that does not exist, a field, alert or secret the
README does not explain. Each failure names what is missing. The script stops at the
end with every failure listed, not at the first.

What this cannot check: that the prose is right. That is read, not tested; the
procedures it describes are each pinned by the VM test the README names beside them.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys

facts = json.loads(pathlib.Path(sys.argv[1]).read_text())
readme = pathlib.Path(facts["readme"]).read_text()
template_readme = pathlib.Path(facts["templateReadme"]).read_text()
docs = {"README.md": readme, "templates/cluster/README.md": template_readme}

failures: list[str] = []
passed = 0


def check(name: str, problems: list[str]) -> None:
    global passed
    if problems:
        failures.append(f"{name}:\n    " + "\n    ".join(problems))
    else:
        passed += 1
        print(f"ok: {name}")


def read_tree(path: str) -> str:
    p = pathlib.Path(path)
    if p.is_file():
        return p.read_text()
    return "\n".join(f.read_text(errors="replace") for f in sorted(p.rglob("*")) if f.is_file())


# ── markdown helpers ─────────────────────────────────────────────────────────

FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.M | re.S)
SPAN = re.compile(r"`([^`\n]+)`")


def code_fragments(text: str) -> list[str]:
    """Fenced blocks (one fragment per line) and inline code spans outside them."""
    out = []
    for block in FENCE.findall(text):
        out.extend(block.splitlines())
    out.extend(SPAN.findall(FENCE.sub("", text)))
    return out


def table(text: str, header_first_cell: str) -> list[list[str]]:
    """The rows of every table whose first header cell is `header_first_cell`, as cells."""
    rows: list[list[str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or cells[0] != header_first_cell:
            continue
        for row in lines[i + 2 :]:
            if not row.startswith("|"):
                break
            rows.append([c.strip() for c in row.strip().strip("|").split("|")])
    return rows


def expand(span: str) -> list[str]:
    """`vlans.{control,app,storage}` -> three paths."""
    m = re.match(r"^(.*)\{([^}]*)\}(.*)$", span)
    if not m:
        return [span]
    return [x for alt in m.group(2).split(",") for x in expand(m.group(1) + alt.strip() + m.group(3))]


# ── 1. the test table ────────────────────────────────────────────────────────

rows = table(readme, "Check")
listed = [s for r in rows for s in SPAN.findall(r[0])]
checks = set(facts["checks"])
check(
    "every check in the flake has a row in the README's test table, and every row is a check",
    [f"no row for checks.{c}" for c in sorted(checks - set(listed))]
    + [f"row `{c}` is not a check" for c in sorted(set(listed) - checks)]
    + [f"`{c}` has two rows" for c in sorted({c for c in listed if listed.count(c) > 1})],
)

# ── 2. commands ──────────────────────────────────────────────────────────────

flows = read_tree(facts["avcFlows"])
actions = set(re.findall(r'@action\(\s*"([\w-]+)",\s*"([\w-]+)"', flows))
groups = {g for g, _ in actions}
# Each action's flags, from its Arg(..., flag=True) declarations.
flags: dict[tuple[str, str], set[str]] = {}
for m in re.finditer(r'@action\(\s*"([\w-]+)",\s*"([\w-]+)"(.*?)\)\ndef ', flows, re.S):
    flags[(m.group(1), m.group(2))] = set(re.findall(r'Arg\(\s*"([\w-]+)"[^)]*flag=True', m.group(3)))
if len(actions) < 30 or ("boot", "bind") not in actions:
    failures.append(f"the avc action registry did not parse ({len(actions)} actions): this test proves nothing")

core = read_tree(facts["bootCore"])
seal_usage = re.search(r"usage: cluster-boot-seal ([^\"]+)\"", core)
seal_subs = {alt.split()[0] for alt in seal_usage.group(1).split("|")} if seal_usage else set()
seal_flags = set(re.findall(r"^\s+(--[\w-]+)\)", core, re.M))
tang = read_tree(facts["tangServer"])
tang_usage = re.search(r"usage: tang-keys ([\w|-]+)", tang)
tang_subs = set(tang_usage.group(1).split("|")) if tang_usage else set()
if not seal_subs or not tang_subs or "--replace" not in seal_flags:
    failures.append("the cluster-boot-seal or tang-keys usage line did not parse: this test proves nothing")

print(
    f"parsed: {len(actions)} avc actions, cluster-boot-seal {sorted(seal_subs)} {sorted(seal_flags)}, "
    f"tang-keys {sorted(tang_subs)}"
)
problems = []
for where, text in docs.items():
    for frag in code_fragments(text):
        for m in re.finditer(r"(?:^|[\s(|;&$])avc\s+([a-z][\w-]*)(?:\s+([a-z][\w-]*))?((?:\s+\S+)*)", frag):
            g, a, rest = m.group(1), m.group(2), m.group(3) or ""
            if g not in groups:
                problems.append(f"{where}: `{frag.strip()}`: avc has no group {g!r}")
            elif a is not None and (g, a) not in actions:
                problems.append(f"{where}: `{frag.strip()}`: avc {g} has no action {a!r}")
            elif a is not None:
                for f in re.findall(r"--([\w-]+)", rest):
                    if f not in flags.get((g, a), set()):
                        problems.append(f"{where}: `{frag.strip()}`: avc {g} {a} has no flag --{f}")
        for m in re.finditer(r"cluster-boot-seal\s+([a-z][\w-]*)((?:\s+\S+)*)", frag):
            if m.group(1) not in seal_subs:
                problems.append(f"{where}: `{frag.strip()}`: cluster-boot-seal has no {m.group(1)!r}")
            for f in re.findall(r"(--[\w-]+)", m.group(2)):
                if f not in seal_flags:
                    problems.append(f"{where}: `{frag.strip()}`: cluster-boot-seal has no flag {f}")
        for m in re.finditer(r"tang-keys\s+([a-z][\w-]*)", frag):
            if m.group(1) not in tang_subs:
                problems.append(f"{where}: `{frag.strip()}`: tang-keys has no {m.group(1)!r}")
check("every avc, cluster-boot-seal and tang-keys command in the docs exists, with its flags", problems)

# ── 3. topology fields ──────────────────────────────────────────────────────

schema_rows = [r for h in ("Field", "Node field") for r in table(readme, h)]


def covered(path: str, node_field: bool) -> bool:
    parts = path.split(".")
    for r in schema_rows:
        first = r[0]
        spans = [p for s in SPAN.findall(first) for p in expand(s)]
        row_words = set(re.findall(r"[A-Za-z0-9]+", " ".join(r)))
        for s in spans:
            sp = s.split(".")
            if node_field:
                sp = [x for x in sp if x not in ("nodes", "<name>", "<n>")]
            if parts[: len(sp)] == sp and all(p in row_words for p in parts[len(sp) :]):
                return True
    return False


problems = []
for path in sorted(set(facts["topologyPaths"])):
    node_field = path.startswith("nodes.<n>.")
    p = path.removeprefix("nodes.<n>.") if node_field else path
    if not covered(p, node_field):
        problems.append(f"topology field `{path}` is in no row of the README's topology tables")
check("every topology field in the template and the fixtures is documented in the README", problems)

# ── 4. alerts ────────────────────────────────────────────────────────────────

rules = "\n".join(read_tree(f) for f in facts["alertRules"])
alerts = set(re.findall(r'alert = "([A-Za-z0-9]+)"', rules))
documented = {s for r in table(readme, "Alert") for s in SPAN.findall(r[0])}
check(
    "every alert rule has a row in the README's alert table, and every row is a rule",
    [f"no row for alert {a}" for a in sorted(alerts - documented)]
    + [f"row `{a}` is not an alert rule" for a in sorted(documented - alerts)]
    + ([] if len(alerts) > 40 else [f"only {len(alerts)} alert rules parsed: this test proves nothing"]),
)

# What an alert email or an avc refusal tells the operator to read must be something they
# have: the README. The design and the planning notes are not published with the library.
problems = []
for m in re.finditer(r'(summary|description) = "((?:[^"\\]|\\.)*)"', rules):
    if re.search(r"\bdesign\b|plans/", m.group(2), re.I):
        problems.append(f"alert {m.group(1)} points at an unpublished document: {m.group(2)[:100]}")
avc_text = read_tree(facts["avcFlows"]) + read_tree(facts["avcCore"])
for bad in ("design section", "design's section", "plans/"):
    if bad in avc_text:
        problems.append(f"avc's source says `{bad}`, a document the operator does not have")
check("alert texts and avc point at the README, not at the design or plans/", problems)

# ── 5. secrets ───────────────────────────────────────────────────────────────


def generators(text: str) -> set[str]:
    names = set(re.findall(r"clan\.core\.vars\.generators\.([a-z][\w-]*) =", text))
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)clan\.core\.vars\.generators = \{$", line)
        if not m:
            continue
        indent = len(m.group(1))
        for inner in lines[i + 1 :]:
            if re.match(rf"^\s{{{indent}}}\}};", inner):
                break
            g = re.match(rf"^\s{{{indent + 2}}}([a-z][\w-]*) = ", inner)
            if g:
                names.add(g.group(1))
    return names


gens = set()
for f in facts["generatorFiles"]:
    gens |= generators(read_tree(f))
print(f"parsed: {len(gens)} generators: {' '.join(sorted(gens))}")
secret_rows = table(readme, "Generator")
in_table = {re.split(r"[/ ]", s)[0] for r in secret_rows for s in SPAN.findall(r[0])}
check(
    "every vars generator the modules declare has a row in the README's secrets table",
    [f"no row for generator {g}" for g in sorted(gens - in_table)]
    + [f"row `{g}` names no generator" for g in sorted(in_table - gens) if not g.startswith("<")]
    + ([] if len(gens) > 15 else [f"only {len(gens)} generators parsed: this test proves nothing"]),
)

# ── 6. paths and metrics the docs name exist in the code ────────────────────

code = read_tree(facts["modules"]) + read_tree(facts["lib"]) + flows + read_tree(facts["avcCore"])
problems = []
for where, text in docs.items():
    for frag in code_fragments(text):
        for p in re.findall(r"/(?:run|var/lib)/cluster-upgrade[\w./-]*", frag):
            p = p.rstrip(".")
            # Whole names only: `/run/cluster-upgrade.skip` must not pass on `.skip-canary`.
            if not re.search(re.escape(p) + r"(?![\w.-])", code):
                problems.append(f"{where}: {p} is named nowhere in modules/, lib/ or avc")
        for metric in re.findall(r"\bcluster_[a-z0-9_]+[a-z0-9]", frag):
            if not re.search(r"\b" + metric + r"\b", code):
                problems.append(f"{where}: metric {metric} is produced nowhere")
check("every cluster-upgrade path and cluster_* metric in the docs is in the code", problems)

# ── 7. every link inside a README goes somewhere ─────────────────────────────


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation but hyphens dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


problems = []
for where, text in docs.items():
    body = FENCE.sub("", text)
    anchors = {slug(h) for h in re.findall(r"^#+\s+(.*)$", body, re.M)}
    for target in re.findall(r"\]\(#([^)]+)\)", body):
        if target not in anchors:
            problems.append(f"{where}: link to #{target}, which no heading makes")
check("every in-page link in the docs points at a heading", problems)

# ── 8. nothing private ──────────────────────────────────────────────────────

allowed4 = [
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "0.0.0.0/32",
    )
]
problems = []
for where, text in docs.items():
    for ip in re.findall(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)", text):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not any(a in n for n in allowed4):
            problems.append(f"{where}: {ip} is not a documentation, private or loopback address")
    for user, domain in re.findall(r"([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)", text):
        if not re.search(r"(^|\.)(example\.(com|net|org)|invalid)$", domain):
            problems.append(f"{where}: {user}@{domain} is not under a reserved example domain")
check("every IPv4 address in the docs is a documentation, private or loopback one; every email an example", problems)

if failures:
    print(f"\n{passed} docs checks passed, {len(failures)} FAILED:", file=sys.stderr)
    for f in failures:
        print(f"FAILED: {f}", file=sys.stderr)
    sys.exit(1)
print(f"{passed} docs checks passed")
