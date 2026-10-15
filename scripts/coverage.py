#!/usr/bin/env python3
"""Collect code coverage for a build configured with GCRYPT_OPENSSL_COVERAGE.

The build is instrumented with gcc/clang's --coverage, so every test run
leaves .gcda counter files next to the object files.  This script runs the
tests (optionally), feeds every counter file to gcov in JSON mode, merges
the per-line counts of all object directories (the same source is
compiled into both the shared and the static library), and writes:

  <output>/summary.txt   per-file and total line/function/branch coverage
  <output>/coverage.json the same numbers, machine readable
  <output>/index.html    the summary with links to annotated sources
  <output>/<file>.html   annotated source, executed lines green, missed red

Only files under the --source-dir's src/ directory are reported unless
--all is given.  Exit status is 1 when --min-lines or --min-branches is
not met, which makes the script usable as a CI gate.
"""
import argparse
import html
import json
import os
import shlex
import subprocess
import sys


def run(cmd, cwd=None):
    """Run a command, returning stdout; raise on failure."""
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def find_gcda(build_dir):
    for root, _dirs, files in os.walk(build_dir):
        for name in files:
            if name.endswith(".gcda"):
                yield os.path.join(root, name)


def gcov_json(gcov, gcda):
    """Return the parsed gcov JSON for one counter file."""
    cmd = gcov + ["--json-format", "--stdout", "--branch-probabilities",
                  gcda]
    out = subprocess.run(cmd, cwd=os.path.dirname(gcda), capture_output=True,
                         text=True)
    if out.returncode != 0 or not out.stdout.strip():
        sys.stderr.write("warning: gcov failed on %s: %s\n"
                         % (gcda, out.stderr.strip()))
        return None
    return json.loads(out.stdout)


class FileCoverage:
    """Merged counters for one source file."""

    def __init__(self, path):
        self.path = path
        self.lines = {}      # line number -> execution count
        self.branches = {}   # (line, index) -> taken count
        self.functions = {}  # name -> execution count

    def merge(self, data):
        for line in data.get("lines", []):
            no = line["line_number"]
            self.lines[no] = self.lines.get(no, 0) + line["count"]
            for i, br in enumerate(line.get("branches", [])):
                key = (no, i)
                self.branches[key] = self.branches.get(key, 0) + br["count"]
        for fn in data.get("functions", []):
            name = fn.get("demangled_name") or fn["name"]
            self.functions[name] = (self.functions.get(name, 0)
                                    + fn["execution_count"])

    def stats(self):
        def pair(counts):
            total = len(counts)
            hit = sum(1 for c in counts.values() if c > 0)
            return hit, total

        return {
            "lines": pair(self.lines),
            "functions": pair(self.functions),
            "branches": pair(self.branches),
        }


def pct(hit, total):
    return 100.0 * hit / total if total else 100.0


def fmt(hit, total):
    return "%5.1f%% (%5d/%5d)" % (pct(hit, total), hit, total)


def annotate_html(fc, src_path, out_path, rel):
    try:
        with open(src_path, encoding="utf-8", errors="replace") as f:
            source = f.read().split("\n")
    except OSError:
        return False
    st = fc.stats()
    rows = []
    for i, text in enumerate(source, 1):
        count = fc.lines.get(i)
        if count is None:
            cls, shown = "na", ""
        elif count == 0:
            cls, shown = "miss", "0"
        else:
            cls, shown = "hit", str(count)
        rows.append('<tr class="%s"><td class="n">%d</td><td class="c">%s'
                    '</td><td><pre>%s</pre></td></tr>'
                    % (cls, i, shown, html.escape(text)))
    page = """<!doctype html><html><head><meta charset="utf-8">
<title>%s coverage</title>
<style>
body{font-family:sans-serif;margin:1em}table{border-collapse:collapse}
td{padding:0 .5em;vertical-align:top}td.n{color:#888;text-align:right}
td.c{text-align:right;color:#444}pre{margin:0;font-size:13px}
tr.hit{background:#e6ffe6}tr.miss{background:#ffe6e6}
</style></head><body>
<p><a href="index.html">&larr; summary</a></p>
<h1>%s</h1>
<p>Lines %s &nbsp; Functions %s &nbsp; Branches %s</p>
<table>%s</table></body></html>
""" % (html.escape(rel), html.escape(rel), fmt(*st["lines"]),
       fmt(*st["functions"]), fmt(*st["branches"]), "\n".join(rows))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--source-dir", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--gcov", default="gcov",
                    help="gcov command, e.g. 'llvm-cov gcov' for clang")
    ap.add_argument("--run-tests", action="store_true",
                    help="reset counters and run ctest first")
    ap.add_argument("--all", action="store_true",
                    help="report every file, not only those under src/")
    ap.add_argument("--min-lines", type=float, default=0.0,
                    help="fail if total line coverage is below this percent")
    ap.add_argument("--min-branches", type=float, default=0.0,
                    help="fail if total branch coverage is below this percent")
    args = ap.parse_args()

    build = os.path.abspath(args.build_dir)
    srcdir = os.path.abspath(args.source_dir)
    gcov = shlex.split(args.gcov)

    if args.run_tests:
        for gcda in list(find_gcda(build)):
            os.remove(gcda)
        res = subprocess.run(["ctest", "--output-on-failure"], cwd=build)
        if res.returncode != 0:
            sys.stderr.write("warning: some tests failed; coverage is for "
                             "the tests that ran\n")

    files = {}
    seen = 0
    for gcda in find_gcda(build):
        data = gcov_json(gcov, gcda)
        if not data:
            continue
        seen += 1
        for entry in data.get("files", []):
            path = entry["file"]
            if not os.path.isabs(path):
                path = os.path.normpath(os.path.join(build, path))
            path = os.path.realpath(path)
            if not path.startswith(srcdir + os.sep):
                continue
            rel = os.path.relpath(path, srcdir)
            if not args.all and not rel.startswith("src" + os.sep):
                continue
            files.setdefault(rel, FileCoverage(path)).merge(entry)

    if not seen:
        sys.exit("no .gcda files under %s; build with "
                 "GCRYPT_OPENSSL_COVERAGE=ON and run the tests" % build)

    os.makedirs(args.output, exist_ok=True)
    totals = {"lines": [0, 0], "functions": [0, 0], "branches": [0, 0]}
    summary = {}
    for rel in sorted(files):
        st = files[rel].stats()
        summary[rel] = st
        for k in totals:
            totals[k][0] += st[k][0]
            totals[k][1] += st[k][1]

    width = max(len(r) for r in summary) if summary else 10
    lines = ["%-*s %22s %22s %22s" % (width, "file", "lines", "functions",
                                      "branches")]
    for rel, st in summary.items():
        lines.append("%-*s %s %s %s" % (width, rel, fmt(*st["lines"]),
                                        fmt(*st["functions"]),
                                        fmt(*st["branches"])))
    lines.append("%-*s %s %s %s" % (width, "TOTAL", fmt(*totals["lines"]),
                                    fmt(*totals["functions"]),
                                    fmt(*totals["branches"])))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(args.output, "summary.txt"), "w") as f:
        f.write(text)
    sys.stdout.write(text)

    with open(os.path.join(args.output, "coverage.json"), "w") as f:
        json.dump({"files": summary, "total": totals}, f, indent=1,
                  sort_keys=True)

    rows = []
    for rel, st in summary.items():
        page = rel + ".html"
        ok = annotate_html(files[rel], files[rel].path,
                           os.path.join(args.output, page), rel)
        name = ('<a href="%s">%s</a>' % (html.escape(page), html.escape(rel))
                if ok else html.escape(rel))
        rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                    % (name, fmt(*st["lines"]), fmt(*st["functions"]),
                       fmt(*st["branches"])))
    rows.append("<tr><th>TOTAL</th><th>%s</th><th>%s</th><th>%s</th></tr>"
                % (fmt(*totals["lines"]), fmt(*totals["functions"]),
                   fmt(*totals["branches"])))
    with open(os.path.join(args.output, "index.html"), "w") as f:
        f.write("""<!doctype html><html><head><meta charset="utf-8">
<title>gcrypt-openssl coverage</title>
<style>body{font-family:sans-serif;margin:1em}table{border-collapse:collapse}
td,th{padding:.2em .8em;text-align:left;border-bottom:1px solid #ddd}
td:nth-child(n+2),th:nth-child(n+2){font-family:monospace;text-align:right}
</style></head><body><h1>gcrypt-openssl coverage</h1>
<table><tr><th>file</th><th>lines</th><th>functions</th><th>branches</th>
</tr>%s</table></body></html>
""" % "\n".join(rows))

    print("report: %s" % os.path.join(args.output, "index.html"))

    failed = False
    if pct(*totals["lines"]) < args.min_lines:
        sys.stderr.write("line coverage %.1f%% is below %.1f%%\n"
                         % (pct(*totals["lines"]), args.min_lines))
        failed = True
    if pct(*totals["branches"]) < args.min_branches:
        sys.stderr.write("branch coverage %.1f%% is below %.1f%%\n"
                         % (pct(*totals["branches"]), args.min_branches))
        failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
