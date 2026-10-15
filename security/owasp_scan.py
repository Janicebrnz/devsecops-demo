#!/usr/bin/env python3
"""
AST-based OWASP Top 10 scanner + auto-remediator.  Python 3.9+, standard library only.

Unlike regex scanners, this parses code into a syntax tree, so it understands
structure (calls, arguments, f-strings) and does light taint tracking
(function parameters / input() / request.* are treated as untrusted).

  python3 security/owasp_scan.py                 # scan only      (exit 1 if findings)
  python3 security/owasp_scan.py --fix           # scan + rewrite (exit 0)
  python3 security/owasp_scan.py --report DIR    # also write JSON + HTML report
"""
import argparse, ast, datetime, html, json, pathlib, re, sys

ROOT = pathlib.Path(".")
SKIP = {".git", "venv", ".venv", "__pycache__", "tests", "security", "reports", "node_modules"}
SECRET = re.compile(r"(password|passwd|pwd|secret|token|api_?key|access_?key)", re.I)
SOURCES = {"input", "sys.argv", "request.args", "request.form", "request.json",
           "request.get_json", "request.args.get", "request.form.get"}
SUBPROC = {"subprocess.run", "subprocess.call", "subprocess.Popen",
           "subprocess.check_output", "subprocess.check_call"}
OWASP = {"A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection",
         "A05": "Security Misconfiguration", "A06": "Vulnerable & Outdated Components",
         "A07": "Identification & Authentication Failures", "A08": "Software & Data Integrity Failures"}


def dotted(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        base = dotted(n.value)
        return f"{base}.{n.attr}" if base else None
    return None


def env_call(name):
    return ast.Call(func=ast.Attribute(value=ast.Name("os", ast.Load()), attr="getenv", ctx=ast.Load()),
                    args=[ast.Constant(name.upper())], keywords=[])


def parameterize(js):
    """f"... WHERE n = '{x}'"  ->  ("... WHERE n = ?", [x])"""
    items = [v.value if isinstance(v, ast.Constant) else v for v in js.values]
    for i, it in enumerate(items):
        if isinstance(it, ast.FormattedValue) and 0 < i < len(items) - 1:
            prev, nxt = items[i - 1], items[i + 1]
            if isinstance(prev, str) and isinstance(nxt, str):
                for q in ("'", '"'):
                    if prev.endswith(q) and nxt.startswith(q):
                        items[i - 1], items[i + 1] = prev[:-1], nxt[1:]
                        break
    sql, params = "", []
    for it in items:
        if isinstance(it, str):
            sql += it
        else:
            sql += "?"
            params.append(it.value)
    return sql, params


class Scanner(ast.NodeTransformer):
    def __init__(self, path, fix):
        self.path, self.fix = str(path), fix
        self.findings, self.tainted, self.dynamic, self.imports = [], set(), set(), set()

    # ---------- helpers ----------
    def add(self, node, owasp, title, fixable=False, detail=""):
        status = "FIXED" if (fixable and self.fix) else ("FIXABLE" if fixable else "MANUAL")
        self.findings.append(dict(owasp=owasp, title=title, file=self.path,
                                  line=getattr(node, "lineno", 0), status=status, detail=detail))

    def is_tainted(self, n):
        for s in ast.walk(n):
            if isinstance(s, ast.Name) and s.id in self.tainted:
                return True
            if isinstance(s, (ast.Call, ast.Attribute)):
                if dotted(s.func if isinstance(s, ast.Call) else s) in SOURCES:
                    return True
        return False

    def is_dynamic(self, n):
        if isinstance(n, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in n.values)
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            return not (isinstance(n.left, ast.Constant) and isinstance(n.right, ast.Constant))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
            return True
        if isinstance(n, ast.Name):
            return n.id in self.dynamic
        return False

    # ---------- visitors ----------
    def visit_FunctionDef(self, node):
        for a in node.args.args + node.args.kwonlyargs:
            if a.arg not in ("self", "cls"):
                self.tainted.add(a.arg)          # treat parameters as untrusted input
        return self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        self.generic_visit(node)
        v = node.value
        for t in node.targets:
            if isinstance(t, ast.Name):
                if self.is_tainted(v):
                    self.tainted.add(t.id)
                if self.is_dynamic(v):
                    self.dynamic.add(t.id)
            n = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if not n:
                continue
            if SECRET.search(n) and isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                self.add(node, "A07", f"Hardcoded credential in '{n}'", fixable=True)
                if self.fix:
                    node.value = env_call(n)
                    self.imports.add("os")
            elif n.lower() == "debug" and isinstance(v, ast.Constant) and v.value is True:
                self.add(node, "A05", "Debug mode enabled", fixable=True)
                if self.fix:
                    node.value = ast.Constant(False)
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        name = dotted(node.func) or ""
        arg0 = node.args[0] if node.args else None

        if name in ("hashlib.md5", "hashlib.sha1"):
            self.add(node, "A02", f"Weak hash function {name}()", fixable=True)
            if self.fix:
                node.func.attr = "sha256"
        elif name == "yaml.load":
            self.add(node, "A08", "Unsafe yaml.load() can execute code", fixable=True)
            if self.fix:
                node.func.attr, node.keywords = "safe_load", []
        elif name == "eval":
            self.add(node, "A03", "eval() on untrusted data (code injection)", fixable=True)
            if self.fix:
                node.func = ast.Attribute(ast.Name("ast", ast.Load()), "literal_eval", ast.Load())
                node.args = node.args[:1]
                self.imports.add("ast")
        elif name == "exec":
            self.add(node, "A03", "exec() - code injection (manual fix)")
        elif name in ("pickle.load", "pickle.loads"):
            self.add(node, "A08", f"Unsafe deserialization {name}() (manual fix)")
        elif name in ("os.system", "os.popen"):
            t = arg0 is not None and self.is_tainted(arg0)
            self.add(node, "A03", f"OS command injection via {name}()", detail="tainted input" if t else "")
        elif name in SUBPROC:
            for k in node.keywords:
                if k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True:
                    self.add(node, "A03", f"{name}(shell=True) - command injection risk (manual fix)")

        for k in node.keywords:
            if not k.arg:
                continue
            if k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False:
                self.add(node, "A07", "TLS certificate verification disabled", fixable=True)
                if self.fix:
                    k.value = ast.Constant(True)
            elif k.arg == "debug" and name.endswith(".run") and isinstance(k.value, ast.Constant) and k.value.value is True:
                self.add(node, "A05", "Debug mode enabled in app.run()", fixable=True)
                if self.fix:
                    k.value = ast.Constant(False)
            elif SECRET.search(k.arg) and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str) and k.value.value:
                self.add(node, "A07", f"Hardcoded credential in argument '{k.arg}'", fixable=True)
                if self.fix:
                    k.value = env_call(k.arg)
                    self.imports.add("os")

        if name.endswith((".execute", ".executemany", ".executescript")) and arg0 is not None and self.is_dynamic(arg0):
            can = isinstance(arg0, ast.JoinedStr) and len(node.args) == 1 and name.endswith(".execute")
            self.add(node, "A03", "SQL injection: query built from dynamic string",
                     fixable=can, detail="tainted input" if self.is_tainted(arg0) else "")
            if can and self.fix:
                sql, params = parameterize(arg0)
                node.args = [ast.Constant(sql), ast.Tuple(params, ast.Load())]
        return node


def add_imports(tree, needed):
    have = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    idx = 0
    b = tree.body
    if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) \
            and isinstance(b[0].value.value, str):
        idx = 1
    while idx < len(b) and isinstance(b[idx], ast.ImportFrom) and b[idx].module == "__future__":
        idx += 1
    for mod in sorted(needed - have):
        b.insert(idx, ast.Import(names=[ast.alias(name=mod)]))


def scan_file(path, fix):
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError as e:
        print(f"[WARN] cannot parse {path}: {e}")
        return []
    sc = Scanner(path, fix)
    tree = sc.visit(tree)
    if fix and any(f["status"] == "FIXED" for f in sc.findings):
        add_imports(tree, sc.imports)
        ast.fix_missing_locations(tree)
        path.write_text(ast.unparse(tree) + "\n")
    return sc.findings


def ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def scan_deps(fix):
    req, adv = ROOT / "requirements.txt", ROOT / "security" / "advisories.json"
    if not req.exists() or not adv.exists():
        return []
    db, out, changed = json.loads(adv.read_text()), [], False
    lines = req.read_text().splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.]+)", line)
        if not m:
            continue
        pkg, v = m.groups()
        a = db.get(pkg.lower())
        if a and ver(v) < ver(a["fixed"]):
            out.append(dict(owasp="A06", title=f"{pkg} {v} has known vulnerability, fixed in {a['fixed']}",
                            file="requirements.txt", line=i + 1,
                            status="FIXED" if fix else "FIXABLE", detail=a["cve"]))
            if fix:
                lines[i], changed = f"{pkg}=={a['fixed']}", True
    if changed:
        req.write_text("\n".join(lines) + "\n")
    return out


def write_reports(d, findings):
    d = pathlib.Path(d)
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.json").write_text(json.dumps(findings, indent=2))
    colour = {"FIXED": "#1a7f37", "FIXABLE": "#9a6700", "MANUAL": "#cf222e"}
    rows = "".join(
        f"<tr><td>{f['owasp']}</td><td>{html.escape(OWASP.get(f['owasp'], ''))}</td>"
        f"<td>{html.escape(f['title'])}</td><td>{html.escape(f['file'])}:{f['line']}</td>"
        f"<td style='color:{colour[f['status']]};font-weight:bold'>{f['status']}</td></tr>" for f in findings)
    (d / "report.html").write_text(
        "<html><body style='font-family:sans-serif'><h2>OWASP Security Report</h2>"
        f"<p>{datetime.datetime.now():%Y-%m-%d %H:%M} &middot; {len(findings)} finding(s)</p>"
        "<table border=1 cellpadding=6 style='border-collapse:collapse'>"
        "<tr><th>ID</th><th>Category</th><th>Issue</th><th>Location</th><th>Status</th></tr>"
        f"{rows}</table></body></html>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--report")
    a = ap.parse_args()

    findings = []
    for p in sorted(ROOT.rglob("*.py")):
        if not any(part in SKIP for part in p.parts):
            findings += scan_file(p, a.fix)
    findings += scan_deps(a.fix)

    print(f"\n{'ID':<5}{'STATUS':<9}{'LOCATION':<24}ISSUE")
    print("-" * 78)
    for f in findings:
        print(f"{f['owasp']:<5}{f['status']:<9}{f['file'] + ':' + str(f['line']):<24}{f['title']}"
              + (f"  [{f['detail']}]" if f["detail"] else ""))
    manual = [f for f in findings if f["status"] == "MANUAL"]
    print("-" * 78)
    print(f"Total: {len(findings)} | fixed: {sum(f['status']=='FIXED' for f in findings)} | "
          f"auto-fixable: {sum(f['status']=='FIXABLE' for f in findings)} | needs manual fix: {len(manual)}")
    if a.report:
        write_reports(a.report, findings)
    if a.fix:
        return 0
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
