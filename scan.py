import ast, re, sys
path = sys.argv[1]
src = open(path).read()
lines = src.splitlines()
tree = ast.parse(src)
findings = []

def add(rule, lineno):
    findings.append((rule, lineno, lines[lineno-1].strip()))

for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func)
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                add("Shell injection (shell=True)", node.lineno)
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                add("Flask debug mode enabled", node.lineno)
        if name in ("pickle.loads", "pickle.load"):
            add("Insecure deserialization (pickle)", node.lineno)
        if name == "yaml.load" and not any(k.arg == "Loader" and "Safe" in ast.unparse(k.value) for k in node.keywords):
            add("Unsafe YAML load", node.lineno)
        if name in ("hashlib.md5", "hashlib.sha1"):
            add("Weak hash algorithm", node.lineno)
        if name in ("random.randint", "random.random", "random.choice"):
            add("Non-cryptographic random for tokens", node.lineno)
        if name in ("os.system",):
            add("OS command execution", node.lineno)
    if isinstance(node, ast.JoinedStr) and node.values and any(isinstance(v, ast.FormattedValue) for v in node.values):
        seg = ast.unparse(node)
        if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", seg, re.I):
            add("SQL built with f-string (SQL injection)", node.lineno)
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and re.search(r"(SECRET|PASSWORD|TOKEN|KEY)", t.id, re.I):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    add("Hardcoded secret/credential", node.lineno)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "app":
        pass

for i, l in enumerate(lines, 1):
    if re.search(r"\.set_cookie\(", l) and "httponly" not in l.lower():
        add("Cookie without HttpOnly/Secure flags", i)
    if re.search(r"render_template_string\(.*\+", l):
        add("Possible XSS: string concatenated into template", i)
    if re.search(r"send_file\(os\.path\.join", l):
        add("Path traversal risk: unvalidated filename", i)

for rule, ln, code in sorted(set(findings), key=lambda x: x[1]):
    print(f"L{ln:<4} {rule:<48} {code}")
print(f"\nTotal: {len(set(findings))} findings")
