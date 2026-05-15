# `ironcontext` (Python wrapper)

Thin, dependency-free Python bridge to the IronContext Rust engine.

```python
import ironcontext

report = ironcontext.scan("path/to/manifest.json")
if report.has_security_issues():
    for f in report.findings:
        print(f"[{f.severity}] {f.rule} on `{f.tool}` — {f.message}")
```

Subprocess-based; works on any Python ≥ 3.9 with the `ironcontext` binary on
`$PATH`, in `./target/release/`, or pointed to via `$IRONCONTEXT_BIN`.
