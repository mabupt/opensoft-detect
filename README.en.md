# OpenSoft Detect

[![CI](https://github.com/mabupt/opensoft-detect/actions/workflows/ci.yml/badge.svg)](https://github.com/mabupt/opensoft-detect/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[中文](README.md) | **English**

A Python vulnerability detection pipeline: **static analysis + RAG context enrichment +
LLM false-positive triage + in-container dynamic verification**.

End-to-end scanning of any Python project: file filtering → multi-engine static discovery →
slicing / routing / CWE enrichment → LLM triage (with a knowledge-base feedback loop) →
**in-container dynamic proof** (dual-track taint detection + route-level DAST) →
JSON/HTML reports (four confidence tiers, CWE→ATT&CK mapping, fix diffs).

> Measured on an intentionally vulnerable Django lab (pygoat, generic code with no per-project
> special-casing): 320 static findings · LLM triage TP 305 / FP 17 ·
> **14 dynamically confirmed** (including 3 independently discovered by DAST) / 6 retry_poc.

## Architecture (6 modules)

```
main.py  ── orchestration (CLI parsing + pipeline scheduling)
│
├─ modules/preprocess           M0  file traversal & filtering → file_manifest.json
├─ modules/static_analysis      M1  Semgrep / CodeQL / pip-audit → findings.json
├─ modules/context_enrichment   M2  AST route & parameter extraction + code slicing + Qdrant → enriched_findings.json
├─ modules/llm_analysis         M3  LLM false-positive triage + vuln-feature feedback loop → verified_findings.json
├─ modules/dynamic_verification M4  import-hook patching + dual-track detection + Docker sandbox → dynamic_findings.json
└─ modules/reporting            M5  JSON/HTML reports (CWE-ATT&CK, confidence tiers, fix diffs, per-engine FP rate)
```

All artifacts land in `output/`: `file_manifest.json` → `findings.json` → `enriched_findings.json`
→ `verified_findings.json` → `dynamic_findings.json` → `final_report.json` / `final_report.html`.

## Requirements

| Item | Value |
|---|---|
| Python | 3.11+ (**any interpreter** — no hard-coded paths; missing dependencies degrade gracefully) |
| CodeQL | `codeql/codeql-bundle-win64/codeql/codeql.exe` (offline bundle, not vendored — download it to this path or set `OPENSOFT_SKIP_CODEQL=1`) |
| Qdrant | Container `opensoft_qdrant` (port 6333), collection `security_knowledge` (384-dim bge model, cached in `models/fastembed_cache`) |
| Docker | Required for dynamic verification (automatic fallback to static-only conclusions otherwise) |
| Dependencies | `pip install -r requirements.txt` plus `semgrep` and `pip-audit` |

### Environment variables (LLM — optional)

When unset, module 3 degrades and static conclusions still stand on their own.

```bash
export OPENSOFT_LLM_PROVIDER=openai                       # or anthropic
export OPENSOFT_LLM_API_BASE=https://api.example.com/v1    # OpenAI-compatible gateway
export OPENSOFT_LLM_MODEL=<model-name>
export OPENAI_API_KEY=<your-key>                           # never commit or write to artifacts
```

## Quick start

```bash
# Default: static pipeline + report (no container probes)
python main.py --target <project-path>

# With dynamic verification (probes run against a COPY of the target — your sources stay untouched)
python main.py --target <project-path> --attempt-dynamic

# One-shot benchmark: full pipeline + archive to output/bench/<name>/ + summary
python scripts/bench.py --target <project-path> --name <archive-name> --attempt-dynamic

# Other useful flags
--fix-suggest              generate fix diffs for dynamically confirmed findings (LLM, fact-checked)
--no-dast                  skip route-level DAST scanning (independent of findings; time-consuming)
--include-excluded         also scan soft-excluded files (tests/docs)
--scan-dirs A B            scan only the given subdirectories
--skip-enrich/--skip-llm/--skip-dynamic
```

## Safety and isolation

- **Copy-mounted sandbox.** Dynamic probes run against a **copy** of the target, mounted at the same
  in-container path — because dynamic verification *really exploits* the code under test, and
  "write-a-file" vulnerabilities would otherwise overwrite your sources (see the incident write-up in
  [docs/HARDENING.md](docs/HARDENING.md)). The same applies to targets outside the repo (mount point `/target`).
- **No credentials in artifacts.** `output/config_used.json` redacts `api_key` and similar fields.
- Containers have hard timeouts and are always reclaimed; probe logs are streamed for visibility.
- See [SECURITY.md](SECURITY.md) for authorized-use requirements and limitations.

## Evaluation corpora

The `test/` directory (labs and real-world projects) is **not distributed** with this repository
(third-party licensing and size) and is excluded via `.gitignore`. To reproduce the evaluation:

- pygoat: `https://github.com/adeyosemanputra/pygoat` → place under `test/goat/pygoat-master/`
- Any small/medium Python project (Flask / Django / FastAPI are supported by the dynamic stage)

## Status flow

```
NEW → UNDER_REVIEW → TRUE_POSITIVE → DYNAMIC_CONFIRMED → FIX_SUGGESTED
                    ↘ FALSE_POSITIVE / UNVERIFIED
```

## Documentation

- [docs/HARDENING.md](docs/HARDENING.md) — portability, stability and reliability engineering notes
  (degradation matrix and incident post-mortems)
- [docs/EVAL_real.md](docs/EVAL_real.md) — evaluation on real-world projects (manual triage of chainlit / pyload)
- [docs/LLM_OPTIMIZATION.md](docs/LLM_OPTIMIZATION.md) — LLM triage design (caching / routing / circuit breaking / feedback loop)
- [CHANGELOG.md](CHANGELOG.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)
