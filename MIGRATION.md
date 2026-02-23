# Migration Guide: Legacy → Production

## Overview
This guide helps you migrate from `graph.py` (legacy) to `graph_refactored.py` (production).

## Key Changes

### 1. Entry Point
**Before:**
```bash
python graph.py
```

**After:**
```bash
python graph_refactored.py
```

### 2. Configuration
**Before:** Hardcoded in `graph.py` line 133
```python
"access_token": "glpat-T**********u"
```

**After:** Environment variable in `.env`
```bash
GIT_ACCESS_TOKEN="your-token-here"
```

### 3. Import Changes
**Before:**
```python
from utils.Nodes import v1_bac, v2_misconfig, ...
from utils.Tools import get_vulnerable_files_from_structure, analyze_code_for_vuln
```

**After:**
```python
from utils.NodesRefactored import v1_bac, v2_misconfig, ...
from utils.ToolsRefactored import get_vulnerable_files_from_structure, analyze_code_for_vuln, run_deterministic_scan
from utils.Config import Config
from utils.Validation import validate_state, log_event
```

### 4. State Initialization
**Before:** Missing `node_results` key
```python
initial_state = {
    "repo_url": "...",
    # node_results NOT SET - causes crash in report generation
}
```

**After:** All required keys present
```python
initial_state = {
    "repo_url": "...",
    "node_results": str(Config.NODE_RESULTS_DIR),  # FIX
    # ... all other keys validated
}
```

### 5. OWASP Category Alignment
**Before:** Categories were misaligned with official OWASP Top 10 2021
```python
v2 = "Security Misconfiguration"
v3 = "Software Supply Chain Failures"
v6 = "Insecure Design"
```

**After:** Official OWASP 2021 naming and order
```python
v2 = "A02:2021 – Cryptographic Failures"
v3 = "A03:2021 – Injection"
v6 = "A06:2021 – Vulnerable and Outdated Components"
# See https://owasp.org/Top10/
```

## Step-by-Step Migration

### Step 1: Update Dependencies
```bash
pip install -r DUMP/requirements.txt
```
Ensure `python-dotenv` is installed.

### Step 2: Create `.env` File
```bash
cp .env.example .env
```
Edit `.env` and set:
- `GIT_ACCESS_TOKEN`
- `LANGSMITH_API_KEY` (optional)
- `TARGET_REPO_URL` (optional, can override in code)

### Step 3: Test Configuration
```bash
python -c "from utils.Config import Config; print('✅ Config OK')"
```

### Step 4: Run Production Pipeline
```bash
python graph_refactored.py
```

### Step 5: Verify Outputs
Check:
- `Node_results/rv1.md` through `rv10.md` exist
- `VAPT_Final_Report.pdf` generated
- `vapt_audit.log` created with timestamped events

## Breaking Changes

| Feature | Legacy | Production |
|---------|--------|------------|
| Hardcoded token | ✅ Yes | ❌ No (env var) |
| Duplicate node code | ✅ 10 functions | ❌ 1 factory |
| State validation | ❌ None | ✅ Runtime checks |
| Audit logging | ❌ None | ✅ Full traceability |
| OWASP alignment | Partial | Official 2021 |
| Ollama config | Hardcoded | Env configurable |
| Structured output | ❌ Free text | ✅ JSON + text |
| Deterministic scans | ❌ None | ✅ Optional |

## Compatibility Notes

### ✅ Still Works
- `utils/Clonning.py` - unchanged
- `utils/Structfile.py` - unchanged
- `utils/Reportgen.py` - unchanged
- `utils/Push.py` - unchanged
- `utils/Agentschema.py` - minor update (added comment)

### ⚠️ Deprecated (but still functional)
- `graph.py` - use `graph_refactored.py` instead
- `utils/Nodes.py` - use `utils/NodesRefactored.py`
- `utils/Tools.py` - use `utils/ToolsRefactored.py`

### ❌ Removed
- None (legacy files kept for reference)

## Rollback Plan

If you need to rollback:
```bash
# Use legacy orchestrator
python graph.py

# Restore old imports (if you modified existing files)
git checkout utils/Agentschema.py
```

## Common Issues

### "Module not found: utils.Config"
**Fix:** Ensure you're using `graph_refactored.py`, not `graph.py`

### "GIT_ACCESS_TOKEN not set"
**Fix:** Create `.env` file with your token

### "State validation failed"
**Fix:** Use production orchestrator, not legacy

## Performance Comparison

| Metric | Legacy | Production |
|--------|--------|------------|
| Lines of code | ~1100 | ~650 (40% reduction) |
| Duplicate logic | High (10 nodes) | None (1 factory) |
| Error handling | Basic | Comprehensive |
| Runtime overhead | None | +2-5 seconds (validation) |
| Maintainability | Low | High |

## Support

For migration issues, check:
1. `vapt_audit.log` for detailed error context
2. Configuration validation output on startup
3. GitHub issues for known problems

---

**Migration Status**: Production-ready  
**Backward Compatibility**: Legacy files preserved  
**Risk Level**: Low (can rollback anytime)
