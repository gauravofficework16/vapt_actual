# Quick Start Commands

## First Time Setup

```bash
# 1. Install dependencies
pip install -r DUMP/requirements.txt

# 2. Configure environment
cp .env.example .env

# 3. Edit .env and set your tokens
# Required: GIT_ACCESS_TOKEN
# Optional: LANGSMITH_API_KEY, ENABLE_SEMGREP, ENABLE_BANDIT

# 4. Verify configuration
python -c "from utils.Config import Config; Config.setup_environment(); print('✅ Config OK')"
```

## Run Production Pipeline

```bash
# Full VAPT analysis
python graph_refactored.py
```

## Optional: Run Legacy Version

```bash
# If you need to compare with old behavior
python graph.py
```

## Check Outputs

```bash
# View individual vulnerability findings
ls Node_results/

# Open final report
# Windows:
start VAPT_Final_Report.pdf

# View audit log
cat vapt_audit.log
```

## Test Ollama Connection

```bash
python Test/test_ollama.py
```

## Common Workflows

### Analyze Different Repository
```bash
# Option 1: Edit .env
# Set TARGET_REPO_URL and TARGET_BRANCH

# Option 2: Override in code (graph_refactored.py line 171-172)
```

### Enable Deterministic Scanners
```bash
# Install tools (if not already)
pip install semgrep bandit

# Enable in .env
echo "ENABLE_SEMGREP=true" >> .env
echo "ENABLE_BANDIT=true" >> .env
```

### View Detailed Logs
```bash
# Filter by event type
grep "node_start" vapt_audit.log
grep "tool_invoke" vapt_audit.log
grep "pipeline_error" vapt_audit.log

# Watch in real-time (Linux/Mac)
tail -f vapt_audit.log
```

## Troubleshooting

### Configuration Issues
```bash
python -c "from utils.Config import Config; errs = Config.validate(); print('\\n'.join(errs) if errs else '✅ Valid')"
```

### State Validation
```bash
python -c "from utils.Validation import validate_state; from utils.Config import Config; state={'repo_url':'test','branch_name':'main','access_token':Config.GIT_ACCESS_TOKEN or '','repo_path':'x','file_struct_path':'x','node_results':'x','final_report':'x','tech_stack':[],'messages':[],'sender':'','v1_msgs':[],'v2_msgs':[],'v3_msgs':[],'v4_msgs':[],'v5_msgs':[],'v6_msgs':[],'v7_msgs':[],'v8_msgs':[],'v9_msgs':[],'v10_msgs':[]}; errs=validate_state(state); print('\\n'.join(errs) if errs else '✅ Valid')"
```

### Test OWASP Config
```bash
python -c "from utils.OWASPConfig import OWASP_CATEGORIES; print(f'✅ {len(OWASP_CATEGORIES)} categories loaded'); [print(f'  - {c[\"id\"]}: {c[\"name\"]}') for c in OWASP_CATEGORIES]"
```

## Performance Monitoring

```bash
# Count findings per category
for i in {1..10}; do echo -n "v$i: "; grep -c "vulnerable" Node_results/rv$i.md 2>/dev/null || echo "0"; done

# Measure pipeline duration
# Check audit log timestamps
head -1 vapt_audit.log  # Start time
tail -1 vapt_audit.log  # End time
```

## Clean Workspace

```bash
# Remove runtime artifacts (keeps source code)
rm -rf cloned_code/ Node_results/ VAPT_Final_Report.pdf vapt_audit.log repo_structure.txt .langgraph_api/

# Windows:
# rmdir /s /q cloned_code Node_results .langgraph_api
# del VAPT_Final_Report.pdf vapt_audit.log repo_structure.txt
```

## Git Operations

```bash
# View changes
git status

# Commit local modifications
git add .
git commit -m "Your message"

# Push to GitHub
git push github vapt_new_sanitized:vapt_new

# Pull latest
git pull github vapt_new
```

---

**Quick Reference:**
- Production: `python graph_refactored.py`
- Legacy: `python graph.py`
- Config: `utils/Config.py`
- Docs: `README.md`, `MIGRATION.md`, `PRODUCTION_SUMMARY.md`
