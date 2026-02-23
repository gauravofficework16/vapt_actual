"""
Refactored parameterized OWASP Top 10:2025 vulnerability analysis nodes.
Replaces 10 near-duplicate functions with one factory pattern.
Includes anti-hallucination measures and large file handling.
"""
import os
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_ollama import ChatOllama
from utils.Agentschema import VAPTState
from utils.Config import Config
from utils.OWASPConfig import get_category_config
from utils.ToolsRefactored import get_vulnerable_files_from_structure, analyze_code_for_vuln
from utils.Validation import log_event


# Initialize model once (reused across all nodes)
model = ChatOllama(
    model=Config.OLLAMA_MODEL,
    temperature=0,
    base_url=Config.get_ollama_base_url(),
    timeout=Config.OLLAMA_TIMEOUT
).bind_tools([get_vulnerable_files_from_structure, analyze_code_for_vuln])


def create_owasp_node(node_id: str):
    """
    Factory function to create parameterized OWASP vulnerability analysis nodes.
    
    Args:
        node_id: OWASP category identifier (e.g., "v1", "v2", ...)
    
    Returns:
        Callable node function compatible with LangGraph StateGraph
    """
    category = get_category_config(node_id)
    
    def node_handler(state: VAPTState) -> dict:
        """Parameterized vulnerability analysis node."""
        print(f"🔍 {category['name']} analysis starting...")
        log_event("node_start", {"node": node_id, "category": category["name"]})
        
        file_struct_path = state["file_struct_path"]
        repo_path = state['repo_path']
        msg_key = f"{node_id}_msgs"
        messages = state.get(msg_key, [])
        
        vulnerability = category["name"]
        owasp_id = category["owasp_id"]
        
        # Build comprehensive system prompt with anti-hallucination measures
        focus_areas_text = "\n".join([f"   {i+1}. {area}" for i, area in enumerate(category["focus_areas"])])
        
        system_prompt = f"""
You are a Security Analyst performing OWASP Top 10:2025 vulnerability assessment.

CURRENT TASK: Analyze for {owasp_id} - {vulnerability}

CRITICAL INSTRUCTIONS TO PREVENT HALLUCINATION:
- ONLY report vulnerabilities that exist in ACTUAL CODE you've analyzed via tools
- DO NOT make up vulnerabilities or guess about code you haven't seen
- If a file is too large or returns an error, SKIP it and state "File too large to analyze"
- LIMIT analysis to maximum {Config.MAX_FILES_PER_CATEGORY} most critical files
- If NO vulnerabilities found after analysis, clearly state: "No {vulnerability} issues detected"

KEY VULNERABILITY PATTERNS TO DETECT:
{focus_areas_text}

DETAILED ANALYSIS GUIDELINES:
{category["analysis_instructions"]}

MANDATORY TOOL WORKFLOW:
Step 1: Call 'get_vulnerable_files_from_structure' ONCE with these inputs:
   - file_struct_path: {file_struct_path}
   - vuln_type: "{vulnerability}"
   
Step 2: Review the returned file list. Select maximum {Config.MAX_FILES_PER_CATEGORY} most relevant files.

Step 3: For each selected file, call 'analyze_code_for_vuln' tool:
   - file_path: [exact filename from structure]
   - repo_path: {repo_path}
   - vuln_type: "{vulnerability}"

Step 4: CAREFULLY analyze the ACTUAL code returned. Look for patterns from KEY VULNERABILITY PATTERNS section above.

Step 5: If file analysis returns "too large" or error, acknowledge and skip that file.

REPORT FORMAT (Only for confirmed vulnerabilities with evidence):
## {vulnerability} Assessment Report

**OWASP ID:** {owasp_id}  
**Risk Score:** [0-10 based on severity and exploitability]  
**Overall Severity:** [Low | Medium | High | Critical]

### Findings Summary
- Total Files Analyzed: [number]
- Vulnerable Files Found: [number]
- False Positives: None (evidence-based analysis)

### Detailed Findings

#### Finding 1: [Specific Vulnerability Name]
**File:** `[exact/relative/path/to/file]`  
**Line Numbers:** [if identifiable]  
**Severity:** [Critical|High|Medium|Low]  
**Confidence:** [High|Medium|Low]

**Vulnerable Code:**
```
[EXACT code snippet from the file showing the vulnerability]
```

**Vulnerability Explanation:**  
[Explain WHY this code is vulnerable - what attack is possible]

**Proof of Concept:**  
[Show how an attacker could exploit it]

**Recommended Fix:**
```
[ACTUAL fixed code with security controls]
```

**References:**  
- OWASP: https://owasp.org/Top10/{owasp_id.replace(':', '/')}

---

[Repeat for each distinct finding]

### Conclusion
[Summary of overall security posture for this category]

---

IF NO VULNERABILITIES: State clearly:
# {vulnerability} Assessment Report
**OWASP ID:** {owasp_id}  
**Status:** ✅ No {vulnerability} vulnerabilities detected in the analyzed codebase.
**Files Analyzed:** [count]
"""
        
        # Prepare input messages
        if not messages:
            input_messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=f"Perform in-depth analysis for {vulnerability}.")
            ]
        else:
            input_messages = [SystemMessage(content=system_prompt)] + messages
        
        # Invoke LLM with tools
        try:
            response = model.invoke(input_messages)
            
            # If no tool calls and we have prior messages, finalize report
            if not response.tool_calls and len(messages) > 0:
                output_path = Config.NODE_RESULTS_DIR / category["output_file"]
                
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(response.content)
                
                log_event("node_complete", {
                    "node": node_id,
                    "category": category["name"],
                    "output_file": str(output_path),
                    "content_length": len(response.content)
                })
                print(f"✅ {category['name']} analysis complete → {category['output_file']}")
            
        except Exception as e:
            log_event("node_error", {
                "node": node_id,
                "category": category["name"],
                "error": str(e)
            })
            print(f"❌ {category['name']} analysis failed: {e}")
            response = HumanMessage(content=f"Error during analysis: {str(e)}")
        
        return {msg_key: [response], "sender": category["key"]}
    
    return node_handler


# ==================== Create All 10 OWASP Top 10:2025 Nodes ====================
v1_bac = create_owasp_node("v1")                           # A01:2025 - Broken Access Control
v2_misconfig = create_owasp_node("v2")                     # A02:2025 - Security Misconfiguration
v3_supply_chain = create_owasp_node("v3")                  # A03:2025 - Software Supply Chain Failures
v4_crypto = create_owasp_node("v4")                        # A04:2025 - Cryptographic Failures
v5_injection = create_owasp_node("v5")                     # A05:2025 - Injection
v6_insecure_design = create_owasp_node("v6")               # A06:2025 - Insecure Design
v7_auth_fail = create_owasp_node("v7")                     # A07:2025 - Authentication Failures
v8_integrity_fail = create_owasp_node("v8")                # A08:2025 - Software/Data Integrity Failures
v9_logging_fail = create_owasp_node("v9")                  # A09:2025 - Security Logging/Alerting Failures
v10_exception_mishandle = create_owasp_node("v10")         # A10:2025 - Mishandling of Exceptional Conditions

