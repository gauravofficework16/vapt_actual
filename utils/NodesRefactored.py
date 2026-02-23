"""
Refactored parameterized OWASP vulnerability analysis nodes.
Replaces 10 near-duplicate functions with one factory pattern.
"""
import os
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_ollama import ChatOllama
from utils.Agentschema import VAPTState
from utils.Config import Config
from utils.OWASPConfig import get_category_config
from utils.Tools import get_vulnerable_files_from_structure, analyze_code_for_vuln
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
        
        # Build comprehensive system prompt
        focus_areas_text = "\n".join([f"   - {area}" for area in category["focus_areas"]])
        
        system_prompt = f"""
You are a Security Engineer specialized in analyzing OWASP vulnerabilities. Your goal is to find the target files for {vulnerability} and analyze them with tools. Create a detailed report of the vulnerability analysis specific for {vulnerability}.

CRITICAL AREA OF FOCUS:
{focus_areas_text}

ANALYSIS PLAN:
{category["analysis_instructions"]}

TOOL USAGE REQUIREMENTS:
1. Use 'get_vulnerable_files_from_structure' tool at start (ONLY ONCE) to filter the directory structure from {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
2. Extract the list of filenames returned by the tool.
3. Pass these specific filenames into the 'analyze_code_for_vuln' tool ONE BY ONE to retrieve their code content from {repo_path}.
4. Analyze the code content returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} ONLY ONCE. Analyze every identified file.
6. Do NOT hallucinate findings. Only report issues present in the actual code.

FINAL REPORT FORMAT:
1. Vulnerability Name: {vulnerability}
2. Vulnerability Score: [0-10]
3. Severity: [Low | Medium | High | Critical]
4. Detailed Technical Analysis:
   - File Name: [Relative path]
   - Technical Description: Explain how the vulnerability occurs
   - Vulnerable Code Snippet: Show the exact code with the issue
   - Secure Fix: Provide a remediated version with proper security controls
   - Confidence: [High | Medium | Low] - based on evidence strength

If NO vulnerabilities are found, clearly state: "No {vulnerability} issues detected in the analyzed codebase."
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


# ==================== Create All 10 OWASP Nodes ====================
v1_bac = create_owasp_node("v1")
v2_crypto = create_owasp_node("v2")
v3_injection = create_owasp_node("v3")
v4_insecure_design = create_owasp_node("v4")
v5_misconfig = create_owasp_node("v5")
v6_components = create_owasp_node("v6")
v7_auth_fail = create_owasp_node("v7")
v8_integrity_fail = create_owasp_node("v8")
v9_logging_fail = create_owasp_node("v9")
v10_ssrf = create_owasp_node("v10")
