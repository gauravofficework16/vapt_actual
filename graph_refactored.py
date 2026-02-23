"""
Production-ready VAPT pipeline orchestrator with:
- Centralized configuration and validation
- Refactored parameterized OWASP nodes
- Structured tool outputs
- Audit logging and error handling
"""
import os
from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

# Import refactored modules
from utils.Agentschema import VAPTState
from utils.Config import Config
from utils.Validation import validate_state, sanitize_state_for_logging, log_event, ensure_paths_exist
from utils.Clonning import clone_node
from utils.Structfile import generate_repo_structure
from utils.NodesRefactored import (
    v1_bac, v2_crypto, v3_injection, v4_insecure_design, v5_misconfig,
    v6_components, v7_auth_fail, v8_integrity_fail, v9_logging_fail, v10_ssrf
)
from utils.ToolsRefactored import get_vulnerable_files_from_structure, analyze_code_for_vuln, run_deterministic_scan
from utils.Reportgen import generate_vapt_report
from utils.Push import push_vapt_report_to_git


# ==================== Setup ====================
# Configure environment variables
Config.setup_environment()

# Ensure required paths exist
ensure_paths_exist()

# Initialize tools
tools = [get_vulnerable_files_from_structure, analyze_code_for_vuln, run_deterministic_scan]
base_tool_node = ToolNode(tools)


# ==================== Tool Handling ====================
def handle_tools(state: VAPTState):
    """Route tool calls to appropriate message buffers based on sender."""
    sender = state.get("sender", "")
    
    # Map sender to message buffer key
    mapping = {
        "v1_bac": "v1_msgs",
        "v2_crypto": "v2_msgs",
        "v3_injection": "v3_msgs",
        "v4_insecure_design": "v4_msgs",
        "v5_misconfig": "v5_msgs",
        "v6_components": "v6_msgs",
        "v7_auth_fail": "v7_msgs",
        "v8_integrity_fail": "v8_msgs",
        "v9_logging_fail": "v9_msgs",
        "v10_ssrf": "v10_msgs"
    }
    
    target_key = mapping.get(sender, "messages")
    node_history = state.get(target_key, [])
    
    # Create temporary state for tool execution
    temp_state = state.copy()
    temp_state["messages"] = node_history
    
    # Execute tools
    tool_output = base_tool_node.invoke(temp_state)
    
    log_event("tool_execution", {
        "sender": sender,
        "target_buffer": target_key,
        "tool_count": len(tool_output.get("messages", []))
    })
    
    return {target_key: tool_output["messages"]}


# ==================== Routing Logic ====================
def router(state: VAPTState) -> Literal["tools", "next"]:
    """Decide whether to call tools or proceed to next node."""
    sender = state.get("sender", "")
    
    mapping = {
        "v1_bac": "v1_msgs",
        "v2_misconfig": "v2_msgs",
        "v3_supply_chain": "v3_msgs",
        "v4_crypto": "v4_msgs",
        "v5_injection": "v5_msgs",
        "v6_insecure_design": "v6_msgs",
        "v7_auth_fail": "v7_msgs",
        "v8_integrity_fail": "v8_msgs",
        "v9_logging_fail": "v9_msgs",
        "v10_ssrf": "v10_msgs"
    }
    
    target_key = mapping.get(sender, "messages")
    history = state.get(target_key, [])
    
    # Check if last message has tool calls
    if history and hasattr(history[-1], "tool_calls") and history[-1].tool_calls:
        return "tools"
    return "next"


def tools_router(state: VAPTState) -> str:
    """Return to the node that invoked tools."""
    sender = state.get("sender", "")
    
    mapping = {
        "v1_bac": "v1",
        "v2_crypto": "v2",
        "v3_injection": "v3",
        "v4_insecure_design": "v4",
        "v5_misconfig": "v5",
        "v6_components": "v6",
        "v7_auth_fail": "v7",
        "v8_integrity_fail": "v8",
        "v9_logging_fail": "v9",
        "v10_ssrf": "v10"
    }
    
    return mapping.get(sender, END)


# ==================== Build Graph ====================
workflow = StateGraph(VAPTState)

# Add all nodes
workflow.add_node("tools", handle_tools)
workflow.add_node("clone", clone_node)
workflow.add_node("struct", generate_repo_structure)
workflow.add_node("v1", v1_bac)
workflow.add_node("v2", v2_crypto)
workflow.add_node("v3", v3_injection)
workflow.add_node("v4", v4_insecure_design)
workflow.add_node("v5", v5_misconfig)
workflow.add_node("v6", v6_components)
workflow.add_node("v7", v7_auth_fail)
workflow.add_node("v8", v8_integrity_fail)
workflow.add_node("v9", v9_logging_fail)
workflow.add_node("v10", v10_ssrf)
workflow.add_node("generate_vapt_report", generate_vapt_report)
workflow.add_node("push_to_git", push_vapt_report_to_git)

# Set entry point
workflow.set_entry_point("clone")

# Add sequential edges
workflow.add_edge("clone", "struct")
workflow.add_edge("struct", "v1")

# Add conditional edges for each vulnerability node
workflow.add_conditional_edges("v1", router, {"tools": "tools", "next": "v2"})
workflow.add_conditional_edges("v2", router, {"tools": "tools", "next": "v3"})
workflow.add_conditional_edges("v3", router, {"tools": "tools", "next": "v4"})
workflow.add_conditional_edges("v4", router, {"tools": "tools", "next": "v5"})
workflow.add_conditional_edges("v5", router, {"tools": "tools", "next": "v6"})
workflow.add_conditional_edges("v6", router, {"tools": "tools", "next": "v7"})
workflow.add_conditional_edges("v7", router, {"tools": "tools", "next": "v8"})
workflow.add_conditional_edges("v8", router, {"tools": "tools", "next": "v9"})
workflow.add_conditional_edges("v9", router, {"tools": "tools", "next": "v10"})
workflow.add_conditional_edges("v10", router, {"tools": "tools", "next": "generate_vapt_report"})

# Add final edges
workflow.add_edge("generate_vapt_report", "push_to_git")
workflow.add_edge("push_to_git", END)

# Tool return routing
workflow.add_conditional_edges(
    "tools",
    tools_router,
    {
        "v1": "v1", "v2": "v2", "v3": "v3", "v4": "v4", "v5": "v5",
        "v6": "v6", "v7": "v7", "v8": "v8", "v9": "v9", "v10": "v10"
    }
)

# Compile graph
app = workflow.compile()


# ==================== Main Execution ====================
if __name__ == "__main__":
    print("🚀 VAPT Pipeline - Production Mode")
    print("=" * 60)
    
    # Build initial state with proper defaults
    initial_state = {
        "repo_url": os.getenv("TARGET_REPO_URL", "https://gitlab.com/khushi_jain-group/btp_uat_application.git"),
        "branch_name": os.getenv("TARGET_BRANCH", "main"),
        "access_token": Config.GIT_ACCESS_TOKEN or "",
        "repo_path": str(Config.CLONED_CODE_DIR),
        "file_struct_path": str(Config.REPO_STRUCTURE_FILE),
        "node_results": str(Config.NODE_RESULTS_DIR),  # FIX: Added missing key
        "final_report": str(Config.FINAL_REPORT_PATH),
        "tech_stack": [],
        "messages": [],
        "sender": "",
        "v1_msgs": [],
        "v2_msgs": [],
        "v3_msgs": [],
        "v4_msgs": [],
        "v5_msgs": [],
        "v6_msgs": [],
        "v7_msgs": [],
        "v8_msgs": [],
        "v9_msgs": [],
        "v10_msgs": []
    }
    
    # Validate state before execution
    validation_errors = validate_state(initial_state)
    if validation_errors:
        print("❌ State validation failed:")
        for error in validation_errors:
            print(f"   - {error}")
        exit(1)
    
    print("✅ Configuration validated")
    print(f"   Target: {initial_state['repo_url']}")
    print(f"   Branch: {initial_state['branch_name']}")
    print(f"   Ollama: {Config.get_ollama_base_url()}")
    print(f"   Model: {Config.OLLAMA_MODEL}")
    print("=" * 60)
    
    # Log pipeline start
    log_event("pipeline_start", sanitize_state_for_logging(initial_state))
    
    # Execute graph
    config = {"configurable": {"thread_id": "1"}, "recursion_limit": 500}
    
    try:
        for event in app.stream(initial_state, config=config):
            for node_name, state_update in event.items():
                print(f"✅ Node Finished: {node_name}")
                log_event("node_finished", {"node": node_name})
        
        log_event("pipeline_complete", {"status": "success"})
        print("\n" + "=" * 60)
        print("🎉 VAPT Pipeline completed successfully!")
        print(f"📄 Report: {Config.FINAL_REPORT_PATH}")
        print(f"📋 Audit log: {Config.AUDIT_LOG_PATH}")
        print("=" * 60)
    
    except Exception as e:
        log_event("pipeline_error", {"error": str(e)})
        print(f"\n❌ Pipeline failed: {str(e)}")
        exit(1)
