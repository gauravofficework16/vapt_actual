import os
from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from utils.Agentschema import VAPTState
from utils.Clonning import clone_node
from utils.Structfile import generate_repo_structure
from utils.Nodes import (
    v1_bac, v2_misconfig, v3_supply_chain, v4_crypto, v5_injection,
    v6_insecure_design, v7_auth_fail, v8_integrity_fail, v9_logging_fail, v10_expt_mishandle
)
from utils.Tools import get_vulnerable_files_from_structure, analyze_code_for_vuln
from utils.Reportgen import generate_vapt_report
from utils.Push import push_vapt_report_to_git

os.environ["LANGCHAIN_TRACING_V2"] = "false"

tools = [get_vulnerable_files_from_structure, analyze_code_for_vuln]
base_tool_node = ToolNode(tools)

def handle_tools(state: VAPTState):
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
        "v10_expt_mishandle": "v10_msgs"
    }
    
    target_key = mapping.get(sender, "messages")
    node_history = state.get(target_key, [])
    
    temp_state = state.copy()
    temp_state["messages"] = node_history
    
    tool_output = base_tool_node.invoke(temp_state)
    
    return {target_key: tool_output["messages"]}

def router(state: VAPTState) -> Literal["tools", "next"]:
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
        "v10_expt_mishandle": "v10_msgs"
    }
    
    target_key = mapping.get(sender, "messages")
    history = state.get(target_key, [])
    
    if history and hasattr(history[-1], "tool_calls") and history[-1].tool_calls:
        return "tools"
    return "next"

def tools_router(state: VAPTState) -> str:
    sender = state.get("sender", "")
    mapping = {
        "v1_bac": "v1",
        "v2_misconfig": "v2",
        "v3_supply_chain": "v3",
        "v4_crypto": "v4",
        "v5_injection": "v5",
        "v6_insecure_design": "v6",
        "v7_auth_fail": "v7",
        "v8_integrity_fail": "v8",
        "v9_logging_fail": "v9",
        "v10_expt_mishandle": "v10"
    }
    return mapping.get(sender, END)

workflow = StateGraph(VAPTState)

workflow.add_node("tools", handle_tools)
workflow.add_node("clone", clone_node)
workflow.add_node("struct", generate_repo_structure)
workflow.add_node("v1", v1_bac)
workflow.add_node("v2", v2_misconfig)
workflow.add_node("v3", v3_supply_chain)
workflow.add_node("v4", v4_crypto)
workflow.add_node("v5", v5_injection)
workflow.add_node("v6", v6_insecure_design)
workflow.add_node("v7", v7_auth_fail)
workflow.add_node("v8", v8_integrity_fail)
workflow.add_node("v9", v9_logging_fail)
workflow.add_node("v10", v10_expt_mishandle)
workflow.add_node("generate_vapt_report", generate_vapt_report)
workflow.add_node("push_to_git", push_vapt_report_to_git)

workflow.set_entry_point("clone")
workflow.add_edge("clone", "struct")
workflow.add_edge("struct", "v1")

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
workflow.add_edge("generate_vapt_report", "push_to_git")
workflow.add_edge("push_to_git", END)
workflow.add_conditional_edges(
    "tools",
    tools_router,
    {
        "v1": "v1", "v2": "v2", "v3": "v3", "v4": "v4", "v5": "v5",
        "v6": "v6", "v7": "v7", "v8": "v8", "v9": "v9", "v10": "v10"
    }
)

app = workflow.compile()

if __name__ == "__main__":
    initial_state = {
        "repo_url": "https://gitlab.com/khushi_jain-group/btp_uat_application.git",
        "branch_name": "main",
        "access_token": os.getenv("GIT_ACCESS_TOKEN", ""),
        "repo_path": os.path.abspath("cloned_code"),
        "file_struct_path": os.path.abspath("repo_structure.txt"),
        "messages": [],
        "sender": "",
        "tech_stack": [],
        "final_report":"VAPT_Final_Report.pdf",
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
    
    config = {"configurable": {"thread_id": "1"}, "recursion_limit": 500}

    try:
        for event in app.stream(initial_state, config=config):
            for node_name, state_update in event.items():
                print(f"✅ Node Finished: {node_name}")
    except Exception as e:
        print(f"Graph stopped: {str(e)}")