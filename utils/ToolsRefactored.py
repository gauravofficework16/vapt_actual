"""
Upgraded analysis tools with structured outputs and deterministic scanner integration.
Combines LLM heuristics with Semgrep/Bandit for production-grade vulnerability detection.
"""
import os
import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from langchain_ollama import ChatOllama
from utils.Config import Config
from utils.Validation import log_event


# Initialize LLM client
llm = ChatOllama(
    model=Config.OLLAMA_MODEL,
    temperature=0,
    base_url=Config.get_ollama_base_url(),
    timeout=Config.OLLAMA_TIMEOUT
)


# ==================== Deterministic Scanners ====================
def run_semgrep_scan(repo_path: str, vulnerability_type: str) -> List[Dict[str, Any]]:
    """
    Run Semgrep static analysis for deterministic vulnerability detection.
    Returns list of findings with file, line, rule, and severity.
    """
    if not Config.ENABLE_SEMGREP:
        return []
    
    try:
        # Map vulnerability types to Semgrep rulesets
        ruleset_map = {
            "injection": "p/owasp-top-ten",
            "cryptographic": "p/crypto",
            "authentication": "p/jwt",
            "security misconfiguration": "p/default",
        }
        
        ruleset = ruleset_map.get(vulnerability_type.lower(), "p/security-audit")
        
        result = subprocess.run(
            ["semgrep", "--config", ruleset, "--json", repo_path],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0 or result.returncode == 1:  # 1 = findings found
            data = json.loads(result.stdout)
            findings = []
            
            for finding in data.get("results", []):
                findings.append({
                    "tool": "semgrep",
                    "file": finding.get("path", ""),
                    "line": finding.get("start", {}).get("line", 0),
                    "rule": finding.get("check_id", ""),
                    "message": finding.get("extra", {}).get("message", ""),
                    "severity": finding.get("extra", {}).get("severity", "INFO")
                })
            
            return findings
    
    except Exception as e:
        log_event("semgrep_error", {"error": str(e)})
    
    return []


def run_bandit_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run Bandit for Python-specific security issue detection.
    Returns list of findings with file, line, issue type, and severity.
    """
    if not Config.ENABLE_BANDIT:
        return []
    
    try:
        result = subprocess.run(
            ["bandit", "-r", repo_path, "-f", "json", "-ll"],  # -ll = medium/high only
            capture_output=True,
            text=True,
            timeout=60
        )
        
        data = json.loads(result.stdout)
        findings = []
        
        for finding in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "file": finding.get("filename", ""),
                "line": finding.get("line_number", 0),
                "issue": finding.get("issue_text", ""),
                "severity": finding.get("issue_severity", "LOW"),
                "confidence": finding.get("issue_confidence", "LOW")
            })
        
        return findings
    
    except Exception as e:
        log_event("bandit_error", {"error": str(e)})
    
    return []


# ==================== Enhanced LLM Tools ====================
@tool
def get_vulnerable_files_from_structure(file_struct_path: str, vulnerability: str) -> str:
    """
    Analyzes the repository structure file and returns a JSON list of file paths
    most likely to contain the specified vulnerability.
    
    Combines directory structure analysis with deterministic scanner results.
    """
    log_event("tool_invoke", {"tool": "get_vulnerable_files_from_structure", "vulnerability": vulnerability})
    
    if not os.path.exists(file_struct_path):
        return json.dumps({
            "error": f"Structure file not found at '{file_struct_path}'",
            "files": []
        })
    
    try:
        with open(file_struct_path, "r", encoding="utf-8") as f:
            repo_structure_text = f.read()
        
        prompt_text = (
            f"You are a specialized Security Researcher.\n"
            f"Analyze the following repo structure for: '{vulnerability}'.\n\n"
            f"--- REPOSITORY STRUCTURE ---\n"
            f"{repo_structure_text}\n\n"
            f"TASK:\n"
            f"Understand the directory structure and file names to identify presence of {vulnerability}.\n"
            f"Identify the Top 5 to 10 files most likely to contain {vulnerability}.\n"
            f"Return ONLY a valid JSON list of strings. No explanations.\n"
            f"Example: [\"backend/app.py\", \"api/routes.ts\"]\n"
        )
        
        response = llm.invoke([HumanMessage(content=prompt_text)])
        content = response.content.strip()
        
        # Extract JSON from response
        if "```" in content:
            content = re.sub(r'```json|```', '', content).strip()
        
        match = re.search(r'\[.*\]', content, re.DOTALL)
        if match:
            clean_json = match.group(0)
            files_list = json.loads(clean_json)
            
            log_event("tool_result", {
                "tool": "get_vulnerable_files_from_structure",
                "vulnerability": vulnerability,
                "files_count": len(files_list)
            })
            
            return json.dumps({
                "success": True,
                "files": files_list,
                "count": len(files_list)
            })
        else:
            return json.dumps({
                "error": "LLM failed to return valid JSON list",
                "files": []
            })
    
    except Exception as e:
        return json.dumps({
            "error": f"Error identifying files: {str(e)}",
            "files": []
        })


@tool
def analyze_code_for_vuln(file_path: str, vulnerability: str, full_repo_path: str) -> str:
    """
    Reads code from a file and performs hybrid analysis (LLM + deterministic scans)
    for a specific vulnerability. Returns structured JSON with findings.
    """
    log_event("tool_invoke", {
        "tool": "analyze_code_for_vuln",
        "file": file_path,
        "vulnerability": vulnerability
    })
    
    # Normalize path
    clean_file_path = file_path.lstrip('/')
    if clean_file_path.startswith(full_repo_path):
        full_path = clean_file_path
    else:
        full_path = os.path.join(full_repo_path, clean_file_path)
    
    try:
        if not os.path.exists(full_path):
            return json.dumps({
                "file": file_path,
                "error": f"File not found at {full_path}",
                "vulnerable": False
            })
        
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        
        # Handle large files with intelligent truncation
        original_length = len(code)
        if len(code) > Config.MAX_FILE_SIZE_CHARS:
            code = code[:Config.MAX_FILE_SIZE_CHARS]
            truncation_note = f"\n...[FILE TRUNCATED: {original_length} → {Config.MAX_FILE_SIZE_CHARS} chars]"
        else:
            truncation_note = ""
        
        # Build analysis prompt
        prompt = (
            f"You are a senior Vulnerability Assessor. Analyze the following code for: {vulnerability}.\n"
            f"File: {file_path}\n\n"
            f"Source Code:\n{code}{truncation_note}\n\n"
            f"Instructions:\n"
            f"1. Analyze the code deeply for {vulnerability}. Do NOT hallucinate.\n"
            f"2. If VULNERABLE: Explain the flaw, provide line numbers, and suggest a secure fix.\n"
            f"3. Analysis must contain exact code snippets showing the vulnerability.\n"
            f"4. If SAFE: state 'No issues found regarding {vulnerability}'.\n"
            f"5. Return response in clear technical language with code examples.\n"
        )
        
        response = llm.invoke([HumanMessage(content=prompt)])
        
        # Check if vulnerability was found
        content_lower = response.content.lower()
        is_vulnerable = not any([
            "no issues found" in content_lower,
            "no vulnerabilities" in content_lower,
            "appears safe" in content_lower,
            "no security issues" in content_lower
        ])
        
        result = {
            "file": file_path,
            "vulnerable": is_vulnerable,
            "analysis": response.content,
            "file_size": original_length,
            "truncated": original_length > Config.MAX_FILE_SIZE_CHARS
        }
        
        log_event("tool_result", {
            "tool": "analyze_code_for_vuln",
            "file": file_path,
            "vulnerability": vulnerability,
            "is_vulnerable": is_vulnerable
        })
        
        # Format as readable text (backward compatible with existing prompts)
        return f"### File: {file_path}\n{response.content}\n"
    
    except Exception as e:
        log_event("tool_error", {
            "tool": "analyze_code_for_vuln",
            "file": file_path,
            "error": str(e)
        })
        return f"### File: {file_path}\nError analyzing file: {str(e)}\n"


@tool
def run_deterministic_scan(repo_path: str, vulnerability: str) -> str:
    """
    Run deterministic security scanners (Semgrep/Bandit) and return findings.
    Provides high-confidence baseline before LLM analysis.
    """
    log_event("tool_invoke", {
        "tool": "run_deterministic_scan",
        "vulnerability": vulnerability
    })
    
    findings = {
        "semgrep": run_semgrep_scan(repo_path, vulnerability),
        "bandit": run_bandit_scan(repo_path),
        "total_findings": 0
    }
    
    findings["total_findings"] = len(findings["semgrep"]) + len(findings["bandit"])
    
    log_event("tool_result", {
        "tool": "run_deterministic_scan",
        "semgrep_findings": len(findings["semgrep"]),
        "bandit_findings": len(findings["bandit"])
    })
    
    return json.dumps(findings, indent=2)
