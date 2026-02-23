"""
State validation and audit utilities for production reliability.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from utils.Config import Config


# ==================== Audit Logging ====================
def setup_audit_logger() -> logging.Logger:
    """Configure audit logger for traceability."""
    logger = logging.getLogger("vapt_audit")
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.FileHandler(Config.AUDIT_LOG_PATH, encoding="utf-8")
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


audit_log = setup_audit_logger()


def log_event(event_type: str, details: Dict[str, Any]):
    """Log structured audit event."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event_type,
        **details
    }
    audit_log.info(json.dumps(log_entry, default=str))


# ==================== State Validation ====================
REQUIRED_STATE_KEYS = [
    "repo_url",
    "branch_name",
    "access_token",
    "repo_path",
    "file_struct_path",
    "node_results",  # Added to fix contract bug
    "final_report",
    "messages",
    "sender",
]

REQUIRED_MSG_KEYS = [
    f"v{i}_msgs" for i in range(1, 11)
]


def validate_state(state: Dict[str, Any]) -> List[str]:
    """
    Validate VAPTState contains all required keys.
    Returns list of missing/invalid keys.
    """
    errors = []
    
    # Check required keys
    for key in REQUIRED_STATE_KEYS:
        if key not in state:
            errors.append(f"Missing required state key: '{key}'")
    
    # Check message buffer keys
    for key in REQUIRED_MSG_KEYS:
        if key not in state:
            errors.append(f"Missing message buffer: '{key}'")
    
    # Validate types
    if "repo_url" in state and not isinstance(state["repo_url"], str):
        errors.append("'repo_url' must be a string")
    
    if "access_token" in state and not state["access_token"]:
        errors.append("'access_token' is empty (required for git operations)")
    
    return errors


def sanitize_state_for_logging(state: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive data from state before logging."""
    safe_state = state.copy()
    
    # Redact sensitive fields
    if "access_token" in safe_state:
        safe_state["access_token"] = "***REDACTED***"
    
    # Truncate large message buffers
    for key in REQUIRED_MSG_KEYS + ["messages"]:
        if key in safe_state and isinstance(safe_state[key], list):
            safe_state[key] = f"<{len(safe_state[key])} messages>"
    
    return safe_state


# ==================== Path Validation ====================
def ensure_paths_exist():
    """Create required directories if they don't exist."""
    Config.NODE_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    Config.CLONED_CODE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Touch audit log
    Config.AUDIT_LOG_PATH.touch(exist_ok=True)
