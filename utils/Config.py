"""
Centralized configuration and validation for VAPT pipeline.
All environment variables, paths, and runtime settings are managed here.
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Production-ready configuration with validation."""
    
    # ==================== Ollama Settings (Fixed as per requirement) ====================
    OLLAMA_IP: str = "172.17.63.4"
    OLLAMA_PORT: str = "11434"
    OLLAMA_MODEL: str = "gpt-oss:20b"
    OLLAMA_TIMEOUT: int = 300
    
    @classmethod
    def get_ollama_base_url(cls) -> str:
        """Return fully qualified Ollama base URL."""
        return f"http://{cls.OLLAMA_IP}:{cls.OLLAMA_PORT}"
    
    # ==================== LangSmith Settings ====================
    LANGSMITH_TRACING: str = os.getenv("LANGSMITH_TRACING", "false")
    LANGSMITH_API_KEY: Optional[str] = os.getenv("LANGSMITH_API_KEY")
    LANGSMITH_PROJECT: str = os.getenv("LANGSMITH_PROJECT", "VAPT_Pipeline")
    LANGSMITH_ENDPOINT: str = os.getenv("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com")
    
    # ==================== Git Settings ====================
    GIT_ACCESS_TOKEN: Optional[str] = os.getenv("GIT_ACCESS_TOKEN")
    
    # ==================== Path Settings ====================
    WORKSPACE_ROOT: Path = Path(__file__).parent.parent
    CLONED_CODE_DIR: Path = WORKSPACE_ROOT / "cloned_code"
    REPO_STRUCTURE_FILE: Path = WORKSPACE_ROOT / "repo_structure.txt"
    NODE_RESULTS_DIR: Path = WORKSPACE_ROOT / "Node_results"
    FINAL_REPORT_PATH: Path = WORKSPACE_ROOT / "VAPT_Final_Report.pdf"
    AUDIT_LOG_PATH: Path = WORKSPACE_ROOT / "vapt_audit.log"
    
    # ==================== Analysis Settings ====================
    MAX_FILE_SIZE_CHARS: int = 10000  # Increased from 8000
    MAX_FILES_PER_CATEGORY: int = 10
    ENABLE_SEMGREP: bool = os.getenv("ENABLE_SEMGREP", "false").lower() == "true"
    ENABLE_BANDIT: bool = os.getenv("ENABLE_BANDIT", "false").lower() == "true"
    
    # ==================== Report Settings ====================
    REPORT_GENERATION_DATE: str = "Auto-generated"
    REPORT_CONFIDENTIALITY: str = "Confidential"
    
    @classmethod
    def validate(cls) -> list[str]:
        """
        Validate critical configuration and return list of errors.
        Returns empty list if all validations pass.
        """
        errors = []
        
        # Check required environment variables
        if not cls.GIT_ACCESS_TOKEN:
            errors.append("GIT_ACCESS_TOKEN not set in environment (required for repo operations)")
        
        # Validate Ollama connectivity (optional - could be network check)
        if not cls.OLLAMA_IP or not cls.OLLAMA_PORT:
            errors.append("Ollama IP or PORT not configured")
        
        # Ensure critical directories can be created
        try:
            cls.NODE_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            cls.CLONED_CODE_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create required directories: {e}")
        
        return errors
    
    @classmethod
    def setup_environment(cls):
        """Set up environment variables for external libraries."""
        os.environ["OLLAMA_HOST"] = cls.get_ollama_base_url()
        os.environ["LANGCHAIN_TRACING_V2"] = cls.LANGSMITH_TRACING
        if cls.LANGSMITH_API_KEY:
            os.environ["LANGSMITH_API_KEY"] = cls.LANGSMITH_API_KEY


# Validate on module import
_validation_errors = Config.validate()
if _validation_errors:
    print("⚠️  Configuration warnings:")
    for error in _validation_errors:
        print(f"   - {error}")
