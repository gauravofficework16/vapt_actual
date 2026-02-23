import os

OLLAMA_IP = "172.17.63.4"
PORT = "11434"
os.environ["OLLAMA_HOST"] = f"http://{OLLAMA_IP}:{PORT}"

LLM_CHAT_MODEL = "gpt-oss:20b"
FAISS_INDEX_PATH = "resume_faiss_index"
FILE_PATH = "Data/resume1.pdf" 

initial_state = {
        "repo_url": "https://gitlab.com/sj0927/aryan_hr_reinitialize.git",
        "branch_name": "demo",
        "access_token": "glpat-SewsOVCZFoesn_fL4ghfkm86MQp1OmhzNWVvCw.01.120sm9tkk",
        "repo_path": "cloned_code",
        "file_struct_path": "repo_structure.txt",
        "messages": [],
        "sender": "" 
    }