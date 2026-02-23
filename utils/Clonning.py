import os
import stat
import shutil
from git import Repo
from langchain_core.messages import SystemMessage
from utils.Agentschema import VAPTState

def remove_readonly(func, path, _):
    """Helper to remove read-only files (git often creates these)"""
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_node(state :VAPTState):
    repo_path = state['repo_path']
    
# #del 3l
#     success_msg = f"Repository cloned to {repo_path} (demo Branch)"
#     if os.path.exists(repo_path):
#         return {"repo_path": repo_path, "messages": [SystemMessage(content=success_msg)]}
# #

    if os.path.exists(repo_path):
        try:
            shutil.rmtree(repo_path, onerror=remove_readonly)
        except Exception as e:
            return {"messages": [SystemMessage(content=f"Error cleaning directory: {e}")]}

    raw_url = state['repo_url']
    
    
    token = state['access_token']
    
    branch = state['branch_name']

    if "/-/tree/" in raw_url:
        parts = raw_url.split("/-/tree/")
        base_url = parts[0]
        if not branch:
            branch = parts[1].split('/')[0].split('?')[0]
        clean_url = base_url if base_url.endswith(".git") else f"{base_url}.git"
    else:
        clean_url = raw_url if raw_url.endswith(".git") else f"{raw_url}.git"

    if token:
        if "@" not in clean_url:
            auth_url = clean_url.replace("https://", f"https://oauth2:{token}@")
        else:
            auth_url = clean_url
    else:
        auth_url = clean_url

    try:
        if branch:
            Repo.clone_from(auth_url, repo_path, branch=branch)
            success_msg = f"Repository cloned to {repo_path} (Branch: {branch})"
        else:
            Repo.clone_from(auth_url, repo_path)
            success_msg = f"Repository cloned to {repo_path} (Default Branch)"
        
        return {"repo_path": repo_path, "messages": [SystemMessage(content=success_msg)]}
    except Exception as e:
        return {"messages": [SystemMessage(content=f"Clone Failed: {str(e)}")]}


# if __name__ == "__main__":

#     state ={
        
#         "repo_url": "https://gitlab.com/khushi_jain-group/btp_uat_application.git", 
#         "branch_name": "main",
#         "repo_path":"cloned_code",
#         "access_token":"<your-access-token>", 
        
#     }

#     result = clone_node(state)
#     print("--------------------------------------------------")
#     print("OUTPUT RESULT:")
#     print(result)
#     print("--------------------------------------------------")