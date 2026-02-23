import os
import shutil
from git import Repo, GitCommandError
from langchain_core.messages import HumanMessage
from utils.Agentschema import VAPTState

def push_vapt_report_to_git(state: VAPTState) -> VAPTState:
    repo_url = state['repo_url']
    access_token = state['access_token']
    local_path = state['repo_path']
    pdf_source_path = state['final_report']
    new_branch_name = "vapt_report"

    if "https://" in repo_url:
        clean_url = repo_url.replace("https://", "")
        authenticated_url = f"https://oauth2:{access_token}@{clean_url}"
    else:
        authenticated_url = repo_url

    try:

        if os.path.exists(local_path) and os.path.isdir(os.path.join(local_path, ".git")):
            repo = Repo(local_path)
            repo.remotes.origin.set_url(authenticated_url)
        else:
            if os.path.exists(local_path):
                shutil.rmtree(local_path)
            print(f"Cloning repository...")
            repo = Repo.clone_from(authenticated_url, local_path)


        with repo.config_writer() as cw:
            cw.set_value("user", "name", "VAPT Bot")
            cw.set_value("user", "email", "vapt-bot@example.com")

        try:
            print(f"Creating orphan branch: {new_branch_name}")
            repo.git.checkout('--orphan', new_branch_name)
        except GitCommandError:

            repo.git.checkout(new_branch_name)
        
        repo.git.rm('-rf', '.', ignore_unmatch=True)

        file_name = os.path.basename(pdf_source_path)
        destination_path = os.path.join(local_path, file_name)
        shutil.copy2(pdf_source_path, destination_path)

        repo.index.add([file_name])
        repo.index.commit("Add VAPT Security Report (Standalone)")
        
        print(f"Pushing {file_name} to branch {new_branch_name}...")
        origin = repo.remote(name='origin')
        origin.push(refspec=f'{new_branch_name}:{new_branch_name}', force=True)

        success_msg = f"Success: Branch '{new_branch_name}' now contains only {file_name}."
        print(success_msg)
        state['messages'].append(HumanMessage(content=success_msg))

    except GitCommandError as e:
        error_msg = str(e).replace(access_token, "********")
        print(f"Git Error: {error_msg}")
        state['messages'].append(HumanMessage(content=f"Git Error: {error_msg}"))
    except Exception as e:
        print(f"Error: {e}")
        state['messages'].append(HumanMessage(content=str(e)))

    return state

# if __name__ == '__main__':
#     initial_state = {
#         "repo_url": "https://gitlab.com/khushi_jain-group/btp_uat_application.git",
#         "branch_name": "main",
#         "access_token": "<your-access-token>",
#         "repo_path": os.path.abspath("cloned_code"),
#         "file_struct_path": os.path.abspath("repo_structure.txt"),
#         "messages": [],
#         "sender": "",
#         "result_file_path": "",
#         "tech_stack": [],
#         "final_report":"VAPT_Final_Report.pdf",
#         "v1_msgs": [],
#         "v2_msgs": [],
#         "v3_msgs": [],
#         "v4_msgs": [],
#         "v5_msgs": [],
#         "v6_msgs": [],
#         "v7_msgs": [],
#         "v8_msgs": [],
#         "v9_msgs": [],
#         "v10_msgs": []
#     }

#     push_vapt_report_to_git(initial_state)