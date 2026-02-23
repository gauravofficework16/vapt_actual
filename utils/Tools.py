from langchain_core.tools import tool
import os
import json
import re
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage

OLLAMA_IP = "172.17.63.4" 
PORT = "11434"
os.environ["OLLAMA_HOST"] = f"http://{OLLAMA_IP}:{PORT}"

llm = ChatOllama(
    model="gpt-oss:20b", 
    temperature=0,
    base_url=f"http://{OLLAMA_IP}:{PORT}",
    timeout=300
)

@tool
def get_vulnerable_files_from_structure(file_struct_path: str, vulnerability: str) -> str:
    """
    Analyzes the repository structure file and returns a JSON list of file paths.
    """

    print(f"Tool1 :get_vulnerable_files_from_structure | vuln:{vulnerability} ")


    if not os.path.exists(file_struct_path):
        return f"Error: The structure file was not found at '{file_struct_path}'. Please check if the path is correct."

    try:
        with open(file_struct_path, "r", encoding="utf-8") as f:
            repo_structure_text = f.read()

        prompt_text = (
            f"You are a specialized Security Researcher.\n"
            f"Analyze the following repo structure for: '{vulnerability}'.\n\n"
            f"--- REPOSITORY STRUCTURE ---\n"
            f"{repo_structure_text}\n\n"
            f"TASK:\n"
            f"Understand the directory structure and the file names to understand the presence of {vulnerability}\n"
            f"Identify the Top 5 to 10 files most likely to contain the {vulnerability}.\n"
            f"Return ONLY a valid JSON list of strings. No explanations.\n"
            f"Example of output to be returned : [\"backend/app.py\", \"api/routes.ts\"]"
        )

        response = llm.invoke([HumanMessage(content=prompt_text)])
        content = response.content.strip()

        if "```" in content:
            content = re.sub(r'```json|```', '', content).strip()
        
        match = re.search(r'\[.*\]', content, re.DOTALL)
        if match:
            clean_json = match.group(0)
            json.loads(clean_json)
            

            print(f"Tool1 :get_vulnerable_files_from_structure | files:{clean_json} ")

            return clean_json
        else:
            return "Error: LLM failed to return a valid JSON list of files."

    except Exception as e:
        return f"Error identifying files: {str(e)}"


@tool
def analyze_code_for_vuln(file_path: str, vulnerability: str, full_repo_path: str) -> str:
    """
    Reads code from a file and performs static analysis for a specific vulnerability.
    """

    print(f"Tool2:analyze_code_for_vuln |filepath:{file_path} | vuln:{vulnerability} ")

    
    clean_file_path = file_path.lstrip('/')
    if clean_file_path.startswith(full_repo_path):
        full_path = clean_file_path
    else:
        full_path = os.path.join(full_repo_path, clean_file_path)
    
    try:
        if not os.path.exists(full_path):
            return f"### File: {file_path}\nError: File not found at {full_path}. Ensure the file_path is relative to the repository root."

        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
            
        if len(code) > 8000:
            code = code[:8000] + "\n...[TRUNCATED FILE CONTENT]"
            
        prompt = (
            f"You are senior Vulnerability Assessors. Analyze the following code for: {vulnerability}.\n"
            f"File: {file_path}\n\n"
            f"Source Code:\n{code}\n\n"
            f"Instructions:\n"
            f"1.Analysze the code deep for {vulnerability} and do not hallucinate.Do not return the things which are not present in code.\n"
            f"2. If VULNERABLE: Explain flaw, line numbers, and provide a secure fix.\n"
            
            f"3. Analysis should be clear and should contain code snippet of vulnerability only\n"
            f"4. If SAFE: state 'No issues found regarding {vulnerability}'.\n"
        )

        response = llm.invoke([HumanMessage(content=prompt)])


       # print(f"Tool2 :analyze_code_for_vuln | vuln:{vulnerability} | ANALYSIS:{response.content} ")


        return f"### File: {file_path}\n{response.content}\n"

    except Exception as e:
        return f"### File: {file_path}\nError analyzing file: {str(e)}\n"






# if __name__ == "__main__":
#     test_struct_file = "repo_structure.txt"

#     vuln_test = "Access Broken Control"
#     print(f"--- Testing for: {vuln_test} ---")
#     files = get_vulnerable_files_from_structure(test_struct_file, vuln_test)
    
#     print("\n[Found Candidate Files]")
#     for f in files:
#         print(f" - {f}")

