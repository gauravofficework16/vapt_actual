from langchain_core.messages import SystemMessage, HumanMessage
from utils.Agentschema import VAPTState
from utils.Tools import get_vulnerable_files_from_structure,analyze_code_for_vuln
from langchain_ollama import ChatOllama
import os

OLLAMA_IP = "172.17.63.4" 
PORT = "11434"
os.environ["OLLAMA_HOST"] = f"http://{OLLAMA_IP}:{PORT}"

model = ChatOllama(
    model="gpt-oss:20b", 
    temperature=0,
    base_url=f"http://{OLLAMA_IP}:{PORT}",
    timeout=300
).bind_tools([get_vulnerable_files_from_structure,analyze_code_for_vuln])

#1
def v1_bac(state: VAPTState):
    print("V1 start")

    file_struct_path = state["file_struct_path"]
    repo_path=state['repo_path']

    messages = state["v1_msgs"]
  
    vulnerability="Broken access control"
    
    system_prompt = f"""
    You are a Security Engineer best in analysing OWASP vulnerabilities. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}. Do not hallucinate with non existing 

    CRITICAL AREA OF FOCUS:
    1. Privilege & Role Logic (Vertical Escalation):
    - Identify sensitive endpoints (e.g., `/admin`, `deleteUser`, `updateConfig`).
    - Verify if these endpoints possess explicit Role Checks or Decorators (e.g., `@require_admin`, `[Authorize(Roles="Admin")]`, `middleware.ensureAdmin`).
    - Flag functions that rely solely on UI suppression (hiding buttons) without backend validation.
    
    2. Ownership Validation Logic (IDOR / Horizontal Escalation):
    - Locate controllers/functions that accept unique identifiers as input (e.g., `user_id`, `invoice_id`, `file_id` in URL/Body).
    - CRITICAL CHECK: Analyze the code flow to ensure there is a logic check comparing the resource's `owner_id` against the `current_user.id` or `session.id` before returning data.
    - Flag Direct Database Queries (e.g., `User.findById(req.params.id)`) that lack an accompanying ownership filter.

    3. Unprotected Routes & HTTP Verbs:
    - Review Router configurations for "Default Allow" patterns.
    - Check if sensitive verbs (POST, PUT, DELETE) are accessible without authentication middleware.
    - Identify "Shadow APIs" or internal routes exposed without any access control logic.

    4. Token & Session Handling Logic:
    - (Instead of "Replaying tokens"): Look for JWT verification logic. Does the code explicitly verify the `signature` and `algorithm`?
    - Check if the code allows the `none` algorithm in JWT decoding.
    - Verify if the "Logout" function actually invalidates the session/token on the server side (e.g., adding to a deny-list) or just deletes the cookie client-side.

    5. Configuration & Middleware:
    - Review CORS settings (e.g., in `settings.py`, `app.js`) for `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`.
    - Check for bypasses in middleware chains (e.g., regex exclusions for authentication that are too broad).

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool at start and only once to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    ### FINAL REPORT FORMAT:
    1. Name of vulnerability: {vulnerability}
    2. Vulnerability Score: [0-10]
    3. Severity: [Low | Medium | High | Critical]
    4. Detailed Technical Analysis:
    - File Name: [Path]
    - Technical Description: Explain how the authorization bypass occurs.
    - Vulnerable Code Snippet: Show the exact code missing the check.
    - Secure Fix: Provide a remediated version using proper RBAC/ABAC logic.
    
    """

    if not messages:
        print("at v1 1.1")
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Perform indepth ananlysis for {vulnerability}")]
    else:
        print("at v1 1.2")
        input_messages = [SystemMessage(content=system_prompt)] + messages

    print("at v1 MID INVOKE")
    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv1.md")

        with open(node_result, "w", encoding="utf-8") as f:
            print("at v1 writing..")
            f.write(response.content)

    # print(f"at v1 {response.content}")   
    print("at v1 end")

    return {"v1_msgs": [response], "sender": "v1_bac"}

#2
def v2_misconfig(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v2_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Security Misconfiguration"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Check Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, testing frameworks, or privileges).
    2. Check Insecure Error Handling (Information Leakage)
    3. Missing or Weak Security Headers, Absence of:Content-Security-Policy (CSP): Prevents XSS,Strict-Transport-Security (HSTS): Forces HTTPS,X-Content-Type-Options: nosniff: Prevents MIME-sniffing attacks,X-Frame-Options: Prevents Clickjacking.
    4.Check Hardcoded Secrets and Default Credentials
    5. Check Enabled Directory Browsing , Insecure Framework Defaults (Example: Django: DEBUG = True in settings.py.)
    6. Check Permissive Cloud Access : leaving storage (S3) or ports (SSH/22) open to the entire internet (0.0.0.0/0), allowing anyone to access your data or servers without a password.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed. 

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv2.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v2_msgs": [response], "sender": "v2_misconfig"}

#3
def v3_supply_chain(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v3_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Software Supply Chain Failures"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Check Use of Unmaintained Third Party Components and  Dependency on Vulnerable Third-Party Component.
    2. Reliance on Component That is Not Updateable
    3. Check  vulnerability of unsupported, or out of date web/application server, applications, APIs and all components, runtime environments, and libraries.
    4. Try to understand the library version from the use of it or check if it is present in requirements.txt file . as the outdated or unstable library version is vulnerable.


    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability .
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv3.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v3_msgs": [response], "sender": "v3_supply_chain"}

#4
def v4_crypto(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v4_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Cryptographic Failures"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Use of Broken or Deprecated Algorithms: Identifying the use of outdated or weak functions such as MD5, SHA1, DES, or RC4 within the source code.

    2. Hardcoded Cryptographic Keys: Detecting secrets, private keys, or default passwords that have been checked into source code repositories or defined as constants.

    3. Insecure Modes of Operation: Spotting the use of insecure block cipher modes, such as ECB (Electronic Codebook), instead of authenticated encryption modes.

    4. Predictable Random Number Generators: Identifying the use of non-cryptographic pseudo-random number generators (PRNGs) for security-sensitive tasks like generating tokens or IVs.

    5. Weak Password Hashing: Detecting the absence of salts or the use of fast, simple hash functions instead of strong, adaptive functions like Argon2, scrypt, or PBKDF2.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv4.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v4_msgs": [response], "sender": "v4_crypto"}

#5
def v5_injection(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v5_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Injection"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1.Use of String Concatenation in Database Queries: Identifying where user-supplied variables are added directly to query strings (SQL or NoSQL) instead of using safe, parameterized interfaces or prepared statements.

    2. Direct Execution of OS Commands: Spotting instances where raw user input from request parameters is passed directly into system-level functions like Runtime.getRuntime().exec() or other command-line interpreters.

    3. Unsafe ORM Parameterization: Detecting the use of unsanitized data within Object-Relational Mapping (ORM) search parameters, such as concatenating input into Hibernate Query Language (HQL) strings.

    4. Dynamic SQL in Stored Procedures: Identifying PL/SQL or T-SQL stored procedures that use functions like EXECUTE IMMEDIATE or exec() to run dynamic queries built from potentially hostile data.

    5. Lack of Context-Aware Escaping or Validation: Detecting data flows where "untrusted" input (from URLs, cookies, or JSON) is sent to an interpreter without passing through any visible validation, filtering, or escaping logic.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv5.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v5_msgs": [response], "sender": "v5_injection"}

#6
def v6_insecure_design(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v6_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Insecure Design"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Unprotected Storage of Credentials: Identifying logic that saves sensitive credentials or secrets to local storage, files, or databases without an appropriate protection or encryption layer.

    2. Unrestricted File Upload Controls: Spotting file upload functions that lack validation for dangerous file types (extensions) or fail to restrict permissions on where those files are stored and executed.

    3. Insecure Identity Recovery Flows: Detecting the implementation of "security questions and answers" for password recovery, which are considered a design flaw because the answers can be known by others.

    4. Lack of Business Logic Limits: Identifying sensitive transaction points (such as booking systems or checkout processes) that do not enforce limits on volume, quantity, or frequency, allowing for automated abuse.

    5. Trust Boundary Violations: Detecting code where untrusted user input is directly assigned to internal session variables or used to modify the application's state without a clear validation boundary.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv6.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v6_msgs": [response], "sender": "v6_insecure_design"}

#7
def v7_auth_fail(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v7_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Authentication Failures"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Use of Hard-coded Credentials: Identifying static, built-in passwords or administrative secrets defined as constants or checked directly into the source code or configuration files.

    2. Session ID Exposure in URLs: Detecting logic that appends session identifiers to URLs or stores them in hidden HTML form fields rather than using secure, server-side cookies.

    3. Improper Session Invalidation: Spotting logout functions or timeout handlers that fail to explicitly destroy the server-side session or correctly invalidate authentication tokens (like SSO tokens).

    4. Missing JWT Claim Validation: Identifying code that processes JSON Web Tokens (JWTs) without verifying critical claims such as the intended audience (aud), issuer (iss), or scope.

    5. Insecure Password Recovery Logic: Detecting the implementation of "knowledge-based answers" (security questions) for credential recovery, which are considered ineffective and easy to bypass.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv7.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v7_msgs": [response], "sender": "v7_auth_fail"}

#8
def v8_integrity_fail(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v8_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Software or Data Integrity Failures"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Insecure Deserialization of Untrusted Data: Identifying the use of native deserialization functions (such as Java's readObject) on data received from untrusted clients without prior integrity checks or digital signatures.

    2. Improper Modification of Object Attributes: Spotting logic that allows user-controlled input to dynamically determine or modify internal object attributes (also known as Mass Assignment), which can lead to unauthorized state changes.

    3. Inclusion of Functionality from Untrusted Sources: Detecting code that imports libraries, plugins, or scripts from unverified third-party domains or untrusted CDNs, effectively bridging a trust boundary.

    4. Missing Signature Verification in Update Logic: Identifying functions responsible for downloading software or firmware updates that fail to implement cryptographic signature checks to verify the artifact's integrity and source.

    5. Transfer of Unsigned Serialized State: Detecting instances where sensitive application or user state is serialized and passed to the client (e.g., in hidden fields or cookies) without being signed or encrypted to prevent tampering.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv8.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v8_msgs": [response], "sender": "v8_integrity_fail"}

#9
def v9_logging_fail(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v9_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Security Logging & Alerting Failures"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Insertion of Sensitive Data into Log Files: Identifying instances where variables containing personally identifiable information (PII), passwords, or other secrets are passed directly to logging functions.

    2. Log Injection via Improper Output Encoding: Detecting code where untrusted user input is written to log files without proper encoding, which could allow an attacker to forge log entries or attack monitoring systems (CWE-117).

    3. Inadequate Error Handling and Logging: Spotting empty "catch" blocks or exception handlers that fail to generate log messages, which prevents the system from being aware of or recording exceptional conditions.

    4. Inconsistent Security Event Logging: Identifying authentication or access control logic that logs successful actions but lacks corresponding log calls for failed attempts or validation errors.

    5. Missing Audit Trails for High-Value Transactions: Detecting critical business logic or state-changing functions (such as financial transfers or record deletions) that do not trigger a logging event to create a required audit trail.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv9.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v9_msgs": [response], "sender": "v9_logging_fail"}

#10
def v10_expt_mishandle(state: VAPTState):
    file_struct_path = state["file_struct_path"]
    messages = state.get("v10_msgs", [])
    repo_path=state['repo_path']

    vulnerability="Mishandling of Exceptional Conditions"
    
    system_prompt = f"""
    You are a Security Engineer. Your goal is to find the target files for {vulnerability} and analyze them with tool. And create a report of the vulnerability analysis specific for {vulnerability}.

    CRITICAL AREA OF FOCUS:
    1. Generation of Error Messages Containing Sensitive Information: Identifying instances where the code catches an exception and returns the full stack trace, database error details, or internal system state directly to the user.

    2. Failing Open in Security Logic: Detecting catch blocks or error-handling branches that default to a permissive state (e.g., setting isAuthenticated = true) or allow a process to continue even when a security check fails.

    3. Improper Resource Cleanup (Resource Exhaustion): Spotting scenarios where resources like file handles, database connections, or memory are allocated but not explicitly released or closed within an error-handling block.

    4. Lack of Transaction Rollback: Identifying multi-step business logic (such as financial transfers) that fails to "fail closed" by rolling back partially completed steps when an error occurs in the middle of the process.

    5. NULL Pointer Dereferences: Detecting code that attempts to use an object or variable without first checking if it is null, particularly in pathways where a previous function may have failed and returned a null value.

    PLAN OF ACTION:
    1. Use 'get_vulnerable_files_from_structure' tool to filter the directory structure {file_struct_path} and retrieve a list of files relevant to {vulnerability}.
    2. Extract the list of filenames returned by the tool.
    3. Pass these specific filenames into the 'analyze_code_for_vuln' tool one by one to retrieve their code content {repo_path}.
    4. Analyze the code  content from {repo_path} returned for each file, checking specifically for the patterns defined in the CRITICAL AREA OF FOCUS.
    5. Each file should be analyzed by 'analyze_code_for_vuln' for {vulnerability} only at once. And every file should be analyzed.

    REPORT FORMAT TO RETURN:
    1. Name of vulnerability:{vulnerability} and score of {vulnerability} out of 10 with severity: [Low | Medium | High | Critical].
    2. File name and the clear and technical description with the code snippet of vulnerability if needed.
    
    """

    if not messages:
        input_messages = [SystemMessage(content=system_prompt), HumanMessage(content=f"Analyze {vulnerability}.")]
    else:
        input_messages = [SystemMessage(content=system_prompt)] + messages

    response = model.invoke(input_messages)

    if not response.tool_calls and len(messages) > 0:
        folder_name = "Node_results"
        os.makedirs(folder_name, exist_ok=True)
        node_result = os.path.join(folder_name, "rv10.md")

        with open(node_result, "w", encoding="utf-8") as f:
            f.write(response.content)

    return {"v10_msgs": [response], "sender": "v10_expt_mishandle"}
