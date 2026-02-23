"""
OWASP Top 10:2025 (Official) vulnerability categories and analysis prompts.
Aligned with https://owasp.org/Top10/2025/
Centralized configuration for consistent analysis across all nodes.
"""

OWASP_CATEGORIES = [
    {
        "id": "v1",
        "name": "Broken Access Control",
        "owasp_id": "A01:2025",
        "key": "v1_bac",
        "output_file": "rv1.md",
        "focus_areas": [
            "Missing Authorization Checks on Endpoints",
            "IDOR - Insecure Direct Object References",
            "Privilege Escalation (Vertical/Horizontal)",
            "CORS Misconfiguration",
            "JWT/Token Bypass Vulnerabilities"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: route definitions, controllers, API endpoints, middleware, authentication decorators
- File patterns: **/routes/**.*, **/controllers/**.*, **/api/**.*, **/middleware/auth*.*, **/decorators/auth*.*
- Focus on files with HTTP verbs (GET, POST, PUT, DELETE) or authentication logic

ANALYSIS CHECKLIST:
1. Find all endpoint definitions (routes, controllers, API handlers)
2. Check if each endpoint has explicit authorization/role checks BEFORE executing logic
3. Look for functions accepting user IDs/object IDs - verify ownership validation exists
4. Check if database queries filter by current user ID (e.g., WHERE user_id = current_user.id)
5. Identify admin/privileged routes - ensure they have role-based guards
6. Review CORS configuration for overly permissive origins
7. Check JWT validation - ensure 'none' algorithm is rejected

EVIDENCE REQUIRED:
- Show the EXACT vulnerable function/route with line numbers
- Explain WHY it's vulnerable (missing check, no ownership filter, etc.)
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Broken Access Control issues detected."
"""
    },
    {
        "id": "v2",
        "name": "Security Misconfiguration",
        "owasp_id": "A02:2025",
        "key": "v2_misconfig",
        "output_file": "rv2.md",
        "focus_areas": [
            "Debug Mode Enabled in Production",
            "Default Credentials and Secrets",
            "Missing Security Headers",
            "Unnecessary Features Enabled",
            "Verbose Error Messages",
            "Insecure Default Settings"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: config files, settings, environment files, middleware, server configs
- File patterns: **/*config*.*, **/settings*.*, **/.env*.*, **/middleware/**.*, **/server.*, **/*nginx*.*, **/*apache*.*
- Focus on application configuration and initialization files

ANALYSIS CHECKLIST:
1. Check for DEBUG=True, debug_mode=True, or development mode enabled
2. Search for hardcoded default passwords (admin/admin, root/root, etc.)
3. Look for security header middleware (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
4. Identify exposed test/debug endpoints or admin panels without auth
5. Check error handlers - do they expose stack traces or internal paths?
6. Review CORS settings for wildcard (*) origins
7. Identify unnecessary services exposed (directory listing, metrics without auth)

EVIDENCE REQUIRED:
- Show the EXACT configuration setting with file path and line number
- Explain the security risk of the misconfiguration
- Provide the ACTUAL vulnerable configuration from the file

IF NO VULNERABILITIES FOUND: State "No Security Misconfiguration issues detected."
"""
    },
    {
        "id": "v3",
        "name": "Software Supply Chain Failures",
        "owasp_id": "A03:2025",
        "key": "v3_supply_chain",
        "output_file": "rv3.md",
        "focus_areas": [
            "Vulnerable Dependencies with Known CVEs",
            "Unmaintained or Deprecated Libraries",
            "Missing Integrity Checks for Dependencies",
            "Insecure Package Sources",
            "Lack of SBOM and Dependency Scanning"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: dependency manifests, lock files, build configurations
- File patterns: **/requirements.txt, **/package.json, **/package-lock.json, **/pom.xml, **/build.gradle, **/Gemfile, **/go.mod, **/composer.json
- Focus on dependency declaration and build files

ANALYSIS CHECKLIST:
1. Identify all dependency files (requirements.txt, package.json, etc.)
2. Look for unpinned versions (using >=, ^, ~, or * wildcards)
3. Check for outdated packages (compare versions with known vulnerabilities)
4. Verify if lockfiles exist (package-lock.json, poetry.lock, Gemfile.lock)
5. Look for dependencies pulled from insecure sources (http://, untrusted registries)
6. Check for post-install scripts that could execute malicious code
7. Identify unmaintained packages (last updated >3 years ago)

EVIDENCE REQUIRED:
- Show the EXACT dependency declaration with file path
- List specific CVE numbers if known vulnerable versions are used
- Provide the ACTUAL dependency versions from the file

IF NO VULNERABILITIES FOUND: State "No Software Supply Chain issues detected."
"""
    },
    {
        "id": "v4",
        "name": "Cryptographic Failures",
        "owasp_id": "A04:2025",
        "key": "v4_crypto",
        "output_file": "rv4.md",
        "focus_areas": [
            "Weak Cryptographic Algorithms (MD5, SHA1, DES, RC4)",
            "Hardcoded Encryption Keys and Secrets",
            "Insecure Random Number Generation",
            "Weak Password Hashing",
            "Sensitive Data Transmitted in Clear Text"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: crypto utilities, password handlers, authentication modules, encryption functions
- File patterns: **/crypto*.*, **/encrypt*.*, **/hash*.*, **/auth*.*, **/security*.*, **/password*.*
- Focus on files with cryptographic operations or secret handling

ANALYSIS CHECKLIST:
1. Search for weak algorithms: md5(), sha1(), des, rc4, ECB mode
2. Look for hardcoded keys/secrets in source code (check strings, constants)
3. Identify usage of random() or Math.random() for security purposes (use crypto-secure RNG)
4. Check password hashing - must use bcrypt, argon2, or PBKDF2 (NOT md5/sha1)
5. Verify passwords are salted and use appropriate work factors
6. Check for sensitive data (passwords, tokens, PII) transmitted over HTTP (not HTTPS)
7. Identify plain text storage of secrets in files or databases

EVIDENCE REQUIRED:
- Show the EXACT line of code using weak crypto with file path
- Identify the specific algorithm or function that's insecure
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Cryptographic Failure issues detected."
"""
    },
    {
        "id": "v5",
        "name": "Injection",
        "owasp_id": "A05:2025",
        "key": "v5_injection",
        "output_file": "rv5.md",
        "focus_areas": [
            "SQL Injection via String Concatenation",
            "Command Injection (OS Command Execution)",
            "NoSQL Injection",
            "LDAP Injection",
            "XML/XPath Injection",
            "Template Injection"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: database queries, command execution, ORM usage, template rendering
- File patterns: **/models/**.*, **/database/**.*, **/queries/**.*, **/repositories/**.*, **/dao/**.*, **/services/**.*
- Focus on files that interact with databases, execute commands, or render templates

ANALYSIS CHECKLIST:
1. Find SQL queries built with string concatenation or f-strings/template strings with user input
2. Look for command execution functions (exec, eval, system, shell_exec, subprocess) with user input
3. Check ORM usage - find raw queries or unsafe filters with untrusted data
4. Identify NoSQL queries using $where or JavaScript injection points
5. Look for XML parsers processing untrusted input without validation
6. Check template engines for Server-Side Template Injection (SSTI)
7. Verify all user inputs are parameterized/escaped before reaching interpreters

EVIDENCE REQUIRED:
- Show the EXACT vulnerable query/command with file path and line number
- Trace how user input flows into the vulnerable code
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Injection issues detected."
"""
    },
    {
        "id": "v6",
        "name": "Insecure Design",
        "owasp_id": "A06:2025",
        "key": "v6_insecure_design",
        "output_file": "rv6.md",
        "focus_areas": [
            "Missing Rate Limiting on Critical Operations",
            "Insecure Password Recovery Mechanisms",
            "Unrestricted File Upload",
            "Business Logic Bypass",
            "Missing Security Controls by Design"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: authentication logic, payment handlers, file uploads, rate limiting, business workflows
- File patterns: **/auth/**.*, **/upload/**.*, **/payment/**.*, **/checkout/**.*, **/booking/**.*, **/transaction/**.*
- Focus on critical business logic and state-changing operations

ANALYSIS CHECKLIST:
1. Check authentication endpoints (login, register, reset) for rate limiting
2. Review password recovery - does it use security questions or predictable tokens?
3. Find file upload handlers - check for extension validation, size limits, content-type verification
4. Identify payment/booking flows - can users manipulate price, quantity, or status?
5. Look for business logic that trusts client-side validation only
6. Check for missing multi-step verification on critical actions (delete account, transfer funds)
7. Verify session management - are concurrent sessions handled securely?

EVIDENCE REQUIRED:
- Show the EXACT function with insecure design and file path
- Explain the design flaw and potential attack scenario
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Insecure Design issues detected."
"""
    },
    {
        "id": "v7",
        "name": "Authentication Failures",
        "owasp_id": "A07:2025",
        "key": "v7_auth_fail",
        "output_file": "rv7.md",
        "focus_areas": [
            "Hardcoded Credentials",
            "Weak Session Management",
            "Missing Multi-Factor Authentication",
            "Credential Stuffing Vulnerabilities",
            "Insecure Session Fixation"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: authentication modules, session handlers, login logic, credential storage
- File patterns: **/auth/**.*, **/login*.*, **/session*.*, **/credentials*.*, **/tokens/**.*
- Focus on authentication and session management code

ANALYSIS CHECKLIST:
1. Search for hardcoded passwords, API keys, or tokens in source code
2. Check session ID generation - is it cryptographically random?
3. Verify session IDs are NOT exposed in URLs or GET parameters
4. Check logout functionality - does it invalidate session server-side?
5. Look for session fixation - is session ID regenerated after login?
6. Verify JWT implementation - check signature validation and claim verification
7. Check for brute-force protection (account lockout, CAPTCHA, rate limiting)

EVIDENCE REQUIRED:
- Show the EXACT vulnerable authentication code with file path
- Identify the specific authentication flaw
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Authentication Failure issues detected."
"""
    },
    {
        "id": "v8",
        "name": "Software or Data Integrity Failures",
        "owasp_id": "A08:2025",
        "key": "v8_integrity_fail",
        "output_file": "rv8.md",
        "focus_areas": [
            "Insecure Deserialization",
            "Missing Code Signing",
            "Insecure CI/CD Pipelines",
            "Auto-Update Without Verification",
            "Mass Assignment Vulnerabilities"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: deserialization, update mechanisms, CI/CD configs, object binding
- File patterns: **/serialization/**.*, **/update*.*, **/.github/workflows/**.*, **/Jenkinsfile, **/models/**.*, **/dto/**.*
- Focus on data deserialization and update mechanisms

ANALYSIS CHECKLIST:
1. Find deserialization of untrusted data (pickle, JSON.parse, unserialize, ObjectInputStream)
2. Check for auto-update mechanisms - verify signature/checksum validation
3. Review CI/CD configs for secrets in plain text or insecure permissions
4. Look for mass assignment - can users set arbitrary object properties?
5. Check for CDN/library imports - are they using SRI (Subresource Integrity)?
6. Verify critical operations use HMAC or digital signatures
7. Identify code that trusts serialized objects without validation

EVIDENCE REQUIRED:
- Show the EXACT deserialization/integrity code with file path
- Explain the integrity failure risk
- Provide the ACTUAL vulnerable code snippet from the file

IF NO VULNERABILITIES FOUND: State "No Software/Data Integrity issues detected."
"""
    },
    {
        "id": "v9",
        "name": "Security Logging and Alerting Failures",
        "owasp_id": "A09:2025",
        "key": "v9_logging_fail",
        "output_file": "rv9.md",
        "focus_areas": [
            "Missing Security Event Logging",
            "Sensitive Data in Logs",
            "Log Injection Vulnerabilities",
            "Insufficient Monitoring",
            "No Alerting on Security Events"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: logging configuration, error handlers, authentication flows, audit trails
- File patterns: **/logging*.*, **/logger*.*, **/audit*.*, **/monitoring*.*, **/error*.*, **/exceptions/**.*
- Focus on logging and monitoring implementations

ANALYSIS CHECKLIST:
1. Check authentication functions - are login failures logged?
2. Verify authorization failures are logged with user context
3. Look for sensitive data in log statements (passwords, tokens, PII, credit cards)
4. Check for log injection - is user input sanitized before logging?
5. Verify critical operations (password change, data deletion) are logged
6. Check exception handlers - are security-relevant exceptions logged?
7. Look for centralized logging (syslog, SIEM) vs local-only logs

EVIDENCE REQUIRED:
- Show the EXACT logging gap or sensitive data leak with file path
- Identify what security event is missing from logs
- Provide the ACTUAL vulnerable logging code from the file

IF NO VULNERABILITIES FOUND: State "No Security Logging/Alerting issues detected."
"""
    },
    {
        "id": "v10",
        "name": "Mishandling of Exceptional Conditions",
        "owasp_id": "A10:2025",
        "key": "v10_exception_mishandle",
        "output_file": "rv10.md",
        "focus_areas": [
            "Empty Catch Blocks",
            "Generic Exception Handling",
            "Information Disclosure in Error Messages",
            "Missing Input Validation Error Handling",
            "Improper Resource Cleanup on Errors"
        ],
        "analysis_instructions": """
CRITICAL: Only report vulnerabilities that exist in the ACTUAL CODE. Do NOT hallucinate.

FILE SELECTION CRITERIA:
- Look for: exception handlers, error handling, try-catch blocks, error middleware
- File patterns: **/error*.*, **/exception*.*, **/handlers/**.*, **/middleware/error*.*
- Focus on error handling and exception management code

ANALYSIS CHECKLIST:
1. Find empty catch/except blocks that silently swallow errors
2. Look for generic exception catches (catch Exception, except:) that hide specific errors
3. Check error responses - do they expose stack traces, file paths, or DB details to users?
4. Verify all external inputs have proper error handling (invalid input, missing fields)
5. Check resource cleanup (file handles, DB connections, sockets) in finally blocks
6. Look for NULL pointer dereferences without null checks
7. Verify critical operations have appropriate fallback/recovery logic

EVIDENCE REQUIRED:
- Show the EXACT error handling code with file path and line number
- Explain how the mishandling creates a security risk
- Provide the ACTUAL vulnerable error handling code from the file

IF NO VULNERABILITIES FOUND: State "No Exception Mishandling issues detected."
"""
    }
]


def get_category_config(node_id: str) -> dict:
    """Retrieve OWASP category configuration by node ID."""
    for cat in OWASP_CATEGORIES:
        if cat["id"] == node_id:
            return cat
    raise ValueError(f"Unknown OWASP category ID: {node_id}")


def get_all_node_keys() -> list[str]:
    """Return list of all node keys for graph routing."""
    return [cat["key"] for cat in OWASP_CATEGORIES]
