"""
OWASP Top 10 (2025-aligned) vulnerability categories and analysis prompts.
Centralized configuration for consistent analysis across all nodes.
"""

OWASP_CATEGORIES = [
    {
        "id": "v1",
        "name": "Broken Access Control",
        "key": "v1_bac",
        "output_file": "rv1.md",
        "focus_areas": [
            "Privilege & Role Logic (Vertical Escalation)",
            "Ownership Validation Logic (IDOR / Horizontal Escalation)",
            "Unprotected Routes & HTTP Verbs",
            "Token & Session Handling Logic",
            "Configuration & Middleware (CORS, authentication bypass)"
        ],
        "analysis_instructions": """
1. Identify sensitive endpoints (e.g., `/admin`, `deleteUser`, `updateConfig`).
2. Verify if these endpoints possess explicit Role Checks or Decorators.
3. Flag functions that rely solely on UI suppression without backend validation.
4. Locate controllers/functions that accept unique identifiers as input.
5. CRITICAL CHECK: Analyze the code flow to ensure ownership filter logic exists.
6. Flag Direct Database Queries that lack an accompanying ownership filter.
7. Review Router configurations for "Default Allow" patterns.
8. Check if sensitive verbs (POST, PUT, DELETE) are accessible without authentication middleware.
9. Look for JWT verification logic and check if the code allows the `none` algorithm.
10. Verify if "Logout" function actually invalidates the session/token server-side.
"""
    },
    {
        "id": "v2",
        "name": "Security Misconfiguration",
        "key": "v2_misconfig",
        "output_file": "rv2.md",
        "focus_areas": [
            "Unnecessary features enabled (ports, services, accounts, testing frameworks)",
            "Insecure Error Handling (Information Leakage)",
            "Missing or Weak Security Headers",
            "Hardcoded Secrets and Default Credentials",
            "Enabled Directory Browsing",
            "Insecure Framework Defaults (e.g., DEBUG mode)",
            "Permissive Cloud Access (open S3, SSH ports)"
        ],
        "analysis_instructions": """
1. Check for unnecessary features enabled or installed.
2. Check Insecure Error Handling that leaks internal information.
3. Verify presence of security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options.
4. Check for Hardcoded Secrets and Default Credentials in code or config files.
5. Check if Directory Browsing is enabled.
6. Check Insecure Framework Defaults (e.g., Django DEBUG = True).
7. Check Permissive Cloud Access configurations (S3 buckets, SSH ports open to 0.0.0.0/0).
"""
    },
    {
        "id": "v3",
        "name": "Software Supply Chain Failures",
        "key": "v3_supply_chain",
        "output_file": "rv3.md",
        "focus_areas": [
            "Use of Unmaintained Third Party Components",
            "Dependency on Vulnerable Third-Party Component",
            "Reliance on Component That is Not Updateable",
            "Unsupported or outdated components (web server, runtime, libraries)",
            "Outdated or unstable library versions"
        ],
        "analysis_instructions": """
1. Check Use of Unmaintained Third Party Components and Dependency on Vulnerable Components.
2. Identify Reliance on Components That are Not Updateable.
3. Check vulnerability of unsupported, or out of date web/application server, APIs, runtime environments.
4. Try to understand library versions from usage or requirements.txt/package.json files.
5. Flag outdated or unstable library versions.
"""
    },
    {
        "id": "v4",
        "name": "Cryptographic Failures",
        "key": "v4_crypto",
        "output_file": "rv4.md",
        "focus_areas": [
            "Use of Broken or Deprecated Algorithms (MD5, SHA1, DES, RC4)",
            "Hardcoded Cryptographic Keys",
            "Insecure Modes of Operation (ECB mode)",
            "Predictable Random Number Generators",
            "Weak Password Hashing"
        ],
        "analysis_instructions": """
1. Identify use of outdated or weak functions such as MD5, SHA1, DES, or RC4.
2. Detect secrets, private keys, or default passwords hardcoded in source code.
3. Spot use of insecure block cipher modes, such as ECB (Electronic Codebook).
4. Identify use of non-cryptographic PRNGs for security-sensitive tasks.
5. Detect absence of salts or use of fast hash functions instead of Argon2, scrypt, or PBKDF2.
"""
    },
    {
        "id": "v5",
        "name": "Injection",
        "key": "v5_injection",
        "output_file": "rv5.md",
        "focus_areas": [
            "Use of String Concatenation in Database Queries",
            "Direct Execution of OS Commands",
            "Unsafe ORM Parameterization",
            "Dynamic SQL in Stored Procedures",
            "Lack of Context-Aware Escaping or Validation"
        ],
        "analysis_instructions": """
1. Identify where user-supplied variables are added directly to query strings (SQL or NoSQL).
2. Spot instances where raw user input is passed directly into system-level functions.
3. Detect use of unsanitized data within ORM search parameters.
4. Identify stored procedures that use dynamic queries built from potentially hostile data.
5. Detect data flows where "untrusted" input is sent to an interpreter without validation or escaping.
"""
    },
    {
        "id": "v6",
        "name": "Insecure Design",
        "key": "v6_insecure_design",
        "output_file": "rv6.md",
        "focus_areas": [
            "Unprotected Storage of Credentials",
            "Unrestricted File Upload Controls",
            "Insecure Identity Recovery Flows",
            "Lack of Business Logic Limits",
            "Trust Boundary Violations"
        ],
        "analysis_instructions": """
1. Identify logic that saves sensitive credentials without appropriate protection.
2. Spot file upload functions that lack validation for dangerous file types.
3. Detect implementation of "security questions and answers" for password recovery.
4. Identify sensitive transaction points that do not enforce limits on volume or frequency.
5. Detect code where untrusted user input is directly assigned to internal session variables.
"""
    },
    {
        "id": "v7",
        "name": "Authentication Failures",
        "key": "v7_auth_fail",
        "output_file": "rv7.md",
        "focus_areas": [
            "Use of Hard-coded Credentials",
            "Session ID Exposure in URLs",
            "Improper Session Invalidation",
            "Missing JWT Claim Validation",
            "Insecure Password Recovery Logic"
        ],
        "analysis_instructions": """
1. Identify static, built-in passwords or administrative secrets defined as constants.
2. Detect logic that appends session identifiers to URLs or stores them in hidden form fields.
3. Spot logout functions that fail to explicitly destroy the server-side session.
4. Identify code that processes JWTs without verifying critical claims (aud, iss, scope).
5. Detect implementation of "knowledge-based answers" for credential recovery.
"""
    },
    {
        "id": "v8",
        "name": "Software or Data Integrity Failures",
        "key": "v8_integrity_fail",
        "output_file": "rv8.md",
        "focus_areas": [
            "Insecure Deserialization of Untrusted Data",
            "Improper Modification of Object Attributes (Mass Assignment)",
            "Inclusion of Functionality from Untrusted Sources",
            "Missing Signature Verification in Update Logic",
            "Transfer of Unsigned Serialized State"
        ],
        "analysis_instructions": """
1. Identify use of native deserialization functions on data from untrusted clients.
2. Spot logic that allows user-controlled input to dynamically determine object attributes.
3. Detect code that imports libraries from unverified third-party domains or untrusted CDNs.
4. Identify functions responsible for downloading updates that fail to implement signature checks.
5. Detect instances where sensitive state is serialized and passed to the client without signing.
"""
    },
    {
        "id": "v9",
        "name": "Security Logging & Alerting Failures",
        "key": "v9_logging_fail",
        "output_file": "rv9.md",
        "focus_areas": [
            "Insertion of Sensitive Data into Log Files",
            "Log Injection via Improper Output Encoding",
            "Inadequate Error Handling and Logging",
            "Inconsistent Security Event Logging",
            "Missing Audit Trails for High-Value Transactions"
        ],
        "analysis_instructions": """
1. Identify instances where PII, passwords, or secrets are passed to logging functions.
2. Detect code where untrusted user input is written to log files without proper encoding.
3. Spot empty "catch" blocks or exception handlers that fail to generate log messages.
4. Identify authentication logic that logs successful actions but lacks logs for failed attempts.
5. Detect critical business logic that does not trigger a logging event.
"""
    },
    {
        "id": "v10",
        "name": "Server-Side Request Forgery (SSRF)",
        "key": "v10_ssrf",
        "output_file": "rv10.md",
        "focus_areas": [
            "Unvalidated URL inputs used in HTTP requests",
            "Missing allowlist/denylist for internal resources",
            "Inadequate URL parsing and sanitization",
            "Exposure of internal services via user-controlled URLs",
            "Lack of network segmentation enforcement"
        ],
        "analysis_instructions": """
1. Identify instances where user-supplied URLs are used directly in HTTP client requests.
2. Detect missing validation or allowlist checks for target domains/IPs.
3. Spot inadequate URL parsing that allows bypass of security controls.
4. Identify code that could be exploited to access internal services (localhost, 169.254.x.x).
5. Check for proper network segmentation and firewall rule enforcement.
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
