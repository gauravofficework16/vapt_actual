"""
"""OWASP Top 10 2021 (Official) vulnerability categories and analysis prompts.
Aligned with https://owasp.org/Top10/
Centralized configuration for consistent analysis across all nodes.
"""

OWASP_CATEGORIES = [
    {
        "id": "v1",
        "name": "Broken Access Control",
        "owasp_id": "A01:2021",
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
        "name": "Cryptographic Failures",
        "owasp_id": "A02:2021",
        "key": "v2_crypto",
        "output_file": "rv2.md",
        "focus_areas": [
            "Use of Broken or Deprecated Algorithms (MD5, SHA1, DES, RC4)",
            "Hardcoded Cryptographic Keys and Secrets",
            "Insecure Modes of Operation (ECB mode)",
            "Predictable Random Number Generators for Security",
            "Weak Password Hashing (missing salt, fast hashes)",
            "Transmitting sensitive data in clear text"
        ],
        "analysis_instructions": """
1. Identify use of outdated or weak cryptographic functions (MD5, SHA1, DES, RC4).
2. Detect hardcoded secrets, private keys, or passwords in source code.
3. Spot use of insecure block cipher modes like ECB (Electronic Codebook).
4. Identify use of non-cryptographic PRNGs for security-sensitive operations.
5. Detect weak password hashing (no salt, fast functions instead of Argon2/bcrypt/PBKDF2).
6. Check for sensitive data transmitted or stored without encryption.
"""
    },
    {
        "id": "v3",
        "name": "Injection",
        "owasp_id": "A03:2021",
        "key": "v3_injection",
        "output_file": "rv3.md",
        "focus_areas": [
            "SQL Injection via String Concatenation",
            "Direct Execution of OS Commands with User Input",
            "Unsafe ORM Parameterization",
            "Dynamic SQL in Stored Procedures",
            "NoSQL Injection",
            "Lack of Context-Aware Input Validation and Escaping"
        ],
        "analysis_instructions": """
1. Identify where user-supplied variables are concatenated directly into SQL/NoSQL queries.
2. Spot instances where raw user input is passed to system commands (exec, shell, eval).
3. Detect use of unsanitized data within ORM search parameters or HQL/JPQL.
4. Identify stored procedures using dynamic SQL built from untrusted input.
5. Check for NoSQL injection vulnerabilities in MongoDB, Cassandra queries.
6. Detect data flows where untrusted input reaches interpreters without validation/escaping.
"""
    },
    {
        "id": "v4",
        "name": "Insecure Design",
        "owasp_id": "A04:2021",
        "key": "v4_insecure_design",
        "output_file": "rv4.md",
        "focus_areas": [
            "Missing Security Controls in Design",
            "Unprotected Storage of Credentials",
            "Unrestricted File Upload Logic",
            "Insecure Password Recovery Flows (security questions)",
            "Lack of Business Logic Rate Limiting",
            "Trust Boundary Violations"
        ],
        "analysis_instructions": """
1. Identify missing threat modeling and secure design patterns.
2. Spot logic that saves credentials without appropriate encryption/protection.
3. Detect file upload functions lacking validation for dangerous extensions/content.
4. Identify use of security questions for password recovery (insecure by design).
5. Check for missing rate limits on sensitive operations (bookings, payments, APIs).
6. Detect where untrusted input directly modifies internal application state.
"""
    },
    {
        "id": "v5",
        "name": "Security Misconfiguration",
        "owasp_id": "A05:2021",
        "key": "v5_misconfig",
        "output_file": "rv5.md",
        "focus_areas": [
            "Unnecessary features enabled (debug, ports, services)",
            "Insecure Default Configurations",
            "Missing or Weak Security Headers",
            "Hardcoded Default Credentials",
            "Verbose Error Messages (stack traces, DB errors)",
            "Permissive Cloud/Storage Access (S3, ports)",
            "Outdated or unpatched software"
        ],
        "analysis_instructions": """
1. Check for unnecessary features enabled (DEBUG=True, test endpoints, directory listing).
2. Verify insecure default configurations in frameworks (Django, Spring, Express).
3. Check for missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
4. Detect hardcoded default credentials in configuration files.
5. Identify verbose error messages exposing stack traces or database structure.
6. Check for permissive cloud access controls (public S3 buckets, 0.0.0.0/0 rules).
7. Flag outdated framework/library versions with known vulnerabilities.
"""
    },
    {
        "id": "v6",
        "name": "Vulnerable and Outdated Components",
        "owasp_id": "A06:2021",
        "key": "v6_components",
        "output_file": "rv6.md",
        "focus_areas": [
            "Use of Unmaintained or Deprecated Libraries",
            "Dependencies with Known CVEs",
            "Outdated Framework Versions",
            "Unsupported Runtime Environments",
            "Missing Security Patches",
            "Lack of Dependency Scanning"
        ],
        "analysis_instructions": """
1. Identify unmaintained third-party components and libraries.
2. Check dependencies against vulnerability databases (CVE, NVD, npm audit, safety).
3. Detect outdated framework versions (Spring, Django, React, etc.).
4. Check for unsupported runtime environments (EOL Node.js, Python, Java versions).
5. Review requirements.txt, package.json, pom.xml for version pinning and known vulns.
6. Verify presence of dependency scanning in CI/CD pipeline.
"""
    },
    {
        "id": "v7",
        "name": "Identification and Authentication Failures",
        "owasp_id": "A07:2021",
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
        "name": "Software and Data Integrity Failures",
        "owasp_id": "A08:2021",
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
        "name": "Security Logging and Monitoring Failures",
        "owasp_id": "A09:2021",
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
        "owasp_id": "A10:2021",
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
