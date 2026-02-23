**Insecure Design Vulnerability Report**  
*Scope: All files identified by `get_vulnerable_files_from_structure` for the “Insecure Design” category.*

| # | File | Key Insecure Design Flaw(s) | Severity | Code Snippet | Suggested Fix |
|---|------|-----------------------------|----------|--------------|---------------|
| 1 | `server/config/settings.py` | Hard‑coded secrets, DEBUG=True, ALLOWED_HOSTS='*', open CORS, missing click‑jacking middleware, hard‑coded email & DB creds, superuser DB access | **Critical** | ```python<br>SECRET_KEY = 'django-insecure-solaruat-dev-key-change-in-prod'<br>DEBUG = True<br>ALLOWED_HOSTS = ['*']<br>CORS_ALLOW_ALL_ORIGINS = True<br>EMAIL_HOST_USER = "bpm@solargroup.com"<br>DATABASES['default']['USER'] = 'postgres'``` | Move all secrets to environment variables or a secrets manager; set `DEBUG=False`; whitelist hosts; restrict CORS; enable click‑jacking middleware; use a dedicated DB user. |
| 2 | `server/reset_pass.py` | Hard‑coded universal password, printed to console, no auth, no audit | **High** | ```python<br>NEW_PASSWORD = "Password@1122334455"<br>print(f"🔐 Updating passwords for {count} employees to: {NEW_PASSWORD}")``` | Generate a random password per user, send via secure channel, log admin action, restrict script execution. |
| 3 | `server/wipe_db.py` | Unprotected destructive operation, no confirmation, runs in any environment | **Critical** | ```python<br>cursor.execute("DROP SCHEMA public CASCADE;")``` | Require explicit confirmation, restrict to non‑prod env, log operation, add permission checks. |
| 4 | `server/seed.py` | Hard‑coded default password for all users | **High** | ```python<br>default_password = "Password123!"<br>user.set_password(default_password)``` | Use env var or random password per user, enforce password change on first login. |
| 5 | `server/tracker/views.py` | Weak OTP generation, plaintext OTP storage, no expiration, no rate‑limit, no RBAC, email leakage | **Critical** | ```python<br>otp = str(random.randint(100000, 999999))<br>employee.otp_code = otp``` | Use `secrets`, hash OTP, enforce expiration, clear after use, add rate‑limit, enforce `IsAuthenticated`, hide email. |
| 6 | `server/tracker/serializers.py` | Optional password on create, client can set `password_hash`, no uniqueness enforcement | **High** | ```python<br>password = serializers.CharField(write_only=True, required=False)``` | Make password required, remove `password_hash` from API, enforce unique email. |
| 7 | `client/components/AdminPanel.tsx` | No RBAC, plain‑text password sent, no CSRF token, email shown | **High** | ```tsx<br>button onClick={...} // Register Identity<br>await api.createEmployee(formData)``` | Wrap panel in admin guard, send plain password over HTTPS, add CSRF token, remove email from response. |
| 8 | `client/components/LoginScreen.tsx` | User enumeration via error messages, email leakage, no input validation, no rate‑limit | **High** | ```tsx<br>setError(err.message || 'Login failed.');<br>setUserEmail(response.email);``` | Return generic errors, hide email, validate inputs, throttle attempts. |
| 9 | `client/services/api.ts` | HTTP transport, hard‑coded internal URL, no auth headers, `any` types, exposes internal URLs, raw error details, no CSRF, plain password sent, no secure token storage | **Critical** | ```ts<br>const SERVER_URL = 'http://siil-gw-drt-vm/uat-solar';<br>const res = await fetch(`${API_BASE}/employees/login/`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(credentials)});``` | Switch to HTTPS, use env vars, add JWT auth header, replace `any` with typed interfaces, sanitize URLs, generic error messages, CSRF token, secure token storage. |
|10 | `client/services/geminiService.ts` | No issues found | **Low** | – | – |

---

### Overall Insecure Design Score

| Metric | Value |
|--------|-------|
| Total files with issues | 9 |
| Highest severity | **Critical** |
| Average severity | **High** |
| **Overall score** | **7.8 / 10** (High risk) |

> **Interpretation:** The repository contains multiple critical insecure design flaws that expose sensitive data, allow privilege escalation, and enable brute‑force or enumeration attacks. Immediate remediation is required.

---

### Action Plan

1. **Secrets Management** – Move all hard‑coded secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).  
2. **Configuration Hardening** – Disable DEBUG, whitelist hosts, restrict CORS, enable click‑jacking middleware.  
3. **Authentication & Authorization** – Implement JWT or session cookie auth, enforce `IsAuthenticated` and role checks on all API endpoints.  
4. **OTP & Password Handling** – Use `secrets`, hash OTPs, enforce expiration, clear after use, enforce password complexity and rotation.  
5. **Client‑Side Security** – Use HTTPS, generic error messages, CSRF tokens, secure token storage, input validation, and rate‑limiting.  
6. **Audit & Logging** – Log all sensitive operations (password resets, DB wipes) with admin identity and timestamp.  
7. **Code Refactoring** – Replace `any` types with proper interfaces, remove unused fields, and enforce unique constraints.

Implementing these changes will transform the current insecure design into a robust, production‑ready security posture.