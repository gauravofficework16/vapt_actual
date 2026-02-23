**Vulnerability Report – Cryptographic Failures**  
**Score:** **8/10**  
**Severity:** **Critical**

| File | Vulnerability | Technical Description & Code Snippet |
|------|---------------|---------------------------------------|
| **server/config/settings.py** | **Hard‑coded secrets & insecure settings** | <pre>SECRET_KEY = 'hard‑coded‑value'  <br>DEBUG = True  <br>ALLOWED_HOSTS = ['*']  <br>EMAIL_HOST_PASSWORD = 'plain‑text'  <br>DATABASES = { 'USER': 'dbuser', 'PASSWORD': 'dbpass' }</pre>  <br>These values expose cryptographic material and allow attackers to forge sessions, send emails, or connect to the database. |
| **server/reset_pass.py** | **Universal hard‑coded password & leakage** | <pre>NEW_PASSWORD = "Password@1122334455"  <br>emp.set_password(NEW_PASSWORD)  <br>print(f"🔐 Updating passwords for {count} employees to: {NEW_PASSWORD}")</pre>  <br>All users share the same clear‑text password, which is printed to logs. |
| **server/tracker/models.py** | **Plain‑text OTP storage** | <pre>otp_code = models.CharField(max_length=6, blank=True, null=True)</pre>  <br>OTPs are stored unencrypted, enabling immediate impersonation if the DB is compromised. |
| **client/services/api.ts** | **Insecure HTTP transport** | <pre>const SERVER_URL = 'http://siil-gw-drt-vm/uat-solar';</pre>  <br>All API traffic is sent over plain HTTP, exposing credentials, OTPs, and other sensitive data to eavesdropping and MITM attacks. |

### Summary of Findings
1. **Hard‑coded secrets** (secret key, email password, DB credentials) are present in source code.  
2. **Debug mode** and wildcard `ALLOWED_HOSTS` increase exposure risk.  
3. **Universal hard‑coded password** is used for all employees, printed to console.  
4. **OTP codes** are stored in clear text.  
5. **API calls** use plain HTTP, lacking TLS encryption.

### Recommendations
| Issue | Fix |
|-------|-----|
| Hard‑coded secrets | Move all secrets to environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). |
| Debug & ALLOWED_HOSTS | Set `DEBUG = False` in production and specify exact hostnames. |
| Universal password | Generate a unique, random password per user; remove console output. |
| OTP storage | Store a hash of the OTP (`make_password`) and verify with `check_password`; add expiration logic. |
| HTTP transport | Switch to HTTPS (`https://…`), enforce TLS on the server, and store the URL in a config file or env var. |

Implementing these changes will eliminate the identified cryptographic failures and significantly harden the application against credential compromise, MITM attacks, and data leakage.