**Name of vulnerability:** Software Supply Chain Failures  
**Score:** 8/10  
**Severity:** **High**

---

## 1. File‑by‑File Analysis

| File | Vulnerability(s) | Why it matters for the supply chain | Code snippet | Secure Fix |
|------|------------------|-------------------------------------|--------------|------------|
| **server/config/settings.py** | 1. Hard‑coded `SECRET_KEY` 2. `DEBUG=True` 3. `ALLOWED_HOSTS=['*']` 4. `CORS_ALLOW_ALL_ORIGINS=True` 5. Hard‑coded `EMAIL_HOST_PASSWORD` 6. Default DB credentials 7. Missing click‑jacking middleware 8. No pinned third‑party versions 9. No hardening middleware | 1‑6 expose secrets or allow attackers to glean environment details, enabling injection or credential theft. 7 removes a critical defense. 8‑9 allow attackers to pull in vulnerable or malicious packages. | ```python\nSECRET_KEY = 'django-insecure-solaruat-dev-key-change-in-prod'\nDEBUG = True\nALLOWED_HOSTS = ['*']\nCORS_ALLOW_ALL_ORIGINS = True\nEMAIL_HOST_PASSWORD = 'whykkcbcxqkfvkyq'\nDATABASES = {'default': {'USER':'postgres','PASSWORD':'postgres'}}\n``` | Store secrets in environment variables or a secrets manager; set `DEBUG=False`; whitelist hosts; whitelist CORS origins; pin dependencies; enable security middleware. |
| **client/package.json** | No direct vulnerability found, but **no pinned versions** in `package-lock.json` or `pnpm-lock.yaml` | Without exact hashes, the client may pull in newer, potentially vulnerable or malicious packages. | N/A | Ensure lock files contain exact hashes; run `npm audit`/`pnpm audit`. |
| **client/package-lock.json** | Same as above – no hard‑coded secrets, but **no integrity checks** | Same risk as above. | N/A | Verify integrity with `npm ci`. |
| **client/pnpm-lock.yaml** | Same as above – no hard‑coded secrets, but **no integrity checks** | Same risk as above. | N/A | Verify integrity with `pnpm ci`. |
| **server/requirements.txt** | No direct vulnerability found, but **no pinned versions** | Without exact versions, the server may install newer, vulnerable packages. | N/A | Pin all dependencies (`pip freeze > requirements.txt`) and use hash‑checking. |
| **server/pyproject.toml** | No direct vulnerability found, but **no pinned versions** | Same risk as above. | N/A | Pin dependencies and use lock file. |
| **server/package.json** | No direct vulnerability found, but **no pinned versions** | Same risk as above. | N/A | Pin dependencies. |
| **.vite/deps/package.json** | No direct vulnerability found, but **no pinned versions** | Same risk as above. | N/A | Pin dependencies. |
| **.vite/deps/_metadata.json** | No direct vulnerability found, but **no pinned versions** | Same risk as above. | N/A | Pin dependencies. |

---

## 2. Detailed Vulnerability Description – `server/config/settings.py`

| Line | Issue | Impact | Code | Fix |
|------|-------|--------|------|-----|
| 8 | Hard‑coded `SECRET_KEY` | If the repo leaks, attackers can forge sessions, tamper with signed cookies, or decrypt data. | `SECRET_KEY = 'django-insecure-solaruat-dev-key-change-in-prod'` | Load from environment variable or secrets manager (`os.getenv('DJANGO_SECRET_KEY')`). |
| 11 | `DEBUG=True` | Exposes stack traces, internal URLs, and environment variables; reveals Django version and installed packages. | `DEBUG = True` | Set `DEBUG=False` in production; use `os.getenv('DJANGO_DEBUG', 'False')`. |
| 13 | `ALLOWED_HOSTS=['*']` | Allows any host header; vulnerable to HTTP Host header attacks and DNS rebinding. | `ALLOWED_HOSTS = ['*']` | Whitelist actual hostnames: `['example.com', 'api.example.com']`. |
| 55 | `CORS_ALLOW_ALL_ORIGINS=True` | Permits any origin to make cross‑origin requests; exposes API to CSRF and data exfiltration. | `CORS_ALLOW_ALL_ORIGINS = True` | Use `CORS_ALLOWED_ORIGINS = ['https://app.example.com']`. |
| 51 | Hard‑coded `EMAIL_HOST_PASSWORD` | Exposes Office365 SMTP credentials; allows spam/phishing. | `EMAIL_HOST_PASSWORD = "whykkcbcxqkfvkyq"` | Store in environment variable or secrets manager. |
| 80‑82 | Default DB credentials (`USER='postgres'`, `PASSWORD='postgres'`) | Trivial credentials allow database access if repo leaks. | `'USER': 'postgres', 'PASSWORD': 'postgres'` | Use environment variables; create least‑privilege DB user. |
| 43 | Commented out `XFrameOptionsMiddleware` | Removes click‑jacking protection. | `# 'django.middleware.clickjacking.XFrameOptionsMiddleware',` | Re‑enable middleware. |
| Missing | No pinned third‑party package versions | Pulling in newer, potentially vulnerable packages. | N/A | Pin all dependencies (`pip freeze > requirements.txt` or Poetry lock). |
| Missing | No hardening middleware (HSTS, SSL redirect, secure cookies) | Vulnerable to TLS downgrade, cookie theft, MIME sniffing. | N/A | Add `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, etc. |

### Code Snippet Highlighting Vulnerabilities

```python
# Hard‑coded secret key
SECRET_KEY = 'django-insecure-solaruat-dev-key-change-in-prod'

# Debug mode enabled
DEBUG = True

# Open host header policy
ALLOWED_HOSTS = ['*']

# Allow all CORS origins
CORS_ALLOW_ALL_ORIGINS = True

# Hard‑coded email password
EMAIL_HOST_PASSWORD = "whykkcbcxqkfvkyq"

# Default database credentials
'USER': 'postgres',
'PASSWORD': 'postgres',
```

---

## 3. Secure Fix Example (settings.py)

```python
import os
from pathlib import Path
import environ

env = environ.Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, ''),
    DB_NAME=(str, 'solaruat_db'),
    DB_USER=(str, 'postgres'),
    DB_PASSWORD=(str, ''),
    DB_HOST=(str, 'localhost'),
    DB_PORT=(str, '5432'),
    EMAIL_HOST_USER=(str, ''),
    EMAIL_HOST_PASSWORD=(str, ''),
)

environ.Env.read_env()  # reads .env file or system env vars

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = env('DEBUG')
SECRET_KEY = env('SECRET_KEY')

ALLOWED_HOSTS = ['example.com', 'api.example.com']

# CORS – whitelist only trusted origins
CORS_ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com',
]
CORS_ALLOW_ALL_ORIGINS = False

# Email
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.office365.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT'),
    }
}

# Security middleware
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# Re‑enable click‑jacking protection
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
X_FRAME_OPTIONS = 'SAMEORIGIN'
```

---

## 4. Key Takeaway

- **Hard‑coded secrets** and **permissive debug/host/CORS settings** expose the application to credential theft and information leakage.
- **Missing dependency pinning** allows attackers to inject malicious or vulnerable packages via the supply chain.
- **Missing security middleware** (HSTS, secure cookies, click‑jacking protection) leaves the app vulnerable to common web attacks.

By externalizing secrets, pinning dependencies, and enforcing strict security policies, the application’s resilience against supply‑chain compromise is dramatically improved.