**Vulnerability Report – Security Misconfiguration**  
**Score:** **8/10**  
**Severity:** **Critical**

---

### 1. `server/config/settings.py`

| Issue | Why it’s a problem | Secure Fix (code snippet) |
|-------|--------------------|---------------------------|
| Hard‑coded `SECRET_KEY` | Exposes session signing key; if leaked, attackers can forge sessions. | ```python<br>import os<br>SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')  # set in env or .env<br>``` |
| `DEBUG = True` | Reveals stack traces, internal URLs, and sensitive data to any user. | ```python<br>DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'<br>``` |
| `ALLOWED_HOSTS = ['*']` | Allows any host header → Host header attacks. | ```python<br>ALLOWED_HOSTS = ['example.com', 'www.example.com']<br>``` |
| `CORS_ALLOW_ALL_ORIGINS = True` | Permits any domain to call APIs → XSS/CSRF risk. | ```python<br>CORS_ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']<br>``` |
| Click‑jacking middleware commented out | `X_FRAME_OPTIONS` header may not be applied. | ```python<br>MIDDLEWARE = [<br>    'corsheaders.middleware.CorsMiddleware',<br>    'django.middleware.security.SecurityMiddleware',<br>    'django.contrib.sessions.middleware.SessionMiddleware',<br>    'django.middleware.common.CommonMiddleware',<br>    'django.middleware.csrf.CsrfViewMiddleware',<br>    'django.contrib.auth.middleware.AuthenticationMiddleware',<br>    'django.contrib.messages.middleware.MessageMiddleware',<br>    'django.middleware.clickjacking.XFrameOptionsMiddleware',<br>]<br>``` |
| Hard‑coded email credentials | Risk of credential leakage. | ```python<br>EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')<br>EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')<br>``` |
| Hard‑coded DB credentials | Anyone with repo access can connect to DB. | ```python<br>DATABASES = {<br>    'default': {<br>        'ENGINE': 'django.db.backends.postgresql',<br>        'NAME': os.getenv('POSTGRES_DB'),<br>        'USER': os.getenv('POSTGRES_USER'),<br>        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),<br>        'HOST': os.getenv('POSTGRES_HOST', 'localhost'),<br>        'PORT': os.getenv('POSTGRES_PORT', '5432'),<br>    }<br>}<br>``` |
| Missing security headers (`SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, etc.) | Application may serve over HTTP and be vulnerable to MITM. | ```python<br>SECURE_SSL_REDIRECT = True<br>SESSION_COOKIE_SECURE = True<br>CSRF_COOKIE_SECURE = True<br>SECURE_HSTS_SECONDS = 31536000<br>SECURE_HSTS_INCLUDE_SUBDOMAINS = True<br>SECURE_HSTS_PRELOAD = True<br>``` |
| No validation on media uploads | Executable uploads could be served. | Add validation and serve media via a separate, read‑only server. |

**Summary:** The settings file contains multiple critical misconfigurations that would expose the application to attacks in production.  

---

### 2. `server/reset_pass.py`

| Issue | Why it’s a problem | Secure Fix |
|-------|--------------------|------------|
| Hard‑coded `NEW_PASSWORD` | Anyone with repo access knows the password; resets all accounts to a known value. | Store in environment variable: `NEW_PASSWORD = os.getenv("DEFAULT_RESET_PASSWORD")` |
| Logging plaintext password | Password appears in stdout/logs → persistent exposure. | Remove password from logs; log only count or hash. |
| No environment guard | Script can run in production, resetting all passwords. | Add check: `if os.getenv('DJANGO_ENV') == 'production': raise RuntimeError("Do not run in prod")` |
| No confirmation prompt | Accidental execution resets all accounts. | Prompt user or require explicit flag. |

**Secure Implementation Snippet**

```python
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from tracker.models import Employee

def reset_all_passwords():
    NEW_PASSWORD = os.getenv("DEFAULT_RESET_PASSWORD")
    if not NEW_PASSWORD:
        raise RuntimeError("DEFAULT_RESET_PASSWORD not set")

    if os.getenv('DJANGO_ENV') == 'production':
        raise RuntimeError("Reset script cannot run in production")

    employees = Employee.objects.all()
    count = employees.count()
    if count == 0:
        print("⚠️ No employees found.")
        return

    print(f"🔐 Updating passwords for {count} employees")
    for emp in employees:
        emp.set_password(NEW_PASSWORD)
        emp.save()
    print(f"✅ Success! All {count} employees now have a new password.")
```

---

### 3. `server/tracker/views.py`

| Issue | Why it’s a problem | Secure Fix |
|-------|--------------------|------------|
| No `permission_classes` | Endpoints are open to unauthenticated users → unauthorized data manipulation. | `permission_classes = [IsAuthenticated]` (or custom role check). |
| No file‑size limit | Large uploads can exhaust memory/disk → DoS. | Enforce `MAX_FILE_SIZE` and check `file_obj.size`. |
| No MIME‑type validation | Attackers can rename malicious files → potential code execution. | Validate `file_obj.content_type` against allowed list. |
| No rate‑limiting | Repeated calls can flood server. | Apply DRF throttling (`UserRateThrottle`). |
| Potential exposure of raw file content | `decode('utf-8')` may corrupt binary data. | Handle binary data properly or validate encoding. |

**Secure Implementation Snippet**

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.throttling import UserRateThrottle

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_TYPES = [
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv',
]

class BulkUploadThrottle(UserRateThrottle):
    rate = '10/min'

class ScriptViewSet(viewsets.ModelViewSet):
    queryset = Script.objects.all().order_by('-created_at')
    serializer_class = ScriptSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    permission_classes = [IsAuthenticated]
    throttle_classes = [BulkUploadThrottle]

    def validate_file(self, file_obj):
        if file_obj.size > MAX_FILE_SIZE:
            raise ValidationError("File too large")
        if file_obj.content_type not in ALLOWED_TYPES:
            raise ValidationError("Unsupported file type")

    @action(detail=False, methods=['post'], parser_classes=[MultiPartParser])
    def validate_bulk_upload(self, request):
        file_obj = request.data.get('file')
        if not file_obj:
            return Response({"error": "No file provided"}, status=400)
        self.validate_file(file_obj)
        # ... rest of the logic ...
```

---

### 4. Other Files (`asgi.py`, `wsgi.py`, `main.py`, `manage.py`, `wipe_db.py`, `admin.py`, `urls.py`)

No security misconfigurations were detected in these files.

---

**Overall Assessment**

The repository contains several high‑severity security misconfigurations, primarily in the Django settings, password reset script, and bulk‑upload API endpoints. These issues expose the application to credential leakage, unauthorized access, denial‑of‑service, and potential code execution. Immediate remediation of the highlighted problems is recommended to bring the application to a secure baseline.