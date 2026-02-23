**Security Vulnerability Report – Security Logging & Alerting Failures**  
*Repository scanned: `/home/ubuntu/Documents/GAURAV's WORK/VAPT/cloned_code`*  

| Item | Description | Code Snippet | Impact | Fix |
|------|-------------|--------------|--------|-----|
| **Vulnerability** | Security Logging & Alerting Failures | – | – | – |
| **Score** | 8/10 | – | – | – |
| **Severity** | **Critical** | – | – | – |

---

### 1. `server/config/settings.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No explicit logging configuration | 1‑108 | Django falls back to default console logger → security events (failed logins, CSRF, etc.) are not captured or alerted. | Add a `LOGGING` dictionary that logs `django.security`, `django.request`, and sends critical logs to a file and/or email. |
| `DEBUG = True` in production | 11 | Exposes stack traces and sensitive data. | Set `DEBUG = False` and configure `ALLOWED_HOSTS`. |
| `ALLOWED_HOSTS = ['*']` | 13 | Allows host‑header injection. | Restrict to actual domain names. |

**Example addition**

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {'verbose': {'format': '[{asctime}] {levelname} {name} {message}', 'style': '{'}},
    'handlers': {
        'file': {'level': 'WARNING', 'class': 'logging.FileHandler',
                 'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
                 'formatter': 'verbose'},
        'mail_admins': {'level': 'ERROR',
                         'class': 'django.utils.log.AdminEmailHandler',
                         'include_html': True},
    },
    'loggers': {
        'django.security': {'handlers': ['file', 'mail_admins'],
                            'level': 'WARNING', 'propagate': False},
        'django.request': {'handlers': ['file', 'mail_admins'],
                           'level': 'ERROR', 'propagate': False},
    },
}
```

---

### 2. `server/tracker/views.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No audit log for failed login | 62‑70 | Brute‑force attempts go unnoticed. | Log each failure with IP, user‑code, timestamp. |
| No audit log for successful login | 70‑80 | Successful logins are invisible. | Log each success. |
| `print` on email failure | 70‑75 | No persistence or alert. | Replace with `logger.error` and create an `AuditLog`. |
| No audit log for OTP expiration / mismatch | 120‑135 | Attackers can repeatedly request OTPs. | Log each expiration/mismatch. |
| No audit log for forgot‑password initiation / confirmation | 142‑190 | Sensitive actions lack traceability. | Log initiation, OTP send, reset confirmation, and failures. |
| No audit log for OTP clearing | 140‑145 | Clearing OTP is a security event. | Log it. |
| No audit logger used | Throughout | No security events are recorded. | Create `security_logger = logging.getLogger('security')` and use it. |

**Sample fix**

```python
security_logger = logging.getLogger('security')

@action(detail=False, methods=['post'])
def login(self, request):
    ...
    if not employee.check_password(password):
        security_logger.warning(
            "Failed login for code %s from IP %s", code, ip)
        return Response({"detail": "Invalid credentials."},
                        status=status.HTTP_401_UNAUTHORIZED)

    security_logger.info(
        "Successful login for code %s from IP %s", code, ip)
    ...
```

---

### 3. `server/tracker/admin.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No audit trail for password changes | 35‑55 | Password changes are silent. | Log in `clean_new_password` and `save`. |
| No audit trail for employee create/update/delete | 90‑110 | Critical data changes are untracked. | Override `save_model` and `delete_model` to write to `AuditLog`. |
| No audit trail for script imports | 140‑160 | Import failures are silent. | Log each import attempt and skipped rows. |
| No audit trail for password validation failures | 45‑55 | Repeated validation failures are unlogged. | Log each failure. |
| `AuditLog` model unused | – | Intended audit mechanism never used. | Ensure all critical actions write to it. |

**Sample fix**

```python
class EmployeeAdmin(ImportExportModelAdmin):
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        action = 'Updated' if change else 'Created'
        AuditLog.objects.create(
            user=request.user,
            action=action,
            details=f'{action} employee {obj.code}'
        )
```

---

### 4. `server/tracker/serializers.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No audit logging for create/update | 24‑38 | Critical data changes are untracked. | Log each create/update with `logging.getLogger('audit')`. |
| No audit logging for issue history access | 70‑78 | Access to issue history is unlogged. | Log each access. |

**Sample fix**

```python
logger = logging.getLogger('audit')

def create(self, validated_data):
    user = Employee.objects.create(**validated_data)
    logger.info(f"Employee created: id={user.id}, code={user.code}")
    return user
```

---

### 5. `server/tracker/models.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No audit trail for Script/TestStep/Issue changes | 71‑133 | Business‑critical objects are untracked. | Add `post_save`/`post_delete` signals that write to `AuditLog`. |
| Password changes not logged | 64‑68 | Silent password changes. | Wrap `set_password` to log. |
| OTP usage not logged | 58‑59 | OTP issuance/verification untracked. | Log OTP events. |
| No alert on failed login attempts | – | Brute‑force attacks go unnoticed. | Log each failed attempt and trigger alert after threshold. |
| `AuditLog` unused | – | Intended audit mechanism never used. | Ensure all critical actions write to it. |

**Signal example**

```python
@receiver(post_save, sender=Script)
def script_saved(sender, instance, created, **kwargs):
    action = 'created' if created else 'updated'
    AuditLog.objects.create(
        script=instance,
        user_code=getattr(instance, '_audit_user', 'system'),
        action=action,
        details=str(instance.__dict__)
    )
```

---

### 6. `server/reset_pass.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| Hard‑coded password logged in plain text | 12‑32 | Exposes credentials. | Remove password from logs; use env variable. |
| `print` instead of logging | 14‑32 | No persistent audit trail. | Use `logging` and avoid printing sensitive data. |
| No error handling | – | Silent failures. | Wrap in `try/except` and log exceptions. |

**Secure version**

```python
import os, logging, django
from django.core.exceptions import ImproperlyConfigured

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

logger = logging.getLogger(__name__)
NEW_PASSWORD = os.getenv('EMPLOYEE_RESET_PASSWORD')
if not NEW_PASSWORD:
    logger.error("EMPLOYEE_RESET_PASSWORD not set")
    raise ImproperlyConfigured("Missing reset password")

# ... rest of script using logger instead of print ...
```

---

### 7. `server/wipe_db.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| `print` only | 5 | No persistent audit trail. | Use `logging` with file handler. |
| No user context | 5 | Cannot trace who ran the script. | Log `getpass.getuser()` or request user. |
| No alerting | 5 | Destructive action goes unnoticed. | Send email/Slack alert after wipe. |

**Secure version**

```python
import logging, getpass
from django.db import connection

logger = logging.getLogger('wipe_db')
user = getpass.getuser()
logger.info("⚠️  WARNING: Deleting all data…", extra={'user': user})
with connection.cursor() as cursor:
    cursor.execute("DROP SCHEMA public CASCADE;")
    cursor.execute("CREATE SCHEMA public;")
logger.info("✅ Database wiped successfully.", extra={'user': user})
```

---

### 8. `server/seed.py`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| `print` only | 1‑4 | No persistent audit trail. | Use `logging`. |
| No error handling | 5‑7 | Silent failures. | Wrap in `try/except` and log. |
| Bulk delete without audit | 10‑12 | Destructive operation untracked. | Log deletions. |
| Bulk create with hard‑coded password | 15‑18 | Security risk. | Log each creation; enforce password change. |
| No alert on failures | 31‑33 | Silent failures. | Log and send email/Slack. |
| No audit for scenario creation | 38‑70 | Business logic changes untracked. | Log each creation. |
| No alert on issue creation | 71‑73 | Failure to notify responsible team. | Log and trigger alert. |

**Secure version**

```python
import logging, django
from django.core.mail import send_mail

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler('seed.log')
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(handler)

def run_seed():
    try:
        logger.info("Cleaning database…")
        for model in [ChatMessage, AuditLog, Issue, TestStep, Script, Employee]:
            count = model.objects.all().delete()[0]
            logger.info(f"Deleted {count} records from {model.__name__}")

        # create users, set passwords, etc.
        # log each step
    except Exception as exc:
        logger.exception("Seed failed")
        send_mail("Seed script failure", str(exc), "noreply@example.com",
                  ["admin@example.com"])
        raise
```

---

### 9. `client/services/api.ts`

| Issue | Lines | Why it matters | Fix |
|-------|-------|----------------|-----|
| No client‑side logging of failed auth | 12‑45 | Brute‑force attempts unlogged. | Call audit endpoint on `res.ok == false`. |
| Silent audit log failure | 120‑130 | Audit failures hidden. | Throw error or reject promise. |
| No alert for critical ops | 70‑200 | Failures may go unnoticed. | Wrap each `fetch` in try/catch, log to Sentry or audit endpoint. |
| No retry logic | 12‑200 | Repeated failures can flood UI. | Implement exponential back‑off. |
| Potential sensitive data in error messages | 12‑45 | Stack traces may leak. | Sanitize error payload before throwing/logging. |

**Sample wrapper**

```ts
const fetchWithAudit = async (url: string, opts: RequestInit, event?: string) => {
  try {
    const res = await fetch(url, opts);
    if (!res.ok) {
      const err = await res.json();
      if (event) await api.createLog({ event, details: err.detail });
      throw new Error(err.detail || 'Request failed');
    }
    return res;
  } catch (e) {
    if (event) await api.createLog({ event, details: e.message });
    throw e;
  }
};
```

---

## Overall Assessment

- **Score:** 8/10  
- **Severity:** **Critical** – The application lacks comprehensive audit logging, alerting, and error handling for all security‑relevant operations.  
- **Impact:** Attackers can perform credential stuffing, OTP abuse, or destructive actions without detection. Administrators cannot detect or investigate incidents.  
- **Recommendation:** Implement the fixes above, enforce a central audit logger, and integrate with an external monitoring/alerting system (e.g., Sentry, Slack, PagerDuty). Ensure all destructive or sensitive operations are logged with user context, timestamps, and persisted to a tamper‑resistant store.  

---