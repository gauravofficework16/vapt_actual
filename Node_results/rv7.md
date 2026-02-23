**Vulnerability Report – Authentication Failures**  
**Score:** **8/10** – **Severity: High**

---

## 1. `server/tracker/views.py`

| # | Vulnerability | Why it matters | Code snippet |
|---|----------------|----------------|--------------|
| 1 | **Unprotected API endpoints** | All CRUD viewsets (`ScriptViewSet`, `IssueViewSet`, `EmployeeViewSet`) use the default `AllowAny` permission. Any user (even unauthenticated) can read/write sensitive data. | ```python<br>class ScriptViewSet(viewsets.ModelViewSet):<br>    permission_classes = [permissions.AllowAny]  # <‑‑ vulnerable<br>``` |
| 2 | **No authentication token issued** | The `login` flow only sends an OTP; it never returns a JWT or session cookie. Subsequent API calls lack an authenticated context. | ```python<br>@action(detail=False, methods=['post'])<br>def login(self, request):<br>    …  # OTP sent, but no token returned<br>``` |
| 3 | **Weak OTP generation** | Uses `random.randint`, which is not cryptographically secure. An attacker could predict or brute‑force the OTP. | ```python<br>otp = random.randint(100000, 999999)  # insecure<br>``` |
| 4 | **Missing OTP expiration check** | `reset_password_confirm` validates the OTP but does not verify that it is still within the 5‑minute window. | ```python<br>if not employee.otp_verified:<br>    …<br>``` |
| 5 | **Plain‑text password reset** | The reset logic assigns `employee.password = new_password` without hashing, storing the password in clear text. | ```python<br>employee.password = new_password  # insecure<br>employee.save()<br>``` |

**Fixes (excerpt)**  
```python
# 1. Enforce authentication
permission_classes = [permissions.IsAuthenticated]

# 2. Issue JWT after OTP verification
token = RefreshToken.for_user(employee).access_token
return Response({'token': str(token)})

# 3. Use cryptographic randomness
import secrets
otp = secrets.randbelow(900000) + 100000

# 4. Check expiration
if timezone.now() > employee.otp_created_at + timedelta(minutes=5):
    return Response({'detail': 'OTP expired'}, status=400)

# 5. Hash password
employee.set_password(new_password)
employee.save()
```

---

## 2. `server/tracker/serializers.py`

| # | Vulnerability | Why it matters | Code snippet |
|---|----------------|----------------|--------------|
| 1 | **Password not required on create** | Allows creation of accounts with empty passwords, bypassing authentication. | ```python<br>password = serializers.CharField(write_only=True, required=False)  # vulnerable<br>``` |
| 2 | **Client can set `password_hash`** | `password_hash` is write‑only but not read‑only; an attacker can supply a pre‑computed hash, creating an account with a known password. | ```python<br>validated_data.pop('password_hash', None)  # but still accepted<br>``` |
| 3 | **Direct `password_hash` update** | `super().update()` may persist a supplied `password_hash`, bypassing Django’s hashing. | ```python<br>user = super().update(instance, validated_data)  # may write hash<br>``` |
| 4 | **No permission checks in other serializers** | While not a direct auth flaw, lack of permission enforcement can allow unauthorized CRUD on related objects. | — |

**Fixes (excerpt)**  
```python
# 1. Make password mandatory
password = serializers.CharField(write_only=True, required=True)

# 2. Remove write access to password_hash
class Meta:
    extra_kwargs = {'password_hash': {'write_only': True, 'read_only': True}}

# 3. Sanitize update
def update(self, instance, validated_data):
    validated_data.pop('password_hash', None)
    password = validated_data.pop('password', None)
    user = super().update(instance, validated_data)
    if password:
        user.set_password(password)
        user.save()
    return user
```

---

## 3. `server/config/settings.py`

| # | Vulnerability | Why it matters | Code snippet |
|---|----------------|----------------|--------------|
| 1 | **DEBUG enabled in production** | Exposes stack traces and secrets. | `DEBUG = True` |
| 2 | **Wildcard ALLOWED_HOSTS** | Allows HTTP Host header attacks. | `ALLOWED_HOSTS = ['*']` |
| 3 | **Hard‑coded SECRET_KEY** | Enables session cookie forgery. | `SECRET_KEY = 'django-insecure-solaruat-dev-key-change-in-prod'` |
| 4 | **Hard‑coded email password** | Credential leakage. | `EMAIL_HOST_PASSWORD = "whykkcbcxqkfvkyq"` |
| 5 | **Hard‑coded DB credentials** | Database compromise. | `DATABASES['default']['USER'] = 'postgres'` |
| 6 | **CORS_ALLOW_ALL_ORIGINS = True** | Exposes authenticated endpoints to any origin. | `CORS_ALLOW_ALL_ORIGINS = True` |
| 7 | **Click‑jacking middleware commented out** | Allows iframe phishing. | `# 'django.middleware.clickjacking.XFrameOptionsMiddleware',` |

**Fixes (excerpt)**  
```python
DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = ['example.com', 'api.example.com']
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB'),
        'USER': os.getenv('POSTGRES_USER'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),
        'HOST': os.getenv('POSTGRES_HOST', 'localhost'),
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
    }
}
CORS_ALLOWED_ORIGINS = ['https://app.example.com', 'https://api.example.com']
MIDDLEWARE.append('django.middleware.clickjacking.XFrameOptionsMiddleware')
```

---

## 4. `server/reset_pass.py`

| # | Vulnerability | Why it matters | Code snippet |
|---|----------------|----------------|--------------|
| 1 | **Hard‑coded new password** | Anyone who reads the script learns the password for all employees. | `NEW_PASSWORD = "Password@1122334455"` |
| 2 | **Mass password reset without checks** | Resets every employee to the same password, potentially locking out legitimate users. | ```python<br>for emp in employees:<br>    emp.set_password(NEW_PASSWORD)<br>    emp.save()<br>``` |

**Fixes (excerpt)**  
```python
import os, getpass, re
from django.core.exceptions import ValidationError

def validate_password(pwd):
    if len(pwd) < 12 or not re.search(r'\d', pwd) or not re.search(r'[^\w\s]', pwd):
        raise ValidationError("Password does not meet complexity requirements.")

def reset_all_passwords():
    NEW_PASSWORD = os.getenv("NEW_EMPLOYEE_PASSWORD") or getpass.getpass("Enter new password: ")
    validate_password(NEW_PASSWORD)
    for emp in Employee.objects.all():
        emp.set_password(NEW_PASSWORD)
        emp.save()
```

---

## 5. `client/services/api.ts`

| # | Vulnerability | Why it matters | Code snippet |
|---|----------------|----------------|--------------|
| 1 | **No Authorization header** | All protected endpoints are called without a bearer token or session cookie. | ```ts<br>const res = await fetch(`${API_BASE}/employees/`);<br>``` |
| 2 | **Missing `credentials: 'include'`** | Browser will not send session cookies, breaking session‑based auth. | ```ts<br>fetch(url, { method: 'GET' });<br>``` |
| 3 | **No CSRF token for POST/PUT** | If the backend uses CSRF protection (e.g., Django), requests will be rejected or can be forged. | ```ts<br>fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'} });<br>``` |

**Fixes (excerpt)**  
```ts
const authHeaders = (token?: string) => ({
  ...(token ? { Authorization: `Bearer ${token}` } : {}),
  'Content-Type': 'application/json',
});

const csrfToken = getCookie('csrftoken');

const getEmployees = async (token: string): Promise<Employee[]> => {
  const res = await fetch(`${API_BASE}/employees/`, {
    headers: authHeaders(token),
    credentials: 'include',
    headers: { ...authHeaders(token), 'X-CSRFToken': csrfToken },
  });
  if (!res.ok) throw new Error('Failed to fetch employees');
  return res.json();
};
```

---

## 6. `client/components/LoginScreen.tsx` & `client/components/ChangePasswordModal.tsx`

No authentication‑failure issues detected in these components.

---

### Overall Assessment

The codebase contains multiple authentication‑failure vectors:

1. **Unprotected API endpoints** and **missing token issuance** in the backend.  
2. **Weak OTP generation** and **no expiration checks**.  
3. **Plain‑text password handling** and **hard‑coded credentials**.  
4. **Missing authentication headers** and **CSRF protection** on the client side.  
5. **Hard‑coded secrets** and **permissive settings** in `settings.py`.

These weaknesses collectively allow attackers to bypass authentication, compromise user accounts, and potentially gain full control of the system.

**Recommendation:**  
Implement the fixes outlined above, enforce strict permission classes, use secure random generators, hash all passwords, externalize secrets, and ensure the client always sends authenticated requests with proper CSRF tokens. After remediation, re‑run a full penetration test to confirm that all authentication failures have been eliminated.