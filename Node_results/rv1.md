**Name of vulnerability:** Broken access control  
**Vulnerability Score:** 9/10  
**Severity:** Critical  

---

## Detailed Technical Analysis

| File | Technical Description | Vulnerable Code Snippet | Secure Fix |
|------|------------------------|------------------------|------------|
| **server/tracker/views.py** | The `ScriptViewSet` and its custom actions expose CRUD operations without any authentication or ownership checks. Any user (even unauthenticated) can create, update, or delete scripts and associated nodes. | ```python<br>class ScriptViewSet(viewsets.ModelViewSet):<br>    queryset = Script.objects.all()<br>    serializer_class = ScriptSerializer<br>``` | Add `permission_classes = [IsAuthenticated]` and filter the queryset to the current user. In custom actions, verify `script.owner == request.user` before creating or modifying data. |
| **server/reset_pass.py** | The script resets **every** employee’s password without any authentication or authorization. Anyone who can run the script can lock out all users. | ```python<br>for emp in employees:<br>    emp.set_password(NEW_PASSWORD)<br>    emp.save()<br>``` | Move logic to a Django management command that requires a secret key or super‑user flag. Verify the caller’s identity before executing. |
| **server/wipe_db.py** | The script drops and recreates the entire database schema without any guard. Anyone who can execute it can wipe the database. | ```python<br>cursor.execute("DROP SCHEMA public CASCADE;")<br>cursor.execute("CREATE SCHEMA public;")<br>``` | Restrict execution to a privileged OS user, add an explicit confirmation prompt, or expose it only via a protected Django view/command. |
| **server/tracker/serializers.py** | Serializers allow any authenticated (or even unauthenticated) client to create or modify `Script`, `TestStep`, `AuditLog`, `ChatMessage`, and `Issue` objects without permission checks. | ```python<br>def create(self, validated_data):<br>    script = Script.objects.create(**validated_data)<br>``` | Move permission logic to the view layer or validate the request user inside the serializer. Use `request.user.has_perm(...)` or custom permission classes to enforce RBAC. |

---

### Secure Fix Summary

1. **Enforce Authentication & RBAC**  
   - Add `permission_classes = [IsAuthenticated]` to all viewsets.  
   - Create custom permission classes (`IsScriptOwner`, `IsAdmin`) and apply them where needed.

2. **Ownership Validation**  
   - In custom actions, compare `script.owner` with `request.user`.  
   - Reject the request with `403 Forbidden` if the check fails.

3. **Restrict Sensitive Operations**  
   - Move destructive scripts (`reset_pass.py`, `wipe_db.py`) into Django management commands that require a secret key or super‑user flag.  
   - Add confirmation prompts and audit logging.

4. **Serializer Validation**  
   - Inject `request` into serializer context and validate permissions in `create`/`update` methods.  
   - Alternatively, enforce permissions in the view layer and keep serializers “plain”.

5. **Audit & Logging**  
   - Log every privileged operation (password reset, database wipe, script creation) with the user ID and timestamp.

Implementing these changes will eliminate the broken access control vulnerabilities and ensure that only authorized users can perform privileged actions.