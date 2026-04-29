# A-Z Books Online Store - CA3 SSDLC Demo

This is a Flask + SQLite Online Book Store Portal for the CA3 Application Security SSDLC project.

## Run in Kali Linux

```bash
cd online_bookstore_secure
sudo apt update
sudo apt install python3 python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000

## Demo Admin

- Username: `admin_nithin`
- Password: `ChangeMe@12345`

## Presentation Focus: Top 3 High-Impact Vulnerabilities

Use `/security-plan` during the presentation. It maps each vulnerability to STRIDE, OWASP ASVS area, implemented mitigation, and demo evidence.

1. **Credential stuffing / brute force**
   - STRIDE: Spoofing
   - ASVS: V2 Authentication
   - Evidence: failed login attempts, account lockout, audit logs.

2. **Checkout price / quantity tampering**
   - STRIDE: Tampering
   - ASVS: V5 Validation / Business Logic Security
   - Evidence: hidden client_total exists for demo; if changed in DevTools/Burp, server recalculates total and logs `CHECKOUT_TAMPER_BLOCKED`.

3. **Unauthorised admin access / privilege escalation**
   - STRIDE: Elevation of Privilege
   - ASVS: V4 Access Control
   - Evidence: `/admin` blocks non-admin users with 403 and logs `ADMIN_ACCESS_BLOCKED`.

## Important Note

This project is for local academic demonstration. For real deployment, enable HTTPS and set `SESSION_COOKIE_SECURE=True`.
