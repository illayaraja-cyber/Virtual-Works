# VirtualWorks Cybersecurity Tasks

This repository contains five modular Python examples developed for the VirtualWorks Cyber Security internship task set. The examples are intended for **defensive learning and authorized testing only**.

## Repository layout

```text
Virtual-Works/
├── task1_password_strength/
├── task2_port_status/
├── task3_email_risk/
├── task4_file_protection/
└── task5_login_control/
```

All scripts use the Python standard library and require Python 3.10 or newer.

---

## Task 1: Password Strength Checker

Directory: [`task1_password_strength/`](task1_password_strength/)

The password checker evaluates a password using these factors:

- Minimum length of 12 characters
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters

It classifies the result as **Weak**, **Medium**, or **Strong**, and gives feedback for missing characteristics. The default input method uses `getpass` so the password is not displayed while typing.

Run it privately:

```bash
cd task1_password_strength
python3 password_strength_checker.py
```

Run a repeatable demonstration:

```bash
python3 password_strength_checker.py --password 'Long!Secure123'
```

A score is only a guideline. Production systems should also use unique passwords, password managers, multi-factor authentication, and breached-password screening.

---

## Task 2: Port Status Checker

Directory: [`task2_port_status/`](task2_port_status/)

The port checker attempts one TCP connection to a specified host and port. It reports whether the port is open or closed/filtered and supports a configurable timeout.

Examples:

```bash
cd task2_port_status
python3 port_status_checker.py 22
python3 port_status_checker.py 443 example.com --timeout 3
```

The tool checks one port only; it does not scan port ranges. Run it only against systems that you own or are explicitly authorized to test. A timeout may indicate packet filtering rather than a definitively closed port.

---

## Task 3: Email Risk Analyzer

Directory: [`task3_email_risk/`](task3_email_risk/)

The email analyzer uses transparent local heuristics to identify potentially unsafe messages. It flags:

- Urgent or pressure-based language
- Requests for passwords, OTPs, banking information, or other sensitive data
- Insecure HTTP links
- URL shorteners
- IP-address links
- Punycode or unusual link hosts

Analyze text directly:

```bash
cd task3_email_risk
python3 email_risk_analyzer.py --text 'URGENT: send your password at http://bit.ly/demo'
```

Analyze a text file:

```bash
python3 email_risk_analyzer.py --file message.txt
```

The analyzer never downloads or executes links. Its findings are warning signals for human review, not proof that a message is malicious.

---

## Task 4: File Protection Utility

Directory: [`task4_file_protection/`](task4_file_protection/)

The file utility demonstrates password-based protection and restoration of file contents. It uses:

- PBKDF2-HMAC-SHA256 for password-based key derivation
- Random salt and nonce values
- A keyed SHA-256 keystream for the demonstration encryption layer
- HMAC-SHA256 for tamper detection and authentication

Example:

```bash
cd task4_file_protection
printf 'confidential note\n' > note.txt
python3 file_protection.py encrypt note.txt note.bin 'demo-password'
python3 file_protection.py decrypt note.bin restored.txt 'demo-password'
cat restored.txt
```

**Production warning:** this is an educational implementation. For real applications, use an audited authenticated-encryption library such as `cryptography` with Fernet or AES-GCM. Do not place real passwords in shell history or source code.

---

## Task 5: Login Attempt Control System

Directory: [`task5_login_control/`](task5_login_control/)

The simulated login controller demonstrates defenses against repeated password guessing:

- Salted PBKDF2 password hashing
- Constant-time credential comparison
- Failed-attempt counting
- Temporary lockout after three failures
- Monotonic timing for lockout expiry

Run the interactive demonstration:

```bash
cd task5_login_control
python3 login_control.py
```

The default demonstration account can also be configured from the command line:

```bash
python3 login_control.py --username alice --password 'correct-horse-battery-staple'
```

Production systems should use a durable server-side rate limiter, secure password-reset workflows, multi-factor authentication, audit logging, and carefully designed lockout policies that reduce denial-of-service risk.

---

## General safety and authorization

These examples are for education and defensive security work. Use the port checker only on authorized systems, protect all passwords and sensitive files, and have permission before analyzing or handling data belonging to another person or organization.
