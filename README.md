# Authentication Platform

A command-line authentication platform implementing password storage 
designed with reference to NIST SP 800-63B (Digital Identity Guidelines) 
recommendations for memorized secret verifiers — salted, iterated 
PBKDF2-HMAC-SHA256 password hashing with constant-time verification.

## Security Design

- **Hashing:** PBKDF2-HMAC-SHA256 (via Python's `hashlib`)
- **Salt:** 128-bit, generated per-user with a cryptographically secure 
  random source (`secrets.randbits`) — exceeds SP 800-63B's 32-bit minimum
- **Iterations:** 10,000, aligned with SP 800-63B's guidance to use 
  "typically at least 10,000 iterations"
- **Comparison:** constant-time hash comparison via `hmac.compare_digest` 
  to mitigate timing attacks

## Requirements

- Python 3.14.0 or later

## Dependencies

All dependencies are part of the Python standard library — no installation required.

- `hashlib` — PBKDF2-HMAC-SHA256 password hashing
- `secrets` — cryptographically secure random salt generation
- `hmac` — constant-time hash comparison

## Usage

Register a new user:
```bash
python3 main.py register -u <username> -p <password>
```

Log in as an existing user:
```bash
python3 main.py login -u <username> -p <password>
```

## Authors

- [@atharvamishra](https://www.github.com/Mishra-Atharva)