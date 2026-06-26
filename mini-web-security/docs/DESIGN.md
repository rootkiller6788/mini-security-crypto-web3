# mini-web-security Design Document

## Overview

mini-web-security is a pure C99 library providing web application security primitives. It covers the OWASP Top 10 categories, XSS/CSRF protection, SQL/NoSQL injection detection, input validation, authentication, session management, and cryptographic operations. The library has zero external dependencies and uses only standard C99 headers.

## Design Principles

### 1. Zero Dependencies
All cryptographic primitives (SHA-256, HMAC, PBKDF2) are implemented from scratch in pure C99. No OpenSSL, no libsodium, no platform-specific APIs required. This ensures maximum portability across embedded systems, IoT devices, and constrained environments.

### 2. C99 Compliance
The codebase targets strict C99 (`-std=c99 -Wall -Wextra -pedantic`). No C11 features, no GNU extensions. All variable declarations occur at the beginning of blocks. The `bool` type is used via `<stdbool.h>`.

### 3. Header + Source Separation
Each module is split into a header (`.h`) declaring the public API and a source file (`.c`) implementing the logic. Headers include only standard library headers and use include guards (`#ifndef` / `#define` / `#endif`).

### 4. Defensive Programming
All public functions validate input pointers before dereferencing. Buffer operations use size-limited variants (`strncpy`, `snprintf`, `memcpy` with bounds checks). Constant-time comparisons are used where appropriate (e.g., CSRF token validation, password verification).

### 5. Security-First Defaults
Default configurations are secure. PBKDF2 uses 100,000 iterations. TOTP defaults to SHA-256 HMAC with 6 digits and 30-second period. CSRF tokens use 32 random bytes. Session IDs are 128-bit random values.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Application Code                     │
├─────────────────────────────────────────────────────────┤
│  xss_csrf   │  sqli_inject  │  owasp_top10  │  input_v  │
│  (XSS/CSRF) │  (SQLi/NoSQL) │  (OWASP Scan)  │  (Valid)  │
├─────────────┴───────────────┴───────────────┴───────────┤
│                    auth_session                          │
│  (Password, TOTP, JWT, Session, Rate Limit, OAuth2)     │
├─────────────────────────────────────────────────────────┤
│              Crypto: SHA-256, HMAC, PBKDF2              │
└─────────────────────────────────────────────────────────┘
```

### Module Dependency Graph

```
auth_session (SHA-256, HMAC, PBKDF2)
    └── (self-contained crypto)
    
xss_csrf (HTML/JS encoding, CSP, CSRF tokens)
    └── auth_session (for session cookie helpers)
    
sqli_inject (SQL pattern matching, escape, NoSQL, ORM)
    └── (self-contained)
    
owasp_top10 (SSRF, LFI/RFI, directory traversal, logging)
    └── (self-contained)
    
input_validation (types, formats, UTF-8, parameter pollution)
    └── (self-contained)
```

## Module Details

### xss_csrf — XSS & CSRF

**XSS Detection** uses pattern matching against known attack vectors:
- `<script>`, `javascript:`, event handlers (`onerror=`, `onload=`)
- DOM sinks: `innerHTML`, `document.write`, `eval`
- Classification: reflected (query param), stored (DB read), DOM-based (client JS)

**Encoding Strategies** follow OWASP XSS Prevention Cheat Sheet:
- HTML body: entity encoding (`<` → `&lt;`)
- HTML attributes: hex entity encoding all non-alphanumeric chars
- JavaScript: `\xHH` escape sequences for non-printable, `\uXXXX` for `<` `>`
- URL: percent-encoding for non-URL-safe characters

**CSP Implementation** builds a policy object with up to 16 directives. Supports 14 source types (default-src, script-src, style-src, etc.). Generates proper HTTP header format. Nonce generation uses random bytes encoded as base64. Hash generation uses djb2 (simple demonstration; production would use SHA-256).

**CSRF Protection** implements three defense layers:
1. Synchronizer Token Pattern: 32 random bytes, hex-encoded for HTML forms
2. Origin/Referer header validation: host extraction and comparison with subdomain support
3. SameSite cookies: Lax, Strict, or None with HttpOnly and Secure flags

### sqli_inject — SQL/NoSQL Injection

**Pattern Database** contains 14 known SQL injection patterns classified by type:
- Classic: `' OR 1=1--`, `" OR "1"="1`
- UNION-based: `' UNION SELECT`
- Blind (boolean): `AND 1=1`, `AND 1=2`
- Blind (time): `SLEEP(`, `WAITFOR DELAY`
- Stacked: `; DROP TABLE`
- Error-based: `extractvalue(`, `updatexml(`
- Out-of-band: `UTL_HTTP.REQUEST`

**Prepared Statement Emulation** provides a safe query building interface. Template queries use `?` placeholders replaced with properly typed and escaped values. Supports int, float, text (with escaping), and NULL bindings.

**NoSQL Injection Detection** checks for MongoDB-specific operators:
- Comparison operators: `$gt`, `$ne`, `$lt`, `$gte`, `$lte`
- Evaluation operators: `$regex`, `$where`, `$exists`
- Logical operators: `$or`, `$and`, `$not`, `$nor`
- Update operators: `$set`, `$unset`, `$push`, `$inc`

**Second-Order SQLi** tracking marks stored values that contain SQL metacharacters. When those values are later used in query construction, a warning is raised.

### owasp_top10 — OWASP Top 10

**Mapping** implements all 10 categories from the 2021 edition with names and descriptions.

**SSRF Analysis** extracts host, port, and path from URLs. Checks for:
- Loopback: `127.0.0.1`, `localhost`, `::1`, `0.0.0.0`
- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.0.0/16`
- Multicast/reserved: `>= 224.0.0.0`

**File Inclusion** detects:
- LFI patterns: `../`, `/etc/passwd`, `php://filter`, `file://`
- RFI patterns: `http://`, `https://`, `ftp://`

**Directory Traversal** detects:
- `../` and `..\` sequences
- Null byte attacks
- Double encoding: `%2e%2e%2f`

**Reporting** aggregates findings into structured reports with category, risk level, description, and remediation advice.

### input_validation — Input Validation

**Validation Strategy** follows a defense-in-depth approach:
1. **Allowlisting** — accept only known-good values
2. **Type Checking** — validate data type (int, float, alpha, alphanum)
3. **Format Validation** — structural validation (email, URL, credit card)
4. **Length Limits** — enforce min/max bounds
5. **Canonicalization** — normalize before comparison

**UTF-8 Validation** implements RFC 3629:
- Validates byte sequences for 1-4 byte codepoints
- Detects overlong encodings (e.g., `C0 80` for NUL)
- Checks valid continuation byte ranges
- Rejects surrogate codepoints and values > U+10FFFF

**Luhn Algorithm** validates credit card numbers using the standard checksum formula. Handles 13-19 digit numbers.

**Parameter Pollution** parses query strings, tracking duplicate parameter names. Detection reports which parameters appear multiple times, often exploited for WAF bypass or business logic attacks.

**Mass Assignment Protection** provides field whitelisting for ORM and API endpoints. Only explicitly allowed fields pass validation, preventing attribute injection (e.g., setting `is_admin=true`).

### auth_session — Authentication & Session

**Password Hashing** implements PBKDF2 with SHA-256 HMAC:
- Salt: 16 random bytes
- Iterations: 100,000 (OWASP recommendation)
- Output: 32-byte derived key
- Verification: constant-time comparison to prevent timing attacks
- Strength scoring: length + character class analysis (0-100)

**TOTP (RFC 6238)** implements time-based one-time passwords:
- HMAC-SHA256 (exceeds RFC 4226 minimum of SHA1)
- Base32 secret encoding per RFC 4648
- 6-digit default output (configurable)
- 30-second default time step
- Validity window: ±1 step by default (configurable)

**Session Management** generates 128-bit session IDs (64 hex chars). Cookie headers include HttpOnly, Secure, and SameSite attributes.

**Session Fixation Prevention** implements the standard rotation pattern:
1. Before login, record the current session ID
2. After successful authentication, generate a new session ID
3. The old (attacker-controlled) session ID becomes invalid
4. New ID is returned in the response cookie

**Rate Limiting** uses a fixed-window counter:
- Configurable window (default: 60s) and max attempts
- Block duration after threshold exceeded (default: 300s)
- Automatic window reset and unblock after timeout

**JWT Validation** detects common vulnerabilities:
- `alg: "none"` attack: JWT without signature verification
- Weak HMAC keys: HS256 with key < 32 bytes, HS384 < 48, HS512 < 64
- Structural parsing: header.payload.signature splitting
- Algorithm extraction from base64url-decoded header

**Password Reset Tokens** provide:
- 128-bit entropy (64 hex characters) from secure random source
- Configurable expiry (default: 15 minutes)
- Single-use enforcement (used flag)
- Entropy measurement for token strength audit

## Cryptographic Implementation

### SHA-256
Full implementation following FIPS 180-4. Handles arbitrary-length input with proper padding (length encoding in big-endian). Uses 32-bit word operations with rotation and shift macros.

### HMAC-SHA256
Implements RFC 2104 with SHA-256 as the hash function. Handles keys longer than the block size (64 bytes) by hashing first. Uses ipad/opad XOR pattern.

### PBKDF2-SHA256
Implements RFC 2898 with SHA-256 PRF. Supports arbitrary output key length by concatenating blocks. Each block uses HMAC iteratively with XOR folding.

## Security Considerations

### Known Limitations

1. **Pattern-based XSS detection** may have false positives. The encoding functions are the primary defense; detection is a secondary measure.
2. **URL-based SSRF checks** use string parsing, not DNS resolution. Real SSRF requires resolving hostnames.
3. **No TLS implementation** — this library focuses on application-layer security; transport security should be handled separately.
4. **Random number generation** uses `rand()` for demonstration. Production code should use a CSPRNG (e.g., `/dev/urandom`, `getrandom()`, or hardware RNG).
5. **JWT signature verification** with RSA/EC keys is not implemented; only HMAC-based algorithms are supported.

### Production Hardening

- Replace `rand()` with platform-specific CSPRNG:
  ```c
  #ifdef _WIN32
    CryptGenRandom(...);
  #else
    getrandom(...) or read /dev/urandom;
  #endif
  ```
- Add multi-threading support with mutex-protected shared state
- Implement DNS resolution for SSRF hostname checks
- Add JSON parsing for JWT header/payload processing
- Support additional JWT algorithms (RS256, ES256)

## Testing Strategy

- **Unit tests**: Each function tested with valid/invalid inputs
- **Security tests**: Known attack payloads verified as detected
- **Fuzzing tests**: Random binary input stress testing
- **Compliance tests**: TOTP against RFC 6238 test vectors

## File Size Design

- Headers: concise declarations with documentation comments (~100 lines each)
- Sources: full implementations with error handling (~200-500 lines each)
- Examples: progressive complexity (basic → intermediate → advanced)
- Demos: standalone applications demonstrating real-world usage
