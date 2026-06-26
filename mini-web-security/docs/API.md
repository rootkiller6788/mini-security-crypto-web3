# mini-web-security API Reference

## xss_csrf.h — XSS & CSRF Protection

### XSS Detection

| Function | Description |
|----------|-------------|
| `xss_detect_reflected(input, context, report)` | Detect reflected XSS in query/source input |
| `xss_detect_stored(db_content, report)` | Detect stored XSS in database content |
| `xss_detect_dom(js_sink, source, report)` | Detect DOM-based XSS in JavaScript sinks |

### XSS Sanitization (Encoding)

| Function | Returns | Description |
|----------|---------|-------------|
| `html_encode(input, output, out_size)` | `size_t` | Encode HTML entities (`<` → `&lt;`) |
| `html_attribute_encode(input, output, out_size)` | `size_t` | Encode for HTML attributes |
| `js_string_encode(input, output, out_size)` | `size_t` | Encode for JavaScript strings |
| `html_decode(input, output, out_size)` | `bool` | Decode HTML entities |
| `xss_sanitize_html(input, output, out_size)` | `int` | Full HTML sanitization |
| `xss_sanitize_attribute(input, output, out_size)` | `int` | Attribute context sanitization |
| `xss_sanitize_javascript(input, output, out_size)` | `int` | JavaScript context sanitization |
| `xss_sanitize_url(input, output, out_size)` | `int` | URL sanitization |

### CSP (Content Security Policy)

| Function | Description |
|----------|-------------|
| `csp_init(policy, report_only)` | Initialize CSP policy |
| `csp_add_directive(policy, src, value)` | Add directive (e.g., `script-src 'self'`) |
| `csp_generate_header(policy, output, out_size)` | Generate `Content-Security-Policy` header |
| `csp_generate_nonce(output, out_size)` | Generate random base64 nonce |
| `csp_generate_hash(content, output, out_size)` | Generate SHA-256+base64 hash for script/style |

### CSRF Protection

| Function | Description |
|----------|-------------|
| `csrf_token_generate(token)` | Generate random 32-byte CSRF token |
| `csrf_token_validate(token, expected)` | Constant-time token comparison |
| `csrf_token_to_hex(token, output, out_size)` | Convert token to hex string |
| `csrf_token_from_hex(hex, token)` | Parse hex string to token |
| `csrf_set_cookie_header(...)` | Generate `Set-Cookie` header with SameSite |
| `csrf_check_origin(origin, target_host)` | Validate Origin header |
| `csrf_check_referer(referer, target_host)` | Validate Referer header |
| `csrf_same_origin(url_a, url_b)` | Check same-origin for two URLs |

---

## sqli_inject.h — SQL/NoSQL Injection Protection

### Detection

| Function | Description |
|----------|-------------|
| `sqli_detect(input, result)` | Main detection: returns best match |
| `sqli_scan_simple(input, results[], max)` | Scan all patterns, return all matches |
| `sqli_detect_classic(input, offset)` | Check for `' OR 1=1--` pattern |
| `sqli_detect_union(input, offset)` | Check for `UNION SELECT` |
| `sqli_detect_boolean_blind(input, offset)` | Check for `AND 1=1` / `AND 1=2` |
| `sqli_detect_time_blind(input, offset)` | Check for `SLEEP()` / `WAITFOR DELAY` |

### Prepared Statements

```c
sqli_prepared_t stmt;
sqli_prepared_init(&stmt, "SELECT * FROM users WHERE id = ?");
sqli_prepared_bind_int(&stmt, 42);
sqli_prepared_bind_text(&stmt, "alice");
sqli_prepared_build(&stmt);
// stmt.sanitized_query: "SELECT * FROM users WHERE id = 42 AND name = 'alice'"
```

| Function | Description |
|----------|-------------|
| `sqli_prepared_init(stmt, template)` | Initialize with `?` placeholder query |
| `sqli_prepared_bind_int(stmt, value)` | Bind `int64_t` parameter |
| `sqli_prepared_bind_float(stmt, value)` | Bind `double` parameter |
| `sqli_prepared_bind_text(stmt, value)` | Bind string parameter (auto-escaped) |
| `sqli_prepared_bind_null(stmt)` | Bind NULL |
| `sqli_prepared_build(stmt)` | Compile final query |

### Sanitization

| Function | Description |
|----------|-------------|
| `sqli_sanitize(input, output, out_size)` | Full SQL sanitization |
| `sqli_escape_string(input, output, out_size)` | Escape `' " \ \0 \n \r` |
| `sqli_is_safe_identifier(identifier)` | Validate SQL identifier `[a-zA-Z_][a-zA-Z0-9_]*` |
| `sqli_is_safe_integer(input)` | Validate integer-only string |
| `sqli_whitelist_columns(col, allowed[], n)` | Column name whitelist check |

### NoSQL Injection

| Function | Returns | Description |
|----------|---------|-------------|
| `nosqli_detect(input)` | `nosqli_type_t` | Detect `$gt`, `$ne`, `$where`, etc. |
| `nosqli_sanitize(input, output, out_size)` | `int` | Escape `$`, `{`, `}` characters |
| `nosqli_is_operator_injection(input)` | `bool` | Quick check for operator injection |

### ORM Protection

| Function | Description |
|----------|-------------|
| `orm_validate_model(field, allowed[], count)` | Check field name against allowed list |
| `orm_validate_type(value, expected_type)` | Type-check value (`int`, `float`, `alphanum`) |

### Second-Order SQLi

| Function | Description |
|----------|-------------|
| `second_order_track(tracker, value)` | Record stored value and flag if suspicious |
| `second_order_check(tracker, context)` | Check stored value before usage |

---

## owasp_top10.h — OWASP Top 10 Detection

### Core

| Function | Description |
|----------|-------------|
| `owasp_category_name(category)` | Get category name string |
| `owasp_category_desc(category)` | Get category description |
| `owasp_report_add(report, cat, risk, detail, fix)` | Add finding to report |
| `owasp_scan_headers(headers[], count, report)` | Scan HTTP headers for security gaps |
| `owasp_scan_url(url, report)` | Scan URL for exposed data/paths |
| `owasp_scan_response(response, report)` | Scan response body for error leakage |

### A01 — Broken Access Control

| Function | Description |
|----------|-------------|
| `idor_check(resource_id, user_id, owner_id)` | Check if user owns resource |
| `idor_validate_ownership(requested_id, owned[], n)` | Validate against owned IDs |
| `access_control_validate(role, resource, action, allowed_roles[])` | Role-based access check |

### A02 — Cryptographic Failures

| Function | Description |
|----------|-------------|
| `crypto_is_weak(algo)` | Check for weak algorithms (MD5, SHA1, DES, RC4) |
| `crypto_check_key_length(algo, key_len)` | Validate minimum key length |
| `crypto_is_hardcoded_secret(secret)` | Detect common/default passwords |

### A10 — SSRF

| Function | Description |
|----------|-------------|
| `ssrf_analyze_url(url, result)` | Full URL analysis: host, port, path, risk |
| `ssrf_is_internal_ip(host)` | Check loopback + private ranges |
| `ssrf_is_loopback(host)` | Check 127.0.0.1, localhost, ::1 |
| `ssrf_is_private_range(host)` | Check 10.x, 172.16-31.x, 192.168.x, 169.254.x |

### File Inclusion (LFI/RFI)

| Function | Description |
|----------|-------------|
| `fi_detect(path_input, result)` | Detect LFI (`../`, `/etc/passwd`) and RFI (`http://`) |
| `fi_is_lfi_payload(path)` | Quick LFI check |
| `fi_is_rfi_payload(path)` | Quick RFI check |
| `fi_sanitize_path(input, output, out_size)` | Remove dangerous path characters |

### Directory Traversal

| Function | Description |
|----------|-------------|
| `dt_detect(path, result)` | Detect `../`, null byte, double encoding |
| `dt_sanitize(input, output, out_size)` | Resolve `..` segments |
| `dt_is_traversal(path)` | Quick check |
| `dt_canonicalize(path, output, out_size)` | Full path canonicalization |

### Security Misconfiguration

| Function | Description |
|----------|-------------|
| `secmis_detect_debug_endpoint(path)` | Check for /debug, /phpinfo, /actuator, etc. |
| `secmis_detect_directory_listing(response)` | Check for "Index of /" patterns |
| `secmis_detect_default_credentials(user, pass)` | Check common default credentials |
| `secmis_header_check(name, value)` | Validate security header values |

### Logging & Monitoring

| Function | Description |
|----------|-------------|
| `log_event_format(event, output, out_size)` | Format structured log event |
| `log_monitor_anomaly(event_count, window, threshold)` | Simple anomaly detection |

---

## input_validation.h — Input Validation

### Allowlist / Blocklist

| Function | Description |
|----------|-------------|
| `ival_list_init(list, items, count, case_sensitive)` | Initialize filter list |
| `ival_allowlist(input, allowed)` | Check input against allowlist |
| `ival_blocklist(input, blocked)` | Check input against blocklist |
| `ival_match_regex(input, pattern)` | Simple regex matching |

### Type Checking

| Function | Description |
|----------|-------------|
| `ival_check_type(input, type)` | Generic type check by enum |
| `ival_is_integer(input)` | Check for integer |
| `ival_is_float(input)` | Check for float |
| `ival_is_alpha(input)` | Check `[a-zA-Z]+` |
| `ival_is_alphanum(input)` | Check `[a-zA-Z0-9]+` |
| `ival_is_printable(input)` | Check printable ASCII |
| `ival_is_base64(input)` | Validate base64 charset |

### Length & Range

| Function | Description |
|----------|-------------|
| `ival_check_length(input, limits)` | Min/max string length |
| `ival_check_range(value, min, max)` | Integer range check |

### Format Validators

| Function | Description |
|----------|-------------|
| `ival_validate_email(email)` | RFC-like email validation |
| `ival_validate_url(url)` | URL scheme + host validation |
| `ival_validate_credit_card(number)` | Luhn algorithm validation |
| `ival_validate_phone(phone)` | Phone number character validation |
| `ival_validate_date(date)` | ISO date YYYY-MM-DD validation |
| `ival_validate_ipv4(ip)` | IPv4 dotted-decimal validation |
| `ival_validate_ipv6(ip)` | IPv6 hex + colon validation |
| `ival_validate_password(pw, min, upper, digit, special)` | Password policy check |

### UTF-8

| Function | Description |
|----------|-------------|
| `utf8_validate(input, len)` | Full UTF-8 validation with overlong check |
| `utf8_codepoint_count(input)` | Count Unicode codepoints |
| `utf8_is_valid_multibyte(lead, cont, len)` | Validate multibyte sequence |
| `utf8_is_overlong(bytes, len)` | Detect overlong encoding |

### Canonicalization

| Function | Description |
|----------|-------------|
| `ival_canonicalize(input, output, out_size)` | Normalize to printable ASCII |
| `ival_canonicalize_path(path, output, out_size)` | Normalize path separators |
| `ival_canonicalize_url(url, output, out_size)` | Normalize URL |

### Double Encoding

| Function | Description |
|----------|-------------|
| `double_enc_detect(input, result)` | Detect `%252e` → `%2e` → `.` chains |
| `double_enc_is_encoded(input)` | Check for percent-encoding |
| `double_enc_decode_once(input, output, out_size)` | One-level URL decode |

### Parameter Pollution

| Function | Description |
|----------|-------------|
| `param_pollution_parse(qs, pp)` | Parse query string with duplicate params |
| `param_pollution_detect(pp)` | Count polluted (duplicated) parameters |
| `param_pollution_get_first(pp, name)` | Get first value (safe) |
| `param_pollution_get_all(pp, name, out[], max)` | Get all values |

### Mass Assignment

| Function | Description |
|----------|-------------|
| `mass_assign_init(ma, fields[], count)` | Set allowed fields |
| `mass_assign_validate(ma, field)` | Check single field |
| `mass_assign_filter(ma, in[], n, out[], max)` | Filter array of fields |

---

## auth_session.h — Authentication & Session Management

### Password Hashing

| Function | Description |
|----------|-------------|
| `auth_password_hash(password, result)` | Generate PBKDF2-SHA256 hash |
| `auth_password_verify(password, stored)` | Constant-time verification |
| `auth_password_to_base64(pw, output, out_size)` | Encode salt+hash as base64 |
| `auth_password_strength(password)` | Score password 0-100 |

### TOTP (RFC 6238)

| Function | Description |
|----------|-------------|
| `totp_init(cfg, digits, period)` | Initialize with digits (6/8) and period (30s) |
| `totp_generate_secret(output, out_size)` | Generate base32 secret |
| `totp_generate_code(cfg, timestamp)` | Generate current TOTP code |
| `totp_validate_code(cfg, timestamp, code)` | Validate single timestamp |
| `totp_validate_window(cfg, timestamp, code, window)` | Validate with ±window tolerance |
| `totp_hotp(key, key_len, counter, digits)` | Low-level HOTP (HMAC-SHA256) |

### Session Management

| Function | Description |
|----------|-------------|
| `session_generate_id(sess)` | Generate 64-char hex session ID |
| `session_is_expired(sess)` | Check expiration |
| `session_cookie_header(sess, httpOnly, secure, samesite, path, out, sz)` | Build Set-Cookie header |

### Session Fixation Prevention

| Function | Description |
|----------|-------------|
| `session_fix_prelogin(sf, session_id)` | Record pre-login session ID |
| `session_fix_postlogin(sf)` | Rotate session ID after authentication |
| `session_fix_validate(sf, session_id)` | Validate rotated session |

### Rate Limiting

| Function | Description |
|----------|-------------|
| `ratelimit_init(rl, max, window_sec, block_sec)` | Configure rate limiter |
| `ratelimit_check(rl)` | Attempt action (returns false if blocked) |
| `ratelimit_is_blocked(rl)` | Check block status |
| `ratelimit_remaining(rl)` | Remaining attempts in current window |
| `ratelimit_reset(rl)` | Reset counter |

### OAuth2

| Function | Description |
|----------|-------------|
| `oauth2_audit_implicit_flow(redirect_uri, client_id, response_type, audit)` | Audit implicit flow |
| `oauth2_validate_state(state_param)` | Validate state parameter length |
| `oauth2_validate_redirect_uri(registered, received)` | Exact match validation |

### JWT

| Function | Description |
|----------|-------------|
| `jwt_parse(token_str, token)` | Parse JWT into header/payload/signature |
| `jwt_sign(token, key, key_len, output, out_size)` | HMAC-SHA256 sign JWT |
| `jwt_validate(token, key, key_len, result)` | Validate JWT with vulnerability checks |
| `jwt_none_attack_check(token_str)` | Detect `"alg":"none"` |
| `jwt_weak_key_check(key, key_len, alg)` | Detect weak HMAC keys |

### Password Reset

| Function | Description |
|----------|-------------|
| `pwd_reset_generate(reset, user_id, expiry_sec)` | Generate 64-hex token with expiry |
| `pwd_reset_validate(reset, token)` | Validate token (not expired, not used) |
| `pwd_reset_is_expired(reset)` | Check expiry |
| `pwd_reset_entropy_bits(token)` | Calculate token entropy (hex*4 bits) |
