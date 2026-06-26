# Binary Security Mitigations

> Reference documentation for `mini-binary-security`

---

## Mitigation Overview

| Mitigation | Compiler/Linker Flag | Protects Against |
|------------|---------------------|------------------|
| Stack Canary | `-fstack-protector-strong` | Stack buffer overflow |
| NX (DEP) | Default (`-z noexecstack`) | Shellcode injection |
| ASLR | Kernel setting | ROP, ret2libc |
| PIE | `-fPIE -pie` | Code reuse attacks |
| RELRO (Partial) | `-Wl,-z,relro` | GOT overwrite (partial) |
| Full RELRO | `-Wl,-z,relro,-z,now` | GOT overwrite (complete) |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=2` | Buffer overflows in libc |
| CFI | `-fsanitize=cfi` (Clang) | Control flow hijack |
| CET IBT | HW + compiler support | JOP, ROP (indirect branches) |
| CET SS | HW + compiler support | Return address tampering |
| SafeStack | `-fsanitize=safe-stack` | Stack buffer overflow |
| Shadow Stack | Software/hardware | Return address overwrite |

---

## 1. ASLR (Address Space Layout Randomization)

### What It Does
Randomizes the base address of key memory regions on each execution:
- **Stack**: ~30 bits of entropy on x86_64
- **Heap**: ~13 bits of entropy
- **libc/mmapped**: ~28 bits of entropy
- **PIE executable**: Random base per execution

### Check
```bash
cat /proc/sys/kernel/randomize_va_space
# 0 = disabled, 1 = partial, 2 = full
```

### Bypass Methods
1. **Information leak**: Leak a pointer to calculate base (format string, side channel)
2. **Partial overwrite**: Overwrite only last 1-2 bytes of a pointer
3. **Brute force**: Sufficient for 32-bit or low entropy
4. **Heap spray**: Fill memory with predictable patterns

### Implementation Note
- Linux: `personality(ADDR_NO_RANDOMIZE)` disables per-process
- Windows: `/DYNAMICBASE` linker flag
- iOS/Android: Always enabled

---

## 2. NX (No-eXecute) / DEP (Data Execution Prevention)

### What It Does
Marks memory pages as non-executable:
- Stack: Read/Write, NOT execute
- Heap: Read/Write, NOT execute
- `.data`/`.bss`: Read/Write, NOT execute

### Check
```bash
readelf -l binary | grep GNU_STACK
# E flag = executable stack (dangerous)
# No E flag = non-executable (safe)
```

### Bypass Methods
1. **ROP**: Reuse code in `.text` (which IS executable)
2. **mprotect()**: Use ROP to call mprotect() to make a region executable
3. **ret2libc**: Call libc functions directly (they're in executable memory)

### Implementation Note
- x86: NX bit (bit 63 of page table entry)
- ARM: XN bit
- PaX: Original Linux implementation (2000)

---

## 3. Stack Canary

### What It Does
Places a random value (canary) between the local variables and saved return address. Before function returns, checks if canary is intact. If modified, calls `__stack_chk_fail()` which aborts the process.

```
[local variables]
[canary:  0xXXXXXXXXXXXXXX00]  <-- null-terminated
[saved RBP]
[return address]
```

### Canary Types
1. **Terminator canary**: Ends with `\x00` (prevents string-based leaks)
2. **Random canary**: Generated from `/dev/urandom`
3. **Random XOR canary**: XOR'd with saved RBP

### Bypass Methods
1. **Leak the canary**: Format string, arbitrary read -> then overwrite with correct value
2. **Brute force**: Fork-based servers; 256 attempts on 32-bit for LSB
3. **Overwrite specific pointer**: Skip canary if pointer between canary and return address
4. **Thread-local canary**: Different threads have different canaries (harder)

### GCC Options
```
-fstack-protector         # protect functions with char buffers > 8 bytes
-fstack-protector-strong  # protect more categories
-fstack-protector-all     # protect ALL functions
-fno-stack-protector      # disable (dangerous)
```

---

## 4. RELRO (Relocation Read-Only)

### Partial RELRO
- `.got.plt` is made read-only after dynamic linker initialization
- `.got` (non-PLT) remains writable
- Lazy binding enabled
- Default with `-Wl,-z,relro`

### Full RELRO
- `.got` AND `.got.plt` both read-only
- Lazy binding disabled (`BIND_NOW`)
- Added with `-Wl,-z,relro,-z,now`

### Effectiveness
| RELRO Level | GOT.plt | GOT (non-PLT) | GOT overwrite |
|-------------|---------|---------------|---------------|
| None | Writable | Writable | Easy |
| Partial | Read-only | Writable | Possible (non-PLT) |
| Full | Read-only | Read-only | Impossible |

### Bypass (Full RELRO)
- Target `__malloc_hook`, `__free_hook`, `__realloc_hook`
- Overwrite `.fini_array` entries
- Vtable hijacking (C++ objects)

---

## 5. PIE (Position Independent Executable)

### What It Does
Compiles the main executable as position-independent code, allowing ASLR to randomize its base address (same as shared libraries).

### Check
```bash
readelf -h binary | grep Type
# EXEC = no PIE (fixed at 0x400000)
# DYN  = PIE enabled
```

### Impact on Exploitation
- Without PIE: ROP gadgets at known addresses -> easy exploitation
- With PIE: Must leak PIE base first

### Compiler/Linker Flags
```
-fPIE          # Compile objects as position independent
-pie           # Link as position independent executable
```

---

## 6. FORTIFY_SOURCE

### What It Does
Replaces unsafe libc functions with bounds-checking versions:
- `sprintf()`, `strcpy()`, `memcpy()`, `gets()`, etc.

### Levels
```
-D_FORTIFY_SOURCE=1  # Lightweight checks (compile-time)
-D_FORTIFY_SOURCE=2  # Additional runtime checks
```

### Limitations
- Only works when buffer size is known at compile time
- Does NOT protect `printf()` format strings
- Cannot catch all overflow cases

---

## 7. CFI (Control Flow Integrity)

### Concept
Ensures that every indirect control flow transfer (function pointers, virtual calls, returns) targets a valid destination.

### Implementations
| Implementation | Forward Edge | Backward Edge | Platform |
|----------------|-------------|---------------|----------|
| Clang CFI | Yes | No | Cross-platform |
| Intel CET IBT | Yes | No | Intel CPUs (11th gen+) |
| Intel CET SS | No | Yes | Intel CPUs (11th gen+) |
| ARM PAuth | Yes | Yes | ARM v8.3-A+ |
| Shadow Stack (SW) | No | Yes | Software-based |

### CET (Intel Control-flow Enforcement Technology)

#### IBT (Indirect Branch Tracking)
- All indirect `jmp`/`call` must target `ENDBR64` instruction
- Prevents JOP attacks
- Hardware-enforced

#### Shadow Stack
- Hardware-maintained copy of return addresses
- On `ret`: compares shadow stack return address with stack return address
- Mismatch -> #CP exception
- Prevents ROP entirely

---

## 8. Additional Hardening Techniques

### SafeStack (Clang)
- Splits stack into "safe" (return address, registers) and "unsafe" (local buffers)
- Unsafe stack is separate from safe stack
- Overflow in buffer cannot reach return address

### Stack Clash Protection
- Prevents stack from growing into heap or other memory regions
- Guard pages between stack and other mappings
- `-fstack-clash-protection` (GCC)

### Heap Hardening
- **glibc 2.29+**: Tcache key field (detects double-free)
- **glibc 2.32+**: Safe-linking (XOR'd pointer protection in fastbins/tcache)
- **jemalloc**: Separate metadata from user data

### ARM-specific
| Mitigation | Protection |
|------------|------------|
| PAuth (PAC) | Pointer Authentication Code for return addresses |
| BTI | Branch Target Identification (similar to CET IBT) |
| MTE | Memory Tagging Extension (detects spatial/temporal errors) |

---

## 9. Checking Mitigations (Tools)

### checksec / pwntools
```python
from pwn import *
elf = ELF('./binary')
print(elf.checksec())
```

### Hardening-check (Debian)
```bash
hardening-check ./binary
```

### Manual Checks
```bash
# Stack canary
readelf -s binary | grep __stack_chk_fail

# NX
readelf -l binary | grep GNU_STACK

# PIE
readelf -h binary | grep Type

# RELRO
readelf -l binary | grep GNU_RELRO

# FORTIFY
readelf -s binary | grep _chk
```

---

## 10. Defense-in-Depth Strategy

```
Layer 1: Compiler → FORTIFY, Stack Protector, SafeStack
Layer 2: Linker   → PIE, Full RELRO, NX
Layer 3: Kernel   → ASLR, seccomp, namespaces
Layer 4: Hardware → CET, PAuth, MTE, SMEP/SMAP
```

### Recommended Flags (Maximum Hardening)
```makefile
CFLAGS   += -fstack-protector-strong
CFLAGS   += -fPIE -fPIC
CFLAGS   += -D_FORTIFY_SOURCE=2
CFLAGS   += -fstack-clash-protection
CFLAGS   += -fcf-protection=full        # CET (GCC 8+)
LDFLAGS  += -Wl,-z,relro,-z,now
LDFLAGS  += -pie
LDFLAGS  += -Wl,-z,noexecstack
```
