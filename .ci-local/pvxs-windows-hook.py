"""Hook for cue.py to configure pvxs-tls for Windows MSVC builds.

Runs in the pvxs-tls source directory before compilation.

1. Adds /std:c++20 (needed for designated initializers in securitylogger.h)
2. Sets OPENSSL include/lib paths via CONFIG_SITE so probe-openssl.c can find headers
3. Patches certstatus.h PERMANENTLY_VALID_STATUS bug (missing #define in #else branch)
   - __INT_MAX__ and __TIME_T_MAX__ are GCC builtins not defined by MSVC
"""

import os

CONFIG_SITE = os.path.join("configure", "CONFIG_SITE")

if os.path.isfile(CONFIG_SITE):
    print("pvxs-windows-hook: Configuring pvxs-tls for Windows MSVC in", os.getcwd())

    lines = []

    # Add /std:c++20 for MSVC (designated initializers require it)
    lines.append("USR_CXXFLAGS_WIN32 += /std:c++20")

    # Point to LIBEVENT if env var is set
    libevent = os.environ.get("LIBEVENT", "")
    if libevent:
        lines.append("LIBEVENT = " + libevent)
        print("pvxs-windows-hook: Set LIBEVENT=" + libevent)

    # Point to OpenSSL if OPENSSL env var is set
    openssl = os.environ.get("OPENSSL", "")
    if openssl:
        lines.append("OPENSSL = " + openssl)
        print("pvxs-windows-hook: Set OPENSSL=" + openssl)

    with open(CONFIG_SITE, "a") as f:
        f.write("\n# Added by pvxs-windows-hook.py\n")
        for line in lines:
            f.write(line + "\n")
            print("pvxs-windows-hook: >>", line)
else:
    print("Warning:", CONFIG_SITE, "not found in", os.getcwd())

# Patch certstatus.h for MSVC compatibility
certstatus_h = os.path.join("src", "certstatus.h")
if os.path.isfile(certstatus_h):
    with open(certstatus_h, "r") as f:
        content = f.read()
    patched = False

    # Patch 1: Fix PERMANENTLY_VALID_STATUS macro (missing #define in #else branch)
    # __INT_MAX__ and __TIME_T_MAX__ are GCC builtins not defined by MSVC
    old = "#else\nPERMANENTLY_VALID_STATUS(time_t)\n((~(unsigned long long)0) >> 1)"
    new = "#else\n#define PERMANENTLY_VALID_STATUS (time_t)((~(unsigned long long)0) >> 1)"
    if old in content:
        content = content.replace(old, new)
        patched = True
        print("pvxs-windows-hook: Patched PERMANENTLY_VALID_STATUS in certstatus.h")

    # Patch 2: Replace compound literal macros with inline functions
    # MSVC does not support C99 compound literals ((const char*[]){...}) in C++
    old_cert = '#define CERT_STATE(index) ((const char*[])CERT_STATES[(index)])'
    old_ocsp = '#define OCSP_CERT_STATE(index) ((const char*[])OCSP_CERT_STATES[(index)])'
    if old_cert in content:
        replacement = (
            '// MSVC-compatible replacements for compound literal macros\n'
            'inline const char* cert_state_name(int index) {\n'
            '    static const char* const states[] = CERT_STATES;\n'
            '    return states[index];\n'
            '}\n'
            'inline const char* ocsp_cert_state_name(int index) {\n'
            '    static const char* const states[] = OCSP_CERT_STATES;\n'
            '    return states[index];\n'
            '}\n'
            '#define CERT_STATE(index) cert_state_name(index)\n'
            '#define OCSP_CERT_STATE(index) ocsp_cert_state_name(index)'
        )
        content = content.replace(old_cert, replacement)
        content = content.replace(old_ocsp, '')  # Remove the old OCSP macro (now in the inline block)
        patched = True
        print("pvxs-windows-hook: Patched CERT_STATE/OCSP_CERT_STATE compound literals")

    if patched:
        with open(certstatus_h, "w") as f:
            f.write(content)
    else:
        print("pvxs-windows-hook: No patches needed for certstatus.h")
else:
    print("pvxs-windows-hook: certstatus.h not found (may not be needed)")
