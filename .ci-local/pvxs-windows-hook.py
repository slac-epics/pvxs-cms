"""Hook for cue.py to configure pvxs-tls for Windows MSVC builds.

Runs in the pvxs-tls source directory before compilation.

1. Adds /std:c++20 (needed for designated initializers in securitylogger.h)
2. Sets OPENSSL include/lib paths via CONFIG_SITE so probe-openssl.c can find headers
3. Patches certstatus.h PERMANENTLY_VALID_STATUS bug (missing #define in #else branch)
   - __INT_MAX__ and __TIME_T_MAX__ are GCC builtins not defined by MSVC
"""

import os
import shutil

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
        # MSVC linker needs /LIBPATH: (not -L) to find ssl.lib/crypto.lib
        # These come via LIBEVENT_SYS_LIBS so EPICS doesn't resolve _DIR for them
        lib_dir = openssl.replace("\\", "/") + "/lib"
        lines.append("USR_LDFLAGS_WIN32 += /LIBPATH:" + lib_dir)
        print("pvxs-windows-hook: Set OPENSSL=" + openssl)

    with open(CONFIG_SITE, "a") as f:
        f.write("\n# Added by pvxs-windows-hook.py\n")
        for line in lines:
            f.write(line + "\n")
            print("pvxs-windows-hook: >>", line)

    # Create ssl.lib/crypto.lib aliases for vcpkg's libssl.lib/libcrypto.lib
    # EPICS build system appends .lib to SYS_LIBS names, so 'ssl' -> 'ssl.lib'
    # but vcpkg OpenSSL 3.x on Windows provides 'libssl.lib' and 'libcrypto.lib'
    openssl_lib = os.environ.get("OPENSSL", "")
    if openssl_lib:
        lib_dir = os.path.join(openssl_lib, "lib")
        for name in [("libssl", "ssl"), ("libcrypto", "crypto")]:
            src = os.path.join(lib_dir, name[0] + ".lib")
            dst = os.path.join(lib_dir, name[1] + ".lib")
            if os.path.isfile(src) and not os.path.isfile(dst):
                shutil.copy2(src, dst)
                print("pvxs-windows-hook: Copied", src, "->", dst)
            elif os.path.isfile(dst):
                print("pvxs-windows-hook:", dst, "already exists")
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

# Patch sharedArray.h: add missing #include <stdexcept>
# MSVC needs explicit include for std::out_of_range and std::logic_error
shared_array_h = os.path.join("src", "pvxs", "sharedArray.h")
if os.path.isfile(shared_array_h):
    with open(shared_array_h, "r") as f:
        sa_content = f.read()
    if '#include <stdexcept>' not in sa_content:
        # Insert #include <stdexcept> after #include <algorithm> or first #include
        import re
        sa_content = re.sub(
            r'(#include <algorithm>)',
            r'\1\n#include <stdexcept>',
            sa_content,
            count=1
        )
        if '#include <stdexcept>' in sa_content:
            with open(shared_array_h, "w") as f:
                f.write(sa_content)
            print("pvxs-windows-hook: Added #include <stdexcept> to sharedArray.h")
        else:
            print("pvxs-windows-hook: WARNING: Could not find insertion point in sharedArray.h")
    else:
        print("pvxs-windows-hook: sharedArray.h already has <stdexcept>")
else:
    print("pvxs-windows-hook: sharedArray.h not found")

# Patch securitylogger.h: replace compound literal (ASIDENTITY){...} for MSVC
# MSVC doesn't support C99 compound literals in C++ mode
security_logger_h = os.path.join("ioc", "securitylogger.h")
if os.path.isfile(security_logger_h):
    with open(security_logger_h, "r") as f:
        sl_content = f.read()
    # Replace the compound literal with a helper lambda that creates the struct
    old_pattern = """        ,pvt(asTrapWriteBeforeWithIdentityData(
            (ASIDENTITY){
                .user = credentials.cred[0].c_str(),
                .host = (char *)credentials.host.c_str(),
                .method =  credentials.method.c_str(),
                .authority = credentials.authority.c_str(),
                .protocol = AS_PROTOCOL_TLS },"""
    new_code = """        ,pvt([&]() {
            ASIDENTITY id = {};
            id.user = credentials.cred[0].c_str();
            id.host = (char *)credentials.host.c_str();
            id.method = credentials.method.c_str();
            id.authority = credentials.authority.c_str();
            id.protocol = AS_PROTOCOL_TLS;
            return asTrapWriteBeforeWithIdentityData(
                id,"""
    if old_pattern in sl_content:
        sl_content = sl_content.replace(old_pattern, new_code)
        # Also need to close the lambda: replace the closing )) with }()))
        # The original ends with: nullptr\n        ))
        old_end = """            nullptr
        ))"""
        new_end = """            nullptr
        ); }())"""
        sl_content = sl_content.replace(old_end, new_end)
        with open(security_logger_h, "w") as f:
            f.write(sl_content)
        print("pvxs-windows-hook: Patched securitylogger.h compound literal")
    else:
        print("pvxs-windows-hook: securitylogger.h pattern not found (may already be patched)")
else:
    print("pvxs-windows-hook: securitylogger.h not found")
