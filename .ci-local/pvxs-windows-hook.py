"""Hook for cue.py to configure pvxs-tls for Windows MSVC builds.

Runs in the pvxs-tls source directory before compilation.

1. Adds /std:c++20 (needed for designated initializers in securitylogger.h)
2. Sets OPENSSL include/lib paths via CONFIG_SITE so probe-openssl.c can find headers
"""

import os

CONFIG_SITE = os.path.join("configure", "CONFIG_SITE")

if os.path.isfile(CONFIG_SITE):
    print("pvxs-windows-hook: Configuring pvxs-tls for Windows MSVC in", os.getcwd())

    lines = []

    # Add /std:c++20 for MSVC (designated initializers require it)
    lines.append("USR_CXXFLAGS_WIN32 += /std:c++20")

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
