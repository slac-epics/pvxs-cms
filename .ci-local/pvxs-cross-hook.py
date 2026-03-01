#!/usr/bin/env python
"""Build libevent for cross-compilation before building pvxs-tls.

This hook is called by cue.py before building pvxs-tls for cross targets.
It builds libevent using CMake directly (not via EPICS makefiles) because
during cue.py prepare phase, T_A is not set and EPICS CONFIG cannot be used.
"""

from __future__ import print_function

import os
import sys
import subprocess as SP

def logcall(fn):
    def logit(*args, **kws):
        print('CALL', fn, args, kws)
        sys.stdout.flush()
        sys.stderr.flush()
        ret = fn(*args, **kws)
        sys.stdout.flush()
        sys.stderr.flush()
        return ret
    return logit

check_call = logcall(SP.check_call)

env = os.environ.copy()
PATH = env['PATH'].split(os.pathsep)

# CMake MinGW generator doesn't like sh.exe in PATH
PATH = [ent for ent in PATH if not os.path.isfile(os.path.join(ent, 'sh.exe'))]
env['PATH'] = os.pathsep.join(PATH)

# Determine working directory (pvxs-tls source directory)
if len(sys.argv) > 1:
    workdir = sys.argv[1]
else:
    workdir = os.getcwd()

print('=== pvxs-cross-hook: building libevent for cross targets in', workdir)

# Parse CI_CROSS_TARGETS (format: "windows-x64-mingw:RTEMS-pc686-qemu@5")
cross_targets = env.get('CI_CROSS_TARGETS', '').split(':')
cross_targets = [t for t in cross_targets if t]  # filter empty

if not cross_targets:
    print('=== No cross targets specified, nothing to build')
    sys.exit(0)

# Map EPICS arch to CMake toolchain file
toolchain_map = {
    'windows-x64-mingw': 'x86_64-w64-mingw32.cmake',
    'RTEMS-pc686-qemu': 'RTEMS-pc686-qemu@5.cmake',  # with version
}

bundle_dir = os.path.join(workdir, 'bundle')
libevent_src = os.path.join(workdir, 'libevent')

if not os.path.isdir(libevent_src):
    print('ERROR: libevent submodule not found at', libevent_src)
    sys.exit(1)

# Build libevent for each cross-compilation target
for target_spec in cross_targets:
    # Parse "RTEMS-pc686-qemu@5" -> arch="RTEMS-pc686-qemu", ver="5"
    arch, _sep, arch_ver = target_spec.partition('@')
    
    # Skip RTEMS - it requires template expansion from EPICS build system
    if arch.startswith('RTEMS'):
        print('=== Skipping RTEMS target (requires EPICS build system):', arch)
        continue
    
    print('=== Building libevent for cross target:', arch, 'version:', arch_ver or 'none')
    
    # Determine install prefix (matches EPICS convention)
    install_prefix = os.path.join(workdir, 'bundle', 'usr', arch)
    
    # Create build directory
    build_dir = os.path.join(bundle_dir, 'O.' + arch)
    if not os.path.exists(build_dir):
        os.makedirs(build_dir)
    
    # Determine toolchain file
    toolchain_file = None
    if arch in toolchain_map:
        toolchain_file = os.path.join(bundle_dir, 'cmake', toolchain_map[arch])
    elif arch_ver:  # Try with version suffix
        full_spec = arch + '@' + arch_ver
        if full_spec in toolchain_map:
            toolchain_file = os.path.join(bundle_dir, 'cmake', toolchain_map[full_spec])
        else:
            # Try generic pattern: RTEMS-pc686-qemu@5 -> RTEMS-pc686-qemu@5.cmake
            toolchain_candidate = os.path.join(bundle_dir, 'cmake', full_spec + '.cmake')
            if os.path.isfile(toolchain_candidate):
                toolchain_file = toolchain_candidate
    
    # Build CMake flags
    cmake_flags = [
        '-DCMAKE_INSTALL_PREFIX=' + install_prefix,
        '-DEVENT__DISABLE_MBEDTLS=ON',
        '-DEVENT__DISABLE_REGRESS=ON',
        '-DEVENT__DISABLE_SAMPLES=ON',
        '-DEVENT__DISABLE_TESTS=ON',
        '-DEVENT__DISABLE_BENCHMARK=ON',
        '-DCMAKE_BUILD_TYPE=RELEASE',
        '-DEVENT__LIBRARY_TYPE=STATIC',  # Cross builds typically use static
    ]
    
    if toolchain_file and os.path.isfile(toolchain_file):
        cmake_flags.append('-DCMAKE_TOOLCHAIN_FILE=' + toolchain_file)
        print('    Using toolchain file:', toolchain_file)
    else:
        print('    WARNING: No toolchain file found for', arch, '- using native build')
    
    # Configure
    print('    Configuring libevent...')
    check_call(['cmake'] + cmake_flags + [libevent_src], cwd=build_dir, env=env)
    
    # Build and install
    print('    Building and installing libevent...')
    check_call(['cmake', '--build', '.', '--target', 'install'], cwd=build_dir, env=env)
    
    print('    libevent installed to:', install_prefix)

print('=== pvxs-cross-hook: all cross-target libevent builds complete')