#!/usr/bin/env python
"""Build libevent for cross-compilation before building pvxs-tls.

This hook is called by cue.py before building pvxs-tls for cross targets.
It ensures that libevent is built for the cross-compilation target so that
pvxs-tls can find the libevent headers and libraries.
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

# Build host libevent (needed for host tools)
print('=== Building libevent for host architecture')
check_call('make -C bundle libevent VERBOSE=1', shell=True, env=env, cwd=workdir)

# Build libevent for each cross-compilation target
for arch in env.get('CI_CROSS_TARGETS', '').split(':'):
    if not arch:
        continue
    
    arch, _sep, arch_ver = arch.partition('@')
    
    print('=== Building libevent for cross target', arch, arch_ver)
    
    check_call('make -C bundle libevent.' + arch + ' VERBOSE=1', shell=True, env=env, cwd=workdir)

print('=== pvxs-cross-hook: libevent build complete')
