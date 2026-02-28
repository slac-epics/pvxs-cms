#!/usr/bin/env python
"""Build bundled libevent inside a pvxs source tree.

Usage:
  python pvxs-libevent-hook.py [<pvxs-source-dir>]

If <pvxs-source-dir> is given, operates in that directory.
Otherwise, operates in the current working directory (for use as a cue.py hook).

Builds libevent for the host architecture, and for each cross-compilation
target listed in CI_CROSS_TARGETS.
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

# Determine working directory
if len(sys.argv) > 1:
    workdir = sys.argv[1]
else:
    workdir = os.getcwd()

print('=== pvxs-libevent-hook: building bundled libevent in', workdir)

# Build host libevent (needed for native compilation of pvxs)
check_call('make -C bundle libevent VERBOSE=1', shell=True, env=env, cwd=workdir)

# Build libevent for each cross-compilation target
for arch in os.environ.get('CI_CROSS_TARGETS', '').split(':'):
    if not arch:
        continue

    arch, _sep, arch_ver = arch.partition('@')

    print('=== pvxs-libevent-hook: building libevent for cross target', arch, arch_ver)

    check_call('make -C bundle libevent.' + arch + ' VERBOSE=1', shell=True, env=env, cwd=workdir)
