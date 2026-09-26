#!/usr/bin/env python3
"""Run one permutation of the pod-replacement experiment and classify the result.

A monitor is started in the client pod, the server is killed in the chosen way, and the
monitor's own output is read back. The outcome is one of:

  decode+noreconnect   the reported failure: a decode error, then silence
  decode+reconnect     a decode error, but updates resumed
  noreconnect          no decode error, but updates never resumed
  clean                disconnected, then resumed

Usage:
  ./experiment.py --variant spva --search udp --kill graceful --load fast-big
  ./experiment.py --matrix matrix.txt            # one permutation per line, same flags
  ./experiment.py --list                         # show every axis value
"""
import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "pvxs-teststand"

# ------------------------------------------------------------------ axes

VARIANTS = {
    # monitor binary and get binary, relative to the image's EPICS tree
    "spva":     dict(mon="/opt/epics/pvxs/bin/{arch}/pvxmonitor", get="/opt/epics/pvxs/bin/{arch}/pvxget",
                     kind="pvxs"),
    "upstream": dict(mon="/opt/epics/pvxs/bin/{arch}/pvxmonitor", get="/opt/epics/pvxs/bin/{arch}/pvxget",
                     kind="pvxs"),
    "pva":      dict(mon="/opt/epics/epics-base/bin/{arch}/pvmonitor", get="/opt/epics/epics-base/bin/{arch}/pvget",
                     kind="base"),
}

# How the client finds the server. {svc} is the ClusterIP Service, {pod} the headless one.
SEARCH = {
    "udp":         "EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST={svc}",
    "udp-pod":     "EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST={pod}",
    "ns":          "EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST= EPICS_PVA_NAME_SERVERS={svc}",
    "ns-pod":      "EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST= EPICS_PVA_NAME_SERVERS={pod}",
    "broadcast":   "EPICS_PVA_AUTO_ADDR_LIST=YES EPICS_PVA_ADDR_LIST=",
    # through pvagw, which holds its own upstream connection to the server
    "gw":          "EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST={gw}",
}

# How the server dies.
KILL = {
    "graceful": "delete the pod; SIGTERM, then SIGKILL after terminationGracePeriodSeconds",
    "abrupt":   "delete the pod with --grace-period=0 --force; SIGKILL at once",
    "ioc":      "kill -9 the IOC process only; supervisord restarts it in the same pod",
    "netcut":   "deny all ingress to the server for 20 s, then delete the pod, then allow again",
    "udpblock": "delete the pod, then block UDP to the new one: a stale UDP conntrack entry, as kube-proxy leaves",
    "impostor": "delete the pod and point the Service at a non-PVA listener for 40 s: the old pod IP reused",
    # SLAC's hand sequence. startMode=manual, so PID 1 is sleep and ignores SIGTERM: the IOC keeps
    # serving for the whole grace period on a pod already out of the endpoints, then dies by SIGKILL.
    # The new pod listens on nothing until the IOC is started by hand, --gap seconds later.
    "manual-delete": "delete the pod; after the new one is Running wait --gap s, then start the IOC by hand",
    "manual-ioc":    "kill -9 the IOC in place; wait --gap s; start it again by hand in the same pod",
}
MANUAL = ("manual-delete", "manual-ioc")
GAP = 60     # seconds, set from --gap
PRERUN = 0   # seconds the monitor runs before the kill, set from --prerun

# Server-side load: how often the monitored records update, and how big the arrays are.
LOAD = {
    "slow":      dict(scanRate=".5 second", fillRate=".2 second", arrayLength=64),
    "fast":      dict(scanRate=".1 second", fillRate=".1 second", arrayLength=1024),
    "fast-big":  dict(scanRate=".1 second", fillRate=".1 second", arrayLength=200000),
}

PROBES = ["none", "supervisor", "tcp"]
GRACE = [30, 0]

DECODE_RE = re.compile(r"Decode error|segmentation violation|cache may be dirty|"
                       r"Error while processing cmd|Invalid magic|Invalid header|Invalid \(or unsupported\)|protocol", re.I)
# pvxmonitor prints the name alone, then "    value ..."; pvmonitor prints "NAME  time  value" on
# one line. Both: the name at the start of a line that is not a disconnect notice.
UPDATE_RE = re.compile(r"^SIM:\S+(?!.*(Disconnected|disconnected|Timeout))")
DISCONNECT_RE = re.compile(r"Disconnected|disconnected|Timeout", re.I)

# ------------------------------------------------------------------ helpers

def sh(cmd, check=True, capture=True, timeout=300):
    r = subprocess.run(cmd, shell=True, text=True, timeout=timeout,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None)
    if check and r.returncode != 0:
        raise RuntimeError(f"failed ({r.returncode}): {cmd}\n{r.stdout}")
    return r.stdout or ""

def k(*args, **kw):
    return sh(f"kubectl -n {NS} " + " ".join(args), **kw)

def pod_of(variant, role, not_named=None):
    sel = f"app=teststand-{role},release=teststand-{variant}"
    out = k(f"get pod -l {sel} --field-selector=status.phase=Running "
            f"-o jsonpath='{{range .items[*]}}{{.metadata.name}}{{\"\\n\"}}{{end}}'", check=False)
    names = [n.strip("'") for n in out.split() if n.strip("'") and n.strip("'") != not_named]
    # a terminating pod still reports Running; skip anything with a deletion timestamp
    live = []
    for n in names:
        if not k(f"get pod {n} -o jsonpath='{{.metadata.deletionTimestamp}}'", check=False).strip("'"):
            live.append(n)
    return live[0] if live else None

def wait_gone(pod, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not k(f"get pod {pod} -o name", check=False).strip().startswith("pod/"):
            return time.time() - t0
        time.sleep(1)
    raise RuntimeError(f"{pod} still present after {timeout}s")

def wait_pod(variant, role, timeout=180, not_named=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        name = pod_of(variant, role, not_named)
        if name:
            ready = k(f"get pod {name} -o jsonpath='{{.status.containerStatuses[0].ready}}'", check=False).strip("'")
            if ready == "true":
                return name
        time.sleep(2)
    raise RuntimeError(f"{role} pod for {variant} not ready after {timeout}s")

def exec_in(pod, script, timeout=120):
    return k(f"exec {pod} -- sh -c {shlex.quote(script)}", check=False, timeout=timeout)

def arch(pod):
    return exec_in(pod, "/opt/epics/epics-base/startup/EpicsHostArch").strip()

# ------------------------------------------------------------------ one run

def start_ioc(server_pod):
    """What the operator does by hand: exec in and start the IOC, detached from the exec session."""
    # stdin must stay open: the IOC shell exits on EOF. His tmux session holds a terminal; this
    # holds a pipe that never closes.
    exec_in(server_pod, "nohup setsid sh -c 'tail -f /dev/null | su testioc -c /usr/local/bin/start-softioc' "
                        "> /tmp/ioc.log 2>&1 < /dev/null & echo started")

def install(variant, load, probe_mode, grace, extra_sets, gateway=False, manual=False):
    sets = [f"probeMode={probe_mode}", f"terminationGracePeriodSeconds={grace}",
            f"startMode={'manual' if manual else 'supervised'}",
            f"gateway.enabled={'true' if gateway else 'false'}",
            f"scanRate={load['scanRate']}", f"fillRate={load['fillRate']}",
            f"arrayLength={load['arrayLength']}"] + list(extra_sets)
    args = " ".join(f"--set {shlex.quote(s)}" for s in sets)
    sh(f"{HERE}/install.sh {variant} {args}", timeout=600)

def start_monitor(variant, client, server_svc, env_tpl, pvs, log):
    v = VARIANTS[variant]
    a = arch(client)
    env = env_tpl.format(svc=server_svc, pod=server_svc + "-pod", gw=f"teststand-{variant}-gateway")
    mon = v["mon"].format(arch=a)
    # pvxs: show connection lifecycle at INFO; Base: default. Line-buffered, backgrounded, detached.
    extra = "PVXS_LOG=pvxs.cli.io=INFO,pvxs.tcp.io=INFO,pvxs.tcp.setup=INFO" if v["kind"] == "pvxs" else ""
    script = (f"rm -f {log}; nohup setsid env {extra} {env} stdbuf -oL {mon} {' '.join(pvs)} "
              f"> {log} 2>&1 < /dev/null & echo $!")
    pid = exec_in(client, script).strip().splitlines()[-1]
    return pid

def read_log(client, log):
    return exec_in(client, f"cat {log} 2>/dev/null")

def count_updates(text):
    return sum(1 for line in text.splitlines() if UPDATE_RE.match(line))

def fresh_get_ok(variant, client, server_svc, pv, via="udp"):
    """A brand-new client from the same pod. Proves the path works even if the monitor is stuck.
    via="ns" searches over TCP, for runs where UDP is deliberately blocked."""
    v = VARIANTS[variant]
    a = arch(client)
    env = (f"EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST= EPICS_PVA_NAME_SERVERS={server_svc}" if via == "ns"
           else f"EPICS_PVA_AUTO_ADDR_LIST=NO EPICS_PVA_ADDR_LIST={server_svc}")
    out = exec_in(client, f"{env} {v['get'].format(arch=a)} -w 5 {pv} 2>&1")
    return ("value" in out or re.search(r"^SIM:\S+\s+\d{4}-", out, re.M) is not None) and "Timeout" not in out, out.strip()

def kill_server(variant, method, server_pod):
    if method == "graceful":
        k(f"delete pod {server_pod} --wait=false")
    elif method == "abrupt":
        k(f"delete pod {server_pod} --grace-period=0 --force --wait=false")
    elif method == "ioc":
        exec_in(server_pod, "pkill -9 -f softIoc")
    elif method == "netcut":
        pol = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: netcut-{variant}, namespace: {NS}}}
spec:
  podSelector: {{matchLabels: {{app: teststand-server, release: teststand-{variant}}}}}
  policyTypes: [Ingress, Egress]
"""
        sh(f"printf %s {shlex.quote(pol)} | kubectl apply -f -")
        time.sleep(20)
        k(f"delete pod {server_pod} --wait=false")
        time.sleep(5)
        k(f"delete networkpolicy netcut-{variant} --ignore-not-found")
    elif method == "manual-delete":
        t = time.time()
        k(f"delete pod {server_pod} --wait=false")
        gone = wait_gone(server_pod)
        new_pod = wait_pod(variant, "server", timeout=240, not_named=server_pod)
        print(f"  old pod gone after {gone:.0f}s (IOC served until SIGKILL); new pod {new_pod} Running at "
              f"+{time.time()-t:.0f}s with nothing listening; operator away for {GAP}s", flush=True)
        time.sleep(GAP)
        start_ioc(new_pod)
    elif method == "manual-ioc":
        exec_in(server_pod, "pkill -9 -f softIoc")
        print(f"  IOC killed in place; operator away for {GAP}s", flush=True)
        time.sleep(GAP)
        start_ioc(server_pod)
    elif method == "udpblock":
        k(f"delete pod {server_pod} --wait=false")
        pol = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: udpblock-{variant}, namespace: {NS}}}
spec:
  podSelector: {{matchLabels: {{app: teststand-server, release: teststand-{variant}}}}}
  policyTypes: [Ingress]
  ingress:
    - ports: [{{protocol: TCP, port: 5075}}]
"""
        sh(f"printf %s {shlex.quote(pol)} | kubectl apply -f -")
    elif method == "impostor":
        # a pod that accepts on 5075 and answers with bytes that are not PVAccess
        imp = f"""apiVersion: v1
kind: Pod
metadata: {{name: impostor-{variant}, namespace: {NS}, labels: {{app: impostor, release: teststand-{variant}}}}}
spec:
  containers:
    - name: nc
      image: docker.io/library/busybox:latest
      command: ["sh", "-c", "while true; do (head -c 4096 /dev/urandom) | nc -l -p 5075 >/dev/null 2>&1; done"]
"""
        sh(f"printf %s {shlex.quote(imp)} | kubectl apply -f -")
        k(f"wait --for=condition=Ready pod/impostor-{variant} --timeout=120s")
        k(f"delete pod {server_pod} --wait=false")
        k(f"patch service teststand-{variant}-server -p "
          + shlex.quote('{"spec":{"selector":{"app":"impostor","release":"teststand-' + variant + '"}}}'))
        time.sleep(40)
        k(f"patch service teststand-{variant}-server -p "
          + shlex.quote('{"spec":{"selector":{"app":"teststand-server","release":"teststand-' + variant + '"}}}'))
        k(f"delete pod impostor-{variant} --wait=false")
    else:
        raise ValueError(method)

def cleanup_after(variant, method):
    if method == "udpblock":
        k(f"delete networkpolicy udpblock-{variant} --ignore-not-found")
    if method == "impostor":
        k(f"patch service teststand-{variant}-server -p "
          + shlex.quote('{"spec":{"selector":{"app":"teststand-server","release":"teststand-' + variant + '"}}}'),
          check=False)
        k(f"delete pod impostor-{variant} --ignore-not-found --wait=false", check=False)

def run_one(variant, search, kill, load_name, probe_mode, grace, observe, settle, extra_sets, verbose):
    load = LOAD[load_name]
    label = f"{variant}/{search}/{kill}/{load_name}/probe={probe_mode}/grace={grace}" + (f"/gap={GAP}" if kill in MANUAL else "")
    print(f"\n=== {label}", flush=True)

    manual = kill in MANUAL
    install(variant, load, probe_mode, grace, extra_sets, gateway=(search == "gw"), manual=manual)
    server_svc = f"teststand-{variant}-server"
    if search == "gw":
        wait_pod(variant, "gateway")
    client = wait_pod(variant, "monitor")
    server_pod = wait_pod(variant, "server")
    if manual:
        start_ioc(server_pod)
        for _ in range(30):
            if fresh_get_ok(variant, client, server_svc, "SIM:counter")[0]:
                break
            time.sleep(2)
        else:
            raise RuntimeError("hand-started IOC never answered")

    pvs = ["SIM:counter", "SIM:mean", "SIM:noisy_signal"]
    log = "/tmp/experiment.log"
    pid = start_monitor(variant, client, server_svc, SEARCH[search], pvs, log)

    # wait until the monitor is actually receiving
    t0 = time.time(); before = 0
    while time.time() - t0 < 60:
        before = count_updates(read_log(client, log))
        if before >= 6:
            break
        time.sleep(2)
    if before < 6:
        text = read_log(client, log)
        print(f"  monitor never connected ({before} updates). tail:\n" + "\n".join(text.splitlines()[-6:]))
        exec_in(client, f"kill {pid} 2>/dev/null")
        return dict(label=label, outcome="never-connected", before=before)
    if PRERUN:
        print(f"  monitor receiving ({before} updates); letting it age {PRERUN}s before the kill", flush=True)
        time.sleep(PRERUN)
        before = count_updates(read_log(client, log))
    print(f"  monitor receiving ({before} updates); killing server: {kill}", flush=True)

    t_kill = time.time()
    try:
        return _after_kill(variant, kill, load_name, server_pod, client, server_svc, pid, log,
                           label, before, t_kill, observe, verbose)
    finally:
        exec_in(client, f"kill {pid} 2>/dev/null")
        cleanup_after(variant, kill)
        time.sleep(settle)

def _after_kill(variant, kill, load_name, server_pod, client, server_svc, pid, log, label, before,
                t_kill, observe, verbose):
    kill_server(variant, kill, server_pod)

    # wait for a serving server to be back, proven by a fresh client
    replaced = kill in ("graceful", "abrupt", "netcut", "manual-delete", "udpblock", "impostor")
    new_pod = wait_pod(variant, "server", timeout=240, not_named=server_pod if replaced else None)
    t_back = None
    for _ in range(60):
        ok, _out = fresh_get_ok(variant, client, server_svc, "SIM:counter",
                                via="ns" if kill == "udpblock" else "udp")
        if ok:
            t_back = time.time(); break
        time.sleep(2)
    if t_back is None:
        print("  server never came back for a fresh client; aborting run")
        return dict(label=label, outcome="server-never-back")
    print(f"  server back after {t_back - t_kill:.0f}s (pod {new_pod}); observing {observe}s", flush=True)

    snapshot_at_back = read_log(client, log)
    updates_at_back = count_updates(snapshot_at_back)
    time.sleep(observe)
    text = read_log(client, log)
    after = count_updates(text) - updates_at_back

    decode_lines = [l for l in text.splitlines() if DECODE_RE.search(l)]
    disconnects = sum(1 for l in text.splitlines() if DISCONNECT_RE.search(l))
    if decode_lines and after == 0:
        outcome = "decode+noreconnect"
    elif decode_lines:
        outcome = "decode+reconnect"
    elif after == 0:
        outcome = "noreconnect"
    else:
        outcome = "clean"

    print(f"  -> {outcome}   updates after server back: {after}, disconnect lines: {disconnects}, "
          f"decode lines: {len(decode_lines)}", flush=True)
    for l in decode_lines[:5]:
        print("     " + l[:160])
    if verbose or outcome != "clean":
        keep = HERE / "results" / f"{datetime.now():%Y%m%d-%H%M%S}-{label.replace('/', '_')}.log"
        keep.parent.mkdir(exist_ok=True)
        keep.write_text(text)
        print(f"  log: {keep}")

    return dict(label=label, outcome=outcome, before=before, after=after,
                disconnects=disconnects, decode=decode_lines[:5],
                back_after_s=round(t_back - t_kill))

# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variant", choices=VARIANTS, default="spva")
    ap.add_argument("--search", choices=SEARCH, default="udp")
    ap.add_argument("--kill", choices=KILL, default="graceful")
    ap.add_argument("--load", choices=LOAD, default="fast")
    ap.add_argument("--probes", choices=PROBES, default="supervisor")
    ap.add_argument("--grace", type=int, default=30)
    ap.add_argument("--gap", type=int, default=60, help="manual modes: seconds before the operator starts the IOC")
    ap.add_argument("--prerun", type=int, default=0, help="seconds the monitor runs before the kill")
    ap.add_argument("--repeat", type=int, default=1, help="run each permutation this many times")
    ap.add_argument("--observe", type=int, default=45, help="seconds to watch after the server is back")
    ap.add_argument("--settle", type=int, default=5)
    ap.add_argument("--set", action="append", default=[], help="extra helm --set")
    ap.add_argument("--matrix", help="file of permutations, one per line, as flag strings")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if a.list:
        print("variants:", ", ".join(VARIANTS))
        print("search:  ", ", ".join(f"{k} ({v})" for k, v in SEARCH.items()))
        print("kill:    ", "; ".join(f"{k}: {v}" for k, v in KILL.items()))
        print("load:    ", "; ".join(f"{k}: {v}" for k, v in LOAD.items()))
        print("probes:  ", ", ".join(PROBES))
        return

    runs = []
    if a.matrix:
        for line in Path(a.matrix).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                runs.append(ap.parse_args(shlex.split(line)))
    else:
        runs.append(a)

    results = []
    for r in runs:
        global GAP, PRERUN
        GAP, PRERUN = r.gap, r.prerun
        for _rep in range(r.repeat):
          try:
            results.append(run_one(r.variant, r.search, r.kill, r.load, r.probes, r.grace,
                                   r.observe, r.settle, r.set, r.verbose))
          except Exception as e:  # keep the sweep going
            print(f"  !! {e}")
            results.append(dict(label=f"{r.variant}/{r.search}/{r.kill}/{r.load}", outcome=f"error: {e}"[:120]))

    print("\n" + "=" * 100)
    print(f"{'permutation':<58} {'outcome':<20} {'after':>5} {'disc':>4}")
    for r in results:
        print(f"{r['label']:<58} {r['outcome']:<20} {str(r.get('after','')):>5} {str(r.get('disconnects','')):>4}")
    out = HERE / "results" / f"{datetime.now():%Y%m%d-%H%M%S}-summary.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=1))
    print(f"\nsummary: {out}")

if __name__ == "__main__":
    main()
