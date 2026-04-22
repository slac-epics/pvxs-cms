# Teststand

A reproduction laboratory for a PVAccess monitor failure SLAC reports and this repository's
Kubernetes laboratories never show: after the server pod is replaced and the server restarted,
a running monitor does not reconnect, and it reports a protocol decode error as it disconnects.

The same chart and the same database run against three PVAccess implementations, so a failure
that appears in one and not the others points straight at the difference.

It has its own namespace, `pvxs-teststand`. The four topologies under `../helm/` use `spva-lab`
and are driven by `../helpers.sh`.

## Run it

```bash
cd example/kubernetes/teststand

# One time each: build the two images that do not already exist.
./docker/upstream/build_docker.sh     # upstream pvxs, no TLS
./docker/pva/build_docker.sh          # the PVAccess inside EPICS Base

./install.sh spva        # this workspace's pvxs
./install.sh upstream    # unmodified upstream pvxs, no TLS
./install.sh pva         # softIocPVA and pvmonitor from EPICS Base
```

All three can run at once. Every object is named and labelled for its release, so each
monitor talks only to its own server.

`install.sh` compares the image config digest it holds locally against the one the cluster's
containerd already has, and loads nothing when they match. `--force-load` loads regardless.

## The three variants

| | `spva` | `upstream` | `pva` |
|---|---|---|---|
| server | `softIocPVX` | `softIocPVX` | `softIocPVA` |
| client | `pvxmonitor` | `pvxmonitor` | `pvmonitor` |
| from | `slac-epics/pvxs-tls` | upstream pvxs `master` | EPICS Base |
| TLS | compiled in | absent | absent |
| image | `testioc`, `lab` | `pvxs-upstream` | `epics-pva` |

`softIocPVA` takes the same `-d`, `-a`, `-m` and `-v` arguments as `softIocPVX`, so all three
load the identical database file and differ only in which binary reads it.

`modules/pvAccess` and `modules/pva2pva` in this Base fork contain no OpenSSL, so the `pva`
variant is the stock EPICS PVAccess stack on both ends. The Secure PVAccess work in this
workspace lives in pvxs, not in Base.

## What it deploys

Per release: a server Deployment behind a ClusterIP Service on TCP 5075 and UDP 5076, and a
client Deployment holding one monitor open. `Recreate` strategy, one replica, and the
environment from the test stand manifests: `EPICS_PVAS_SERVER_PORT=5075`,
`EPICS_PVAS_INTF_ADDR_LIST=0.0.0.0`, `EPICS_PVAS_AUTO_BEACON_ADDR_LIST=NO`,
`EPICS_PVAS_BEACON_ADDR_LIST=""`.

The client carries no probe on purpose: a probe that failed when the server went away would
restart the client pod and destroy the monitor state the run exists to watch. The server
carries readiness and liveness on its PVAccess port, dropped in manual start mode where nothing
listens until you act.

The database and the supervisord program come from ConfigMaps, not from the images, so every
variant serves identical process variables from an identical command line. The pod template
carries a hash of those ConfigMaps, so changing a rate or a script rolls the pods.

## Process variables

Monitored, one update every `scanRate`:

| name | type |
|---|---|
| `SIM:counter`, `SIM:mean`, `SIM:sigma`, `SIM:snr`, `SIM:x_axis` | `calc` |
| `SIM:noisy_signal`, `SIM:clean_signal` | `waveform`, `arrayLength` doubles |

Not monitored, running at `fillRate`: `SIM:tick`, `SIM:clean_src`, `SIM:noise_src`,
`SIM:clean_buf`, `SIM:noisy_buf`. They exist only to keep the two arrays full, so an array
arrives complete rather than slowly filling, without adding anything to the monitor output.

Tuning the noise:

```bash
# slower still
./install.sh spva --set scanRate="10 second"

# a large payload on the wire, the likelier trigger for a decode error
./install.sh spva --set arrayLength=1024

# fewer process variables
./install.sh spva --set 'monitorPvs={counter,noisy_signal}'
```

Valid `scanRate` and `fillRate` values are the EPICS scan menu entries: `.1 second`,
`.2 second`, `.5 second`, `1 second`, `2 second`, `5 second`, `10 second`.

## Provoke the failure

Supervised, which is the default:

```bash
# One terminal: watch the monitor.
kubectl -n pvxs-teststand logs -f deployment/teststand-upstream-monitor

# Another: replace the server pod under it.
kubectl -n pvxs-teststand delete pod -l app=teststand-server,release=teststand-upstream
```

Manual, which is what SLAC does. The pod comes up with nothing listening and you start the
server yourself:

```bash
./install.sh upstream --manual

kubectl -n pvxs-teststand exec -it deployment/teststand-upstream-server \
    -- su testioc -c /usr/local/bin/start-softioc

# Monitor in another terminal, then replace the pod and start the server again.
kubectl -n pvxs-teststand delete pod -l app=teststand-server,release=teststand-upstream
kubectl -n pvxs-teststand exec -it deployment/teststand-upstream-server \
    -- su testioc -c /usr/local/bin/start-softioc
```

Evidence worth capturing either way:

```bash
kubectl -n pvxs-teststand get endpoints teststand-upstream-server -o yaml
kubectl -n pvxs-teststand logs deployment/teststand-upstream-server
kubectl -n pvxs-teststand logs deployment/teststand-upstream-monitor
```

One theory the chart tests directly: endpoint churn while the pod is unready. Reinstall with
`--set publishNotReadyAddresses=false` and see whether the behaviour changes.

## Compare Cilium and PVXS

Run one of the four Cilium and PVXS combinations. Each run recreates `cilium-repro`, enables
socket-level backend termination, replaces the server pod, and checks the monitor result:

```bash
./cilium-repro/run.sh 1.18 regular
./cilium-repro/run.sh 1.18 fixed
./cilium-repro/run.sh 1.19 regular
./cilium-repro/run.sh 1.19 fixed
```

The expected result is `noreconnect` only for Cilium 1.19 with regular PVXS. The other three
combinations expect `clean` reconnection. The runner restores the original Kubernetes context
and the regular `pvxs-upstream:latest` image tag when it exits.

## What a negative result does not prove

Differences from the reported setup that remain:

- The server here is an EPICS soft IOC. SLAC's is a Python p4p server, `gaussian_sim.py` from
  `ghcr.io/slaclab/epics-ml-toolbox`. A fault on the p4p side would not appear here.
- Both new images are built on the `slac-epics/epics-base-tls` fork of EPICS Base, because that
  image was already built. For the `upstream` variant only the pvxs half is upstream.
- There is no PVA gateway and no MetalLB load balancer. The client talks straight to the
  server's Service.

## Files

```
teststand/
  chart/
    Chart.yaml
    values.yaml
    templates/
      _helpers.tpl      release-scoped names, labels and addressing
      configmaps.yaml   start scripts, supervisord program, process database
      server.yaml       server Deployment and Service
      monitor.yaml      client Deployment
      acf.yaml          access security, only when useAccessSecurity is on
  values-spva.yaml
  values-upstream.yaml
  values-pva.yaml
  docker/upstream/      upstream pvxs image
  docker/pva/           EPICS Base PVAccess image
  install.sh
```

## Uninstall

```bash
for r in spva upstream pva; do helm uninstall teststand-$r -n pvxs-teststand; done
kubectl delete namespace pvxs-teststand
```
