### Is there an existing issue for this?

- [x] I have searched the existing issues

### Version

equal or higher than v1.19.7 and lower than v1.20.0

### What happened?

Since v1.19, `bpf-lb-sock-terminate-pod-connections` destroys **unconnected** UDP sockets, not only connected ones. Any UDP socket that has ever done a `sendto()` to a Service ClusterIP is destroyed with `bpf_sock_destroy()` when the backend it was translated to is deleted. In v1.16 to v1.18 such sockets were left alone.

The consequence in the kernel is worse than an error code. `bpf_sock_destroy()` runs `udp_abort()`, which sets `sk_err = ECONNABORTED` and then calls `__udp_disconnect()`. For a socket that was bound with port 0 (kernel-chosen port), `SOCK_BINDPORT_LOCK` is not set, so `__udp_disconnect()` unhashes the socket and **releases its local port**. The next `sendto()` silently autobinds to a different ephemeral port. The application sees the same file descriptor, issues no `close()`, `bind()` or `connect()`, and its source port has changed underneath it.

Observed in the reproducer below, one `sendto()` per second from a never-connected socket:

```
bound to port 60155
16:22:49 reply from ('10.96.63.201', 9999) local port 60155
16:22:50 ERROR errno 103 ECONNABORTED Connection aborted ; local port now 38475
16:22:58 reply from ('10.96.63.201', 9999) local port 38475
```

and in the agent log at the same moment:

```
level=info msg="Forcefully terminated sockets"
  module=agent.controlplane.loadbalancer-reconciler.socket-termination
  filter="{DestIp:10.244.0.170 DestPort:9999 Family:2 Protocol:17 States:65535 ...}" success=1
```

The same client against Cilium v1.16.5 with the same options set keeps port 60155 and gets no error.

#### The false assumption

The change is #38693 ("sockets: Terminate sockets with BPF socket iterators"), shipped in v1.19.0. Its description says:

> The program combines the current socket's cookie and the configured filter into a `cilium_lb(4|6)_reverse_sk` map key and checks for the existence of that key to see if this socket was **connected** to the now obsolete backend.

A reverse-NAT entry does not imply a **connected** socket. `cil_sock4_sendmsg` writes a `cilium_lb4_reverse_sk` entry for every unconnected `sendto()` to a Service, because that is how `cil_sock4_recvmsg` un-translates the reply source. So `bpf/bpf_sock_term.c` (`matches_v4()` / `matches_v6()`) selects every socket that has ever sent a datagram to the Service, connected or not.

Before #38693 the destroyer was `pkg/datapath/sockets/sockets.go`, and `MatchSocket()` compared the socket's own kernel-side destination:

```go
if socket.Destination.Equal(f.DestIp) && socket.DestinationPort == f.DestPort {
```

An unconnected socket has destination `0.0.0.0:0` and could never match. That is why the reporter of #39470 could write, on v1.16, that "using `sendto()`, i.e. a short-lived socket, effectively works around the issue". That exemption was removed without being mentioned.

#### Why this matters

The echo client above recovers, because an echo server replies to the datagram's source port. Any protocol whose messages **quote the client's reply port** does not recover. The client keeps quoting the port it read at startup, the server replies there, the client's own kernel answers ICMP port unreachable, and the client never receives another reply for the life of the process.

EPICS PVAccess is such a protocol: the SEARCH message carries the reply port, so every PVAccess client in a Cilium 1.19 cluster (`pvxs`, `p4p`, `pvAccessCPP`) loses server discovery permanently the first time a Service backend it has searched through is replaced. EPICS Channel Access, whose SEARCH reply goes to the datagram source port, survives the identical event, which is how this was narrowed down. Other protocols that quote a port in the payload (SIP, some RTP/RTCP negotiation, TFTP-style transfers, custom discovery) are exposed the same way.

### How can we reproduce the issue?

kind, one node, kube-proxy disabled, Cilium with socket-LB and termination on.

```yaml
# kind-cluster.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: cilium-repro
nodes: [{role: control-plane}]
networking:
  disableDefaultCNI: true
  kubeProxyMode: none
  podSubnet: 10.244.0.0/16
```

```sh
kind create cluster --config kind-cluster.yaml
API=$(docker inspect cilium-repro-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}')
helm install cilium cilium/cilium --version 1.19.7 -n kube-system \
  --set ipam.mode=kubernetes --set operator.replicas=1 \
  --set kubeProxyReplacement=true --set k8sServiceHost=$API --set k8sServicePort=6443 \
  --set socketLB.enabled=true --set socketLB.terminatePodConnections=true
kubectl -n kube-system rollout status ds/cilium
```

A UDP echo server behind a ClusterIP Service, and a client that binds port 0, never calls `connect()`, and prints its own port on every round trip:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: echo}
spec:
  replicas: 1
  selector: {matchLabels: {app: echo}}
  template:
    metadata: {labels: {app: echo}}
    spec:
      terminationGracePeriodSeconds: 1
      containers:
        - name: echo
          image: docker.io/library/python:3.12-alpine
          command: ["python3", "-u", "-c"]
          args:
            - |
              import socket
              s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              s.bind(("0.0.0.0", 9999))
              while True:
                  data, peer = s.recvfrom(4096)
                  s.sendto(data, peer)
---
apiVersion: v1
kind: Service
metadata: {name: echo}
spec:
  selector: {app: echo}
  ports: [{protocol: UDP, port: 9999, targetPort: 9999}]
---
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  containers:
    - name: client
      image: docker.io/library/python:3.12-alpine
      command: ["python3", "-u", "-c"]
      args:
        - |
          import socket, time, errno
          s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          s.bind(("0.0.0.0", 0))            # kernel-chosen port, never connect()ed
          s.settimeout(2)
          print("bound to port", s.getsockname()[1], flush=True)
          while True:
              try:
                  s.sendto(b"ping", ("echo", 9999))
                  data, peer = s.recvfrom(4096)
                  print(time.strftime("%H:%M:%S"), "reply from", peer, "local port", s.getsockname()[1], flush=True)
              except socket.timeout:
                  print(time.strftime("%H:%M:%S"), "timeout; local port now", s.getsockname()[1], flush=True)
              except OSError as e:
                  print(time.strftime("%H:%M:%S"), "ERROR errno", e.errno, errno.errorcode.get(e.errno),
                        e.strerror, "; local port now", s.getsockname()[1], flush=True)
              time.sleep(1)
```

```sh
kubectl apply -f repro.yaml
kubectl wait --for=condition=Ready pod --all --timeout=180s
sleep 10
kubectl delete pod -l app=echo --wait=false
sleep 20
kubectl logs client
kubectl -n kube-system logs ds/cilium -c cilium-agent --since=2m | grep "Forcefully terminated"
```

Repeat with `--version 1.16.5` (or 1.18.x): no error, port unchanged.

### Expected results

- A UDP socket that has never been `connect()`ed is not destroyed by backend termination. It has no connection to terminate. This was the behaviour through v1.18 and is what the option's name and documentation describe.
- If destroying unconnected sockets is intended, it needs to be opt-in and documented, with the note that the kernel releases the local port of any socket bound with port 0, so every protocol that carries its reply port in the payload will stop working after the first backend rotation.
- Either way, the v1.19 release notes should state the behavioural change, since users on v1.16 to v1.18 were relying on `sendto()` being exempt (#39470).

### Cilium Version

1.19.7 704b537b 2026-08-18 (also reproduced against 1.19.0 source; `bpf/bpf_sock_term.c` first appears in v1.19.0). Not reproducible on 1.16.5 with identical options.

### Kernel Version

7.0.12-linuxkit (Docker Desktop, arm64). Any kernel with `bpf_sock_destroy` (6.5+) is expected to behave the same.

### Kubernetes Version

v1.36.1 (kind). Originally observed on a production cluster at v1.35.6.

### Regression

Yes. v1.16 to v1.18 did not destroy unconnected sockets. Introduced by #38693 in v1.19.0.

### Sysdump

Available on request.

### Relevant log output

```
# client
bound to port 60155
16:22:49 reply from ('10.96.63.201', 9999) local port 60155
16:22:50 ERROR errno 103 ECONNABORTED Connection aborted ; local port now 38475
16:22:58 reply from ('10.96.63.201', 9999) local port 38475

# cilium-agent
time=2026-09-08T16:22:49.609161386Z level=info msg="Forcefully terminated sockets" module=agent.controlplane.loadbalancer-reconciler.socket-termination filter="{DestIp:10.244.0.170 DestPort:9999 Family:2 Protocol:17 States:65535 DestroyCB:0x2af5310}" success=1
```

Real-world victim, an EPICS `pvxmonitor` client on the same cluster after its server pod was replaced. It advertised port 36235 in every SEARCH, the kernel had moved it to 46215, and it never recovered:

```
16:01:58.911  SIM:counter Disconnected
16:02:00.138  WARN pvxs.client.io UDP search RX Error (103) : Software caused connection abort

# tcpdump on the new server pod
10.244.0.205.46215 > 10.244.0.187.5076   SEARCH, from the socket's new port
10.244.0.187.5076  > 10.244.0.205.36235  reply, to the port the message quoted
```

### Anything else?

Related, and helpful for context but not duplicates: #39470 (asks for *more* termination, and notes `sendto()` was exempt on v1.16), #37577, #35773, #37907 (the motivation for #38693).

Configuration on the reproducing cluster:

```
bpf-lb-sock: "true"
bpf-lb-sock-terminate-pod-connections: "true"
kube-proxy-replacement: "true"
```

### Cilium Users Document

- [ ] Are you a user of Cilium? Please add yourself to the [Users doc](https://github.com/cilium/cilium/blob/main/USERS.md)

### Code of Conduct

- [x] I agree to follow this project's Code of Conduct
