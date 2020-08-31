# Container Images

First, build the image:

```bash
sudo podman build -t greenpau/tbox .
```

Next, start a container:

```bash
sudo podman run --name=worker1 --net=podman -P -d greenpau/tbox
sudo podman run --name=worker1 --net=podman -p 80:80/tcp -p 5201:5201/tcp -d greenpau/tbox
sudo podman run --name=worker1 --net=podman -p 80:80 -p 5201:5201 -d greenpau/tbox
```

After starting the container, connect to it:

```bash
sudo podman exec -it worker1 /bin/bash
```

## Miscellaneous

### Shortcuts

The following command deletes the namespaces created during
the plugin tests. The names of the namespaces begin with `cnitest`.

```bash
ip netns list | grep cnitest | xargs sudo ip netns delete
```

Additionally, it is worth adding the following `podman` shortcuts:

```bash
alias podls="podman ps -a"
alias podrm="podman ps -a | egrep \"(Exited|Created)\" | cut -d\" \" -f1 | xargs podman rm"
alias podstop="podman ps -a | egrep \" (Up) \" | cut -d\" \" -f1 | xargs podman stop"
```

If necessary, take a traffic capture at the host level:

```
sudo tcpdump -nn -i enp0s3 port not 22 and port not 53
```

### Netfilter Debugging

Further, add the following instruction at the top of a netfilter chain
to enable debugging, see [here](https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/tracing).

```
meta nftrace set 1
```

Next, monitor the trace:

```bash
nft monitor trace | tee trace_1.txt
```

### Connection Tracking

Install `conntrack`:

```bash
yum -y install conntrack-tools
```

Next, use it to view established connections:

```bash
$ conntrack -E

[NEW] tcp      6 120 SYN_SENT src=10.0.2.2 dst=10.0.2.15 sport=50841 dport=80 [UNREPLIED] src=10.0.2.15 dst=10.0.2.2 sport=80 dport=50841
[UPDATE] tcp      6 60 SYN_RECV src=10.0.2.2 dst=10.0.2.15 sport=50841 dport=80 src=10.0.2.15 dst=10.0.2.2 sport=80 dport=50841
[UPDATE] tcp      6 432000 ESTABLISHED src=10.0.2.2 dst=10.0.2.15 sport=50841 dport=80 src=10.0.2.15 dst=10.0.2.2 sport=80 dport=50841 [ASSURED]
```

### Virtual Switch Troubleshooting

Install `bridge-utils`:

```bash
yum -y install bridge-utils
```

Run the following commands to examine MAC address table:

* `brctl show`
* `brctl showmacs <BRIDGE_NAME>`

```
$ brctl show
bridge name	bridge id		STP enabled	interfaces
cni-podman0		8000.ee583f4d1f23	no		veth0ba41dc9

$ brctl showmacs cni-podman0
port no	mac addr		is local?	ageing timer
  1	86:5f:b9:87:56:d7	no		  87.39
  1	a2:c7:53:d1:54:94	yes		   0.00
  1	a2:c7:53:d1:54:94	yes		   0.00
```
