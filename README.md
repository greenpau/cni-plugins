# CNI Plugins compatible with nftables

<a href="https://github.com/greenpau/cni-plugins/actions/" target="_blank"><img src="https://github.com/greenpau/cni-plugins/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/cni-plugins" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
![License](https://img.shields.io/github/license/greenpau/cni-plugins)

The plugins in this repository implement
[CNI Specification v0.4.0](https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md).

At the moment, the [CNI Plugins](https://github.com/containernetworking/plugins)
maintained by the CNI team do not support `nftables`. The below plugins do.

This repository contains the following plugins:

* `cni-nftables-portmap`: port mapping with `nftables`
* `cni-nftables-firewall`: firewalling with `nftables`

## Getting Started

The plugins assume the following:

* `nftables` are operational
* the `filter` table (or the one specified by `filter_table_name`) exist
* the `FORWARD` chain (or the one specified by `forward_chain_name`)
  in the `filter` tables exist

## Plugin Development

### Overview

The entry point to a plugin is `cmd.go`. The code in the file
is responsible for the initializing the instances of a plugin
and triggering `Add()`, `Delete()`, and `Check()` function.

### Integration Testing

First, copy `testdata/net.d/87-podman-bridge.conflist` to
`/etc/cni/net.d/`.

```bash
sudo cp testdata/net.d/87-podman-bridge.conflist /etc/cni/net.d/
```

Review network config:

```bash
$ sudo podman network ls
NAME     VERSION   PLUGINS
podman   0.4.0     bridge,cni-nftables-portmap,cni-nftables-firewall
```

#### firewall

The following command tests `firewall` plugin by placing
a container in `podman` network and quering AWS Check IP
website:

```bash
podman run --net=podman -it nicolaka/netshoot curl http://checkip.amazonaws.com/
```

#### portmap

The following command tests `portmap` plugin by placing
a container in `podman` network and exposing a web server
in the container.

First, start the container:

```bash
podman run --net=podman -P -d nginxdemos/hello
```

Next, attach to the container:

```
podman exec -it <Container ID> /bin/bash
```


