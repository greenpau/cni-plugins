# CNI Plugins compatible with nftables

<a href="https://github.com/greenpau/cni-plugins/actions/" target="_blank"><img src="https://github.com/greenpau/cni-plugins/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/cni-plugins" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
![License](https://img.shields.io/github/license/greenpau/cni-plugins)

The plugins in this repository implement
[CNI Specification v0.4.0](https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md).

At the moment, the [CNI Plugins](https://github.com/containernetworking/plugins)
maintained by the CNI team do not support `nftables`. The below plugins do.

This repository contains the following plugins:

* `cni-nftables-portmap`: port mapping with `nftables`
* `cni-nftables-firewall`: firewalling with `nftables`

<!-- begin-markdown-toc -->
## Table of Contents

* [Getting Started](#getting-started)
  * [cni-nftables-firewall](#cninftablesfirewall)
  * [cni-nftables-portmap](#cninftablesportmap)
* [Plugin Development](#plugin-development)
  * [Overview](#overview)
  * [Integration Testing](#integration-testing)
    * [cni-nftables-firewall](#cninftablesfirewall-1)
    * [cni-nftables-portmap](#cninftablesportmap-1)

<!-- end-markdown-toc -->

## Getting Started

### cni-nftables-firewall

The `cni-nftables-firewall` plugin performs the following steps upon
the "add" operation.

1. If `filter` table (or the one specified by `filter_table_name`) does not
  exist, it creates it.
2. If the `forward` chain (or the one specified by `forward_chain_name`)
  in the `filter` table does not exist, it creates it.

### cni-nftables-portmap

The `cni-nftables-portmap` plugin performs the following steps upon
the "add" operation.

1. If `nat` table (or the one specified by `nat_table_name`) does not
   exist, it creates it.
1. If the `postrouting` chain (or the one specified by `postrouting_chain_name`)
  in the `nat` table does not exist, it creates it.
1. If the `prerouting` chain (or the one specified by `prerouting_chain_name`)
  in the `nat` table does not exist, it creates it.

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

#### cni-nftables-firewall

The following command tests `firewall` plugin by placing
a container in `podman` network and quering AWS Check IP
website:

```bash
podman run --net=podman -it nicolaka/netshoot curl http://checkip.amazonaws.com/
```

#### cni-nftables-portmap

The following command tests `portmap` plugin by placing
a container in `podman` network and exposing a web server
in the container.

First, start the container:

```bash
podman run --net=podman -P -d nginxdemos/hello
```

Alternatively, map the container port to port `8080`:

```bash
podman run --net=podman -p 8080:80/tcp -d nginxdemos/hello
```

Verify connectivity to the container:

```bash
curl -v http://127.0.0.1:8080
```
