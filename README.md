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

## Target Systems

The plugins had been tested on the following systems:

* CentOS 8, kernel version: `4.18.0-193.14.2.el8_2.x86_64`

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

First, copy `assets/net.d/87-podman-bridge.conflist` to
`/etc/cni/net.d/`.

```bash
sudo cp assets/net.d/87-podman-bridge.conflist /etc/cni/net.d/
```

The configuration is as follows:

```json
{
  "cniVersion": "0.4.0",
  "name": "podman",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni-podman0",
      "isGateway": true,
      "ipMasq": false,
      "ipam": {
        "type": "host-local",
        "routes": [
          {
            "dst": "0.0.0.0/0"
          }
        ],
        "ranges": [
          [
            {
              "subnet": "10.88.0.0/16",
              "gateway": "10.88.0.1"
            }
          ]
        ]
      }
    },
    {
      "type": "cni-nftables-portmap",
      "capabilities": {
        "portMappings": true
      }
    },
    {
      "type": "cni-nftables-firewall",
      "forward_chain_name": "forward"
    }
  ]
}
```

Please note the `ipMasq` key is being set to `false`.

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

## Miscellaneous

### Known Issues

There could be an issue with checksums when using `portmap` plugin.

Specifically, packets would arrive to a container, but they would be
disregarded and no `SYN/ACK` would be sent.

When running `tcpdump` inside a container, there is checksum error
`cksum 0xd776 (incorrect -> 0xd8b9)`.

```
$ tcpdump -i eth0 -vvv -nne
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
01:05:16.704789 ee:58:3f:4d:1f:23 > ea:56:b4:c6:4f:c7, ethertype IPv4 (0x0800), length 58: (tos 0x0, ttl 63, id 8844, offset 0, flags [none], proto TCP (6), length 44)
    10.0.2.2.54017 > 10.88.0.116.80: Flags [S], cksum 0xd776 (incorrect -> 0xd8b9), seq 2337032705, win 65535, options [mss 1460], length 0
```

See similar issue
[here](https://stackoverflow.com/questions/26716722/tcp-receives-packets-but-it-ignores-them).
