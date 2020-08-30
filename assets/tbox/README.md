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
