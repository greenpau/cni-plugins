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
