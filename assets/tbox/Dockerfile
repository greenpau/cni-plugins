FROM centos:latest

LABEL maintainer="Paul Greenberg"

RUN yum -y install bind-utils openssh-server openssh-clients iproute
RUN yum -y install tcpdump telnet nmap-ncat traceroute net-tools mailx iperf3 wget
RUN yum -y --enablerepo=PowerTools install elinks

RUN wget https://github.com/caddyserver/caddy/releases/download/v2.2.0-rc.1/caddy_2.2.0-rc.1_linux_amd64.tar.gz && \
tar xvzf caddy_2.2.0-rc.1_linux_amd64.tar.gz && \
chmod +x caddy && mv caddy /usr/bin

ADD ./init.sh /init.sh

EXPOSE 5201
EXPOSE 80

WORKDIR /var/lib/caddy

ENTRYPOINT ["/init.sh"]
CMD ["tail", "-f", "/dev/null"]
