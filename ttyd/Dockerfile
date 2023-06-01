FROM    ubuntu:latest as builder
ARG     DEBIAN_FRONTEND=noninteractive
RUN     apt update \
        && apt-get install --yes build-essential cmake git libjson-c-dev libwebsockets-dev \
        && git clone https://github.com/tsl0922/ttyd.git \
        && cd ttyd \
        && mkdir build \
        && cd build \
        && cmake .. \
        && make \
        && make install

#FROM    ubuntu
#COPY    --from=builder /usr/local/bin/ttyd /usr/local/bin/ttyd
#ARG     DEBIAN_FRONTEND=noninteractive

RUN     apt update \
        && apt-get install --yes git libjson-c5 tmux vim

COPY    tmux.conf /tmux.conf
COPY    entrypoint.sh /entrypoint.sh
RUN     chmod +x /entrypoint.sh

COPY    id_rsa /root/.ssh/id_rsa
RUN     chmod 600 /root/.ssh/id_rsa && chmod 700 /root/.ssh
RUN     printf 'Host runner\n  User ubuntu\n  Port 22\n  Hostname runner\n' > /root/.ssh/config

COPY    Dockerfile /etc/Dockerfile
RUN     touch /etc/Dockerfile

EXPOSE  80
WORKDIR /root

ENTRYPOINT [ "/entrypoint.sh" ]