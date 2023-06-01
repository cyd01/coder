FROM	docker:dind

USER 	root

ENV     DEBIAN_FRONTEND=noninteractive

RUN	    ln -f -s /usr/share/zoneinfo/Europe/Paris /etc/localtime

RUN 	echo "root:root01" | chpasswd

#RUN     \
#        apt update \
#	    && apt-get install -y ca-certificates curl docker.io docker-compose iputils-ping jq make mlocate net-tools nmon openssl perl sudo tmux unzip vim wget

RUN     \
        apk update \
        && apk add bash curl jq make vim

RUN     cd /tmp \
        && [ $(uname -m) = x86_64 ] && curl -sSkLo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64 \
        && chmod +x ./kind \
        && mv -f ./kind /usr/local/bin/kind \
        && kind version >&2 \
        && cd - > /dev/null

RUN     \
        curl -sSkLO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl \
        && chmod +x ./kubectl \
        && mv ./kubectl /usr/local/bin/kubectl \
        && kubectl version --client >&2

COPY    tunnel /usr/local/bin/tunnel
RUN     chmod +x /usr/local/bin/tunnel

COPY    kind-config.yaml /etc/kind-config.yaml

COPY 	Dockerfile /etc/Dockerfile
COPY 	entrypoint.sh /entrypoint.sh
RUN 	chmod +x /entrypoint.sh ; touch /etc/Dockerfile

RUN     mkdir -p /root/.ssh
COPY    id_rsa /root/.ssh/id_rsa
RUN     chmod 600 /root/.ssh/id_rsa

EXPOSE 	8090-8099

WORKDIR	/root

ENTRYPOINT [ "/entrypoint.sh" ]