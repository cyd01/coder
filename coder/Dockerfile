FROM    codercom/code-server:latest

USER    root

ARG     APT_HTTP_PROXY
RUN     test -z "${APT_HTTP_PROXY}" || printf 'Acquire::http::Proxy "'${APT_HTTP_PROXY}'";' > /etc/apt/apt.conf.d/00proxy
ARG     CA_CERTS
RUN     test -z "${CA_CERTS}" || echo "${CA_CERTS}" >> /usr/local/share/ca-certificates/ca.crt

ARG     DEBIAN_FRONTEND=noninteractive
ARG     CODER_PKG_INSTALL
RUN     \
        apt update \
        && apt install --yes ca-certificates && update-ca-certificates \
        && apt install --yes curl git iputils-ping jq make net-tools nmon openssh-server sudo tig tmux tzdata unzip vim wget ${CODER_PKG_INSTALL} \
              docker.io docker-compose \
        && apt clean \
        && curl -fksSL --no-progress-meter -o /tmp/go-linux-amd64.tar.gz "https://go.dev/dl/$(curl -fksSL 'https://go.dev/VERSION?m=text' | head -1).linux-amd64.tar.gz" \
        && rm -rf /usr/local/go \
        && cd /usr/local && tar zxf /tmp/go-linux-amd64.tar.gz && cd - > /dev/null \
        && cd /usr/local/bin && for file in /usr/local/go/bin/*; do ln -s -f $file; done && cd - > /dev/null \
        && rm -f /tmp/go-linux-amd64.tar.gz \
        && go version >&2 \
        && curl -fsSLk "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl-bin \
        && chmod +x /usr/local/bin/kubectl-bin && kubectl-bin version --client --output=yaml >&2 \
        && curl -fsSLk -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && chmod 700 /tmp/get_helm.sh && /tmp/get_helm.sh && rm -f /tmp/get_helm.sh \
        && helm version >&2 \
        && curl -fsSLk "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
        && unzip -q awscliv2.zip \
        && ./aws/install --update \
        && rm -rf ./awscliv2.zip ./aws  \
        && aws --version >&2 \
        && curl -fskSL "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp \
        && mv -f /tmp/eksctl /usr/local/bin && eksctl version >&2 \
        && curl -fsSLk https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
        && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
        && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
        && apt update \
        && apt install gh -y

COPY    kubectl-script /usr/local/bin/kubectl
RUN     chmod +x /usr/local/bin/kubectl
RUN     usermod --append --groups docker coder

COPY    dockerd-entrypoint.sh /usr/bin/dockerd-entrypoint.sh
RUN     chmod +x /usr/bin/dockerd-entrypoint.sh

RUN     printf '#!/bin/sh\ntest $# -ne 3 && { echo "Usage: $(basename ${0}) Pattern File Perms" >&2 ; exit 1 ; }\nsed -e '\''/^## -'\''${1}'\''/,/## '\''${1}'\''-$/!d'\'' /etc/Dockerfile | sed '\''s/^#//'\'' | sed '\''1d;$d'\'' > ${2}\nchmod ${3:-755} ${2}\n' > /usr/local/bin/make-file.sh && chmod 755 /usr/local/bin/make-file.sh
COPY    Dockerfile /etc/Dockerfile
RUN     touch /etc/Dockerfile

COPY    pre-startup.sh /pre-startup.sh
COPY    startup.sh /startup.sh

COPY    id_rsa /etc/id_rsa
RUN     chmod ugo+rx /pre-startup.sh /startup.sh

RUN     printf 'unset HTTP_PROXY\nunset HTTPS_PROXY\nunset http_proxy\nunset https_proxy\n' >> /etc/environment
RUN     sed -i 's#^exec dumb-init .*$#sudo -E /pre-startup.sh;/startup.sh "\$@"#' /usr/bin/entrypoint.sh

USER    coder
WORKDIR /home/coder
