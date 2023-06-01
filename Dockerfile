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
        && apt install --yes curl git jq make nmon openssh-server sudo tig tmux tzdata unzip vim wget ${CODER_PKG_INSTALL} \
              docker.io docker-compose golang upx \
        && apt clean \
        && curl -fsSLk "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
        && chmod +x /usr/local/bin/kubectl && kubectl version --client --output=yaml \
        && curl -fsSLk -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && chmod 700 /tmp/get_helm.sh && /tmp/get_helm.sh && rm -f /tmp/get_helm.sh \
        && helm version \
        && curl -fsSLk "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
        && unzip -q awscliv2.zip \
        && ./aws/install --update \
        && rm -rf ./awscliv2.zip ./aws  \
        && aws --version \
        && curl -fskSL "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp \
        && mv -f /tmp/eksctl /usr/local/bin && eksctl version \
        && curl -fsSLk https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
        && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
        && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
        && apt update \
        && apt install gh -y

RUN     printf '#!/bin/sh\ntest $# -ne 3 && { echo "Usage: $(basename ${0}) Pattern File Perms" >&2 ; exit 1 ; }\nsed -e '\''/^## -'\''${1}'\''/,/## '\''${1}'\''-$/!d'\'' /etc/Dockerfile | sed '\''s/^#//'\'' | sed '\''1d;$d'\'' > ${2}\nchmod ${3:-755} ${2}\n' > /usr/local/bin/make-file.sh && chmod 755 /usr/local/bin/make-file.sh
COPY    Dockerfile /etc/Dockerfile
RUN     touch /etc/Dockerfile
RUN     sed -e '/^## -PRESTARTUP/,/## PRESTARTUP-$/!d' /etc/Dockerfile | sed 's/^#//' | sed '1d;$d' > /pre-startup.sh ; true
RUN     sed -e '/^## -STARTUP/,/## STARTUP-$/!d' /etc/Dockerfile | sed 's/^#//' | sed '1d;$d' > /startup.sh ; true

#COPY    pre-startup.sh /pre-startup.sh
#COPY    startup.sh /startup.sh

RUN     chmod ugo+rx /pre-startup.sh /startup.sh

RUN     sed -i 's#^exec dumb-init .*$#sudo -E /pre-startup.sh;/startup.sh "\$@"#' /usr/bin/entrypoint.sh

USER    coder
WORKDIR /home/coder



## -PRESTARTUP
##!/bin/bash
#echo "Running pre-startup.sh"
#
#update-ca-certificates
#
#mkdir -p /home/${SUDO_USER}/.config/code-server
#
#printf 'bind-addr: 127.0.0.1:8080
#auth: none
#cert: false
#' > /home/${SUDO_USER}/.config/code-server/config.yaml
#
#test -z ${CODER_PKG_INSTALL} || {
#  export DEBIAN_FRONTEND=noninteractive
#  apt update > /dev/null
#  apt clean > /dev/null
#  apt install --yes ${CODER_PKG_INSTALL}
#  rm -rf /var/cache/apt/* /var/lib/apt/lists/* /tmp/* /var/tmp/* 2> /dev/null
#}
#
#test -z "${CODER_START_SCRIPT}" || {
#  echo ${CODER_START_SCRIPT} > /post-startup.sh
#  chmod ugo+x /post-startup.sh
#  /post-startup.sh
#}
#
#test -S /var/run/docker.sock && {
#  ID=$(stat -c '%g' /var/run/docker.sock)
#  getent group ${ID} > /dev/null || groupadd --gid $ID docker-host
#  usermod --append --groups $ID ${SUDO_USER}
#}
#
#chown -R ${SUDO_USER}:${SUDO_USER} /home/${SUDO_USER}
#test -z "${TZ}" || { rm --force /etc/localtime && ln --symbolic --force /usr/share/zoneinfo/${TZ} /etc/localtime ; }
#
##cat /usr/bin/entrypoint.sh
## PRESTARTUP-


## -STARTUP
##!/bin/bash
#echo "Running startup.sh"
#export HOME=/home/${USER}
#id ; echo "HOME="$HOME ; echo "USER="$USER
#
#
#LIST="ritwickdey.LiveServer redhat.vscode-yaml shd101wyy.markdown-preview-enhanced bierner.markdown-mermaid ${CODER_EXT_LIST}"
#cmdext=""
#test -z "${LIST}" || {
#  for ext in ${LIST} ; do
#    cmdext=${cmdext}" --install-extension $ext"
#  done
#}
#appname=${CODER_APP_NAME:-This is a test}
#
##/usr/bin/code-server --version --show-versions --help
#
#if [ "X${CODER_PASSWORD}" = "X" ] ; then
#  CMD="/usr/bin/code-server --disable-workspace-trust --disable-telemetry --auth none --bind-addr 127.0.0.1:8080 --app-name \"${appname}\""
#  sed -i 's/^auth:.*$/auth: none/' ~/.config/code-server/config.yaml
#  sed -i '/^password:/d' ~/.config/code-server/config.yaml
#else
#  export PASSWORD=${CODER_PASSWORD}
#  CMD="/usr/bin/code-server --disable-workspace-trust --disable-telemetry --auth password --bind-addr 127.0.0.1:8080 --app-name \"${appname}\""
#  sed -i 's/^auth:.*$/auth: password/' ~/.config/code-server/config.yaml
#fi
#
#test -f  ~/.local/share/code-server/User/settings.json || { mkdir -p ~/.local/share/code-server/User ; echo '{"workbench.colorTheme": "Visual Studio Light"}' >  ~/.local/share/code-server/User/settings.json ; }
#
#CMD="${CMD} --welcome-text \"Welcome to Coder\""
#
#${CMD} --force ${cmdext}
#
#cat ~/.config/code-server/config.yaml
#
#if [ "X${CODER_GIT_URL}" = "X" ] ; then
#  mkdir -p ~/project
#else
#  test -d ~/project && rm -rf ~/project
#  git clone ${CODER_GIT_URL} ~/project
#fi
#cd ~/project
#
#if [ -S /var/run/docker.sock ] ; then
#  ID=$(stat -c '%g' /var/run/docker.sock)
#  GRP=$(getent group $ID | cut -d: -f1)
#  { echo '#!/bin/bash' ; echo ${CMD} "$@" ; } > /tmp/run.sh && sudo mv /tmp/run.sh /run.sh && sudo chmod ugo+x /run.sh
#  exec sg ${GRP} /run.sh
#else
#  exec dumb-init ${CMD} "$@"
#fi
#
## exec dumb-init /usr/bin/code-server "$@"
## STARTUP-
