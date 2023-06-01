FROM    codercom/code-server:latest

USER    root

ARG     DEBIAN_FRONTEND=noninteractive
ARG     CODER_PKG_INSTALL=
RUN     \
        apt update \
        && apt install --yes ca-certificates curl git jq tig tzdata unzip wget ${CODER_PKG_INSTALL} \
              docker.io docker-compose golang \
        && apt clean \
        && curl -Lk "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl \
        && chmod +x /usr/local/bin/kubectl && kubectl version --client --output=yaml

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
#chown -R ${SUDO_USER}:${SUDO_USER} /home/${SUDO_USER}
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
#/usr/bin/code-server --version --show-versions --help
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
#
#cd ~/project
#exec dumb-init ${CMD} "$@"
#
## exec dumb-init /usr/bin/code-server "$@"
## STARTUP-
