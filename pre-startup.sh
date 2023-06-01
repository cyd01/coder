#!/bin/bash
echo "Running pre-startup.sh"

update-ca-certificates

mkdir -p /home/${SUDO_USER}/.config/code-server

printf 'bind-addr: 127.0.0.1:8080
auth: none
cert: false
' > /home/${SUDO_USER}/.config/code-server/config.yaml

test -z ${CODER_PKG_INSTALL} || {
  export DEBIAN_FRONTEND=noninteractive
  apt update > /dev/null
  apt clean > /dev/null
  apt install --yes ${CODER_PKG_INSTALL}
  rm -rf /var/cache/apt/* /var/lib/apt/lists/* /tmp/* /var/tmp/* 2> /dev/null
}

test -z "${CODER_START_SCRIPT}" || {
  echo ${CODER_START_SCRIPT} > /post-startup.sh
  chmod ugo+x /post-startup.sh
  /post-startup.sh
}

chown -R ${SUDO_USER}:${SUDO_USER} /home/${SUDO_USER}

#cat /usr/bin/entrypoint.sh
