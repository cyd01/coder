#!/usr/bin/env bash

echo "Running pre-startup.sh"

echo "Running update-ca-certificates"
update-ca-certificates

echo "Making code-server config"
mkdir -p /home/${SUDO_USER}/.config/code-server

printf 'bind-addr: 127.0.0.1:8080
auth: none
cert: false
' > /home/${SUDO_USER}/.config/code-server/config.yaml

test -z ${CODER_PKG_INSTALL} || {
  echo "Install optionnal packages: ${CODER_PKG_INSTALL}"
  export DEBIAN_FRONTEND=noninteractive
  apt update > /dev/null
  apt clean > /dev/null
  apt install --yes ${CODER_PKG_INSTALL}
  rm -rf /var/cache/apt/* /var/lib/apt/lists/* /tmp/* /var/tmp/* 2> /dev/null
}

echo "Making /home/${SUDO_USER}/.ssh directory"
mkdir -p /home/${SUDO_USER}/.ssh
mv /etc/id_rsa /home/${SUDO_USER}/.ssh/id_rsa && chmod 600 /home/${SUDO_USER}/.ssh/id_rsa
printf 'Host runner\n  User ubuntu\n  Port 22\n  Hostname runner\n' > /home/${SUDO_USER}/.ssh/config
printf 'alias ll="ls -lart"\n' >> /home/${SUDO_USER}/.bash_aliases
echo "Making /home/${SUDO_USER}/.kube directory"
mkdir -p /home/${SUDO_USER}/.kube

chown -R ${SUDO_USER}:${SUDO_USER} /home/${SUDO_USER}

# Add to docker group (create if not exists)
if [ -S /var/run/docker.sock ] ; then
  g=$(stat -c "%g" /var/run/docker.sock)
  getent group $g > /dev/null || { echo "Creating group docker-sock with gid $g" ; groupadd --gid $g docker-sock ; }
  getent group $g | grep ${SUDO_USER} > /dev/null || { echo "Adding user ${SUDO_USER} to group $g" ; usermod --append --groups $g ${SUDO_USER} ; }
fi

# Start docker
if [ -z $DOCKER_HOST ] ; then
  echo "Starting docked..."
  /usr/bin/dockerd-entrypoint.sh dockerd &
  sleep 3
fi

test -z "${CODER_START_SCRIPT}" || {
  echo "Calling post-startup.sh"
  echo ${CODER_START_SCRIPT} > /post-startup.sh
  chmod ugo+x /post-startup.sh
  /post-startup.sh
}

#cat /usr/bin/entrypoint.sh
