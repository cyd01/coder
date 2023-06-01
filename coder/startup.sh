#!/usr/bin/env bash

echo "Running startup.sh"

export HOME=/home/${USER}
id ; echo "HOME="$HOME ; echo "USER="$USER


LIST="ritwickdey.LiveServer redhat.vscode-yaml shd101wyy.markdown-preview-enhanced bierner.markdown-mermaid ${CODER_EXT_LIST}"
cmdext=""
test -z "${LIST}" || {
  for ext in ${LIST} ; do
    cmdext=${cmdext}" --install-extension $ext"
  done
}
appname=${CODER_APP_NAME:-This is a test}

/usr/bin/code-server --version --show-versions --help

if [ "X${CODER_PASSWORD}" = "X" ] ; then
  CMD="/usr/bin/code-server --disable-workspace-trust --disable-telemetry --auth none --bind-addr 127.0.0.1:8080 --app-name \"${appname}\""
  sed -i 's/^auth:.*$/auth: none/' ~/.config/code-server/config.yaml
  sed -i '/^password:/d' ~/.config/code-server/config.yaml
else
  export PASSWORD=${CODER_PASSWORD}
  CMD="/usr/bin/code-server --disable-workspace-trust --disable-telemetry --auth password --bind-addr 127.0.0.1:8080 --app-name \"${appname}\""
  sed -i 's/^auth:.*$/auth: password/' ~/.config/code-server/config.yaml
fi

CMD="${CMD} --welcome-text \"Welcome to Coder\""

${CMD} --force ${cmdext}

cat ~/.config/code-server/config.yaml

if [ "X${CODER_GIT_URL}" = "X" ] ; then
  mkdir -p ~/project
else
  test -d ~/project && rm -rf ~/project
  git clone ${CODER_GIT_URL} ~/project
fi

ssh-keyscan runner 2> /dev/null >> ~/.ssh/known_hosts

cd ~/project
exec dumb-init ${CMD} "$@"

# exec dumb-init /usr/bin/code-server "$@"
