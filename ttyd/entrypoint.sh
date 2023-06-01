#!/usr/bin/env bash

ssh-keyscan runner 2> /dev/null >> ~/.ssh/known_hosts

tmux -f /tmux.conf new -d -s ttyd /bin/bash -c 'while [ 1 ] ; do ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=3 -o LogLevel=quiet runner ; sleep 1 ; done'
ttyd --writable --port 80 -t enableTrzsz=true -t enableSixel=true -t enableZmodem=true tmux attach
# --base-path /tty/