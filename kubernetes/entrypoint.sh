#!/usr/bin/env bash

printf 'alias ll="ls -lart"\n' >> /root/.bash_aliases

echo "Starting dockerd..."
dockerd-entrypoint.sh &

sleep 3

echo "Waiting for docker..."
docker ps
while [ $? -ne 0 ] ; do
  sleep 2
  docker ps
done

echo "Starting kubernetes..."
kind create cluster --name cluster --config /etc/kind-config.yaml

/usr/local/bin/tunnel -port $(hostname -i):6443 -tunnel 127.0.0.1:6443 &

mkdir -p /root/.kube
kind get kubeconfig --name cluster

kubectl get nodes --show-labels
echo

if [ -s /root/.kube/config ] ; then
  cat /root/.kube/config | sed 's/127\.0\.0\.1/kubernetes/' | tee /root/kubeconfig
  {
    while [ 1 ] ; do
      scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -o ConnectTimeout=3 -o LogLevel=quiet -i /root/.ssh/id_rsa /root/kubeconfig ubuntu@runner:.kube/config
      sleep 10
    done
  } &
else
  echo "Unable to start kind !" >&2
  exit 1
fi

exec sleep infinity
