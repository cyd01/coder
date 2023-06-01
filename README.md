# coder

deprecated.

## Description

How to build a light VSCode server.

## How to build

```bash
docker build . --tag coder
```

## How to run

First it is needed to create a volume for datas.

```bash
docker volume inspect coder_data > /dev/null 2>&1 \
  || docker volume create coder_data
```

### Simple start

```bash
docker run \
  --tty --interactive --rm \
  --name coder \
  --user "$(id -u):$(id -g)" \
  --env "DOCKER_USER=$USER" \
  --volume coder_data:/home \
  --publish ${CODER_PORT:-8080}:8080 coder
```

### Start with docker socket support

```bash
docker run \
  --tty --interactive --rm \
  --name coder \
  --user "$(id -u):$(id -g)" \
  --volume coder_data:/home \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --publish ${CODER_PORT:-8080}:8080 coder
```

### Start against remote docker

```bash
docker run \
  --tty --interactive --rm \
  --name coder \
  --user "$(id -u):$(id -g)" \
  --volume coder_data:/home \
  --env DOCKER_HOST=tcp://192.168.0.1:2375 \
  --publish ${CODER_PORT:-8080}:8080 coder
```

## Configuration

Some variables can be passed to the `docker run` command to modify image behavior.

| Name               | Description                                       |
| ------------------ | ------------------------------------------------- |
| CODER_APP_NAME     | Name of the VSCode server                         |
| CODER_EXT_LIST     | List of VSCode extensions to install in image     |
| CODER_GIT_URL      | A git repository to clone at startup              |
| CODER_PASSWORD     | The initial GUI password                          |
| CODER_PKG_INSTALL  | List of additional packages to install at startup |
| CODER_START_SCRIPT | Commands to run at the end of startup             |

---

> References:  
https://hub.docker.com/r/codercom/code-server  
https://github.com/coder/code-server  
https://coder.com/docs/code-server/latest/guide  


## Examples

### Start a docker image

```bash
docker run --rm --detach -p 8081:8080 --name httpbin grafana/k6-httpbin:latest
```

Start a browser at http://localhost:8081/

### Start a compose file

```bash
docker-compose --file docker-compose-httpbin.yml up --detach
```

Start a browser at http://localhost:8085/

### Start a kubernetes manifest

```bash
kubectl apply -f httpbin.yaml
kubectl get all -n httpbin
```

Start a browser at http://localhost:8091/
