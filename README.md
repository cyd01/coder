# coder

## Description

How to build a light VSCode server.

## How to build

```bash
docker build . --tag coder
```

## How to run

```bash
docker volume inspect coder_data > /dev/null 2>&1 \
  || docker volume create coder_data
docker run \
  --tty --interactive --rm \
  --name coder \
  --user "$(id -u):$(id -g)" \
  --env "DOCKER_USER=$USER" \
  --volume coder_data:/home \
  --publish ${CODER_PORT:-8080}:8080 coder
```

## Configuration

Some variables can be passed to the `docker run` command to modify image behavior.

| Name               | Description                                       |
| ------------------ | ------------------------------------------------- |
| CODER_GIT_URL      | A git repository to clone at startup              |
| CODER_PASSWORD     | The initial GUI password                          |
| CODER_PKG_INSTALL  | List of additional packages to install at startup |
| CODER_START_SCRIPT | Commands to run at the end of startup             |

---

> References:
https://hub.docker.com/r/codercom/code-server
https://github.com/coder/code-server
https://coder.com/docs/code-server/latest/guide
