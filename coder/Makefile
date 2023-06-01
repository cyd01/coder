.PHONY: build
build:
	docker build . -t coder

.PHONY: run
run:
	docker run --rm --name coder --tty --interactive --privileged --publish 8080:8080 coder

.PHONY: start
start: run

.PHONY: stop
stop:
	docker stop coder

.PHONY: kill
kill:
	docker kill coder

.PHONY: purge
purge:
	docker system prune --all --force
