MAKEFILE_NAME:=$(notdir $(lastword $(MAKEFILE_LIST)))
TARGET=$(notdir $(abspath $(lastword $(MAKEFILE_LIST)/..)))
MAKETARGETS=$(filter-out $@,$(MAKECMDGOALS))

include variables.mk
-include .makerc
-include ~/.makerc


## Curl client
CURL ?=$(shell which curl 2> /dev/null)

## Git command-line tool
GIT ?=$(shell which git 2> /dev/null)

## Docker client
DOCKER ?=$(shell which docker 2> /dev/null)
COMPOSE_FILE?=docker-compose.yml
DOCKER_COMPOSE_OPT ?= --file $(COMPOSE_FILE) --project-name $(TARGET)
DOCKER_COMPOSE ?=$(shell which docker-compose 2> /dev/null) $(DOCKER_COMPOSE_OPT)

MAKER=$(shell test -n "$${USER}" && echo $${USER} || { test -n "$${USERNAME}" && echo $${USERNAME} || { which logname > /dev/null 2>&1 && logname || echo Unknown ; } } )

## convinient variable to define current date/time which can be used for build time
NOW=$(shell date --rfc-3339=seconds)
export NOW
DEBUG = printf -- "| $$(date --rfc-3339=seconds) | %-s | %-5.5s | %-s |\n" "$(subst $(ROOT),$(PROJECT_NAME),$(shell pwd)/$(MAKEFILE_NAME))" "DEBUG"
INFO = printf -- "\e[92m| $$(date --rfc-3339=seconds) | %-s | %-5.5s | %-s |\e[39m\n" "$(subst $(ROOT),$(PROJECT_NAME),$(shell pwd)/$(MAKEFILE_NAME))" "INFO"
WARN = printf -- "\e[93m| $$(date --rfc-3339=seconds) | %-s | %-5.5s | %-s |\e[39m\n" "$(subst $(ROOT),$(PROJECT_NAME),$(shell pwd)/$(MAKEFILE_NAME))" "WARN"
ERROR = printf -- "\e[91m| $$(date --rfc-3339=seconds) | %-s | %-5.5s | %-s |\e[39m\n" "$(subst $(ROOT),$(PROJECT_NAME),$(shell pwd)/$(MAKEFILE_NAME))" "ERROR"
FATAL = printf -- "\e[31m| $$(date --rfc-3339=seconds) | %-s | %-5.5s | %-s |\e[39m\n" "$(subst $(ROOT),$(PROJECT_NAME),$(shell pwd)/$(MAKEFILE_NAME))" "FATAL"

## Show this help prompt.
.PHONY: all
all : help
	@:

## Show this help prompt.
.PHONY: help
help:
	@ echo
	@ echo '  Usage:'
	@ echo ''
	@ echo '    [flags...] make <target>'
	@ echo ''
	@ echo '  Targets:'
	@ echo ''
	@ (echo '   Name:Description'; echo '   ----:-----------'; (awk -F: '/^## /{ comment = substr($$0,4) } comment && /^[a-zA-Z][a-zA-Z ]*[^ ]+:/{ print "   " substr($$1,0,80) ":" comment }' $(MAKEFILE_LIST) | sort -d)) | column -t -s ':'
	@ echo ''
	@ echo '  Flags:'
	@ echo ''
	@ (echo '   Name?=Default value?=Description'; echo '   ----?=-------------?=-----------'; (awk -F"\?=" '/^## /{ comment = substr($$0,4) } comment && /^[a-zA-Z][a-zA-Z0-9_-]+[ ]+\?= /{ print "   " $$1 "?=" substr($$2,0,80) "?=" comment }' $(MAKEFILE_LIST) 2>/dev/null | sort -d)) | sed -e 's/\?= /?=/g' | column -t -s '?='
	@ echo ''

## Will display value of variable.
debug/%:
	@test -z "$(wordlist 2,3,$(subst /, ,$*))" && echo '$*=$($*)' || $(MAKE) -C "$(*:$(firstword $(subst /, ,$*))/%=%)" "debug/$(firstword $(subst /, ,$*))"

## Build all
.PHONY: build
build:
	$(DOCKER_COMPOSE) build --parallel --force-rm $(filter-out $@,$(MAKECMDGOALS))

## Build a specific service
build/%:
	test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(DOCKER_COMPOSE) build --parallel --force-rm '$*'

## Start all
.PHONY: start
start:
	$(DOCKER_COMPOSE) up --detach --remove-orphans --renew-anon-volumes $(filter-out $@,$(MAKECMDGOALS))
	@-$(DOCKER) system prune -f -a > /dev/null 2>&1

.PHONY: up
up : 
	@$(MAKE) --no-print-directory start

.PHONY: run
run : start
	@:

## Start a specific service
start/%:
	test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(DOCKER_COMPOSE) up --detach --remove-orphans --renew-anon-volumes '$*'

## Status
.PHONY: status
status:
	-@$(DOCKER_COMPOSE) ps --all

.PHONY: ps
ps : status
	@:

## Rebuild and restart a specific service
rebuild/%:
	test -z "$(wordlist 2,3,$(subst /, ,$*))" && { $(MAKE) --no-print-directory build/$* ; $(MAKE) --no-print-directory start/$* ; }

restart/% :
	@$(MAKE) --no-print-directory rebuild/$*

## Stop all
.PHONY: stop
stop:
	$(DOCKER_COMPOSE) stop $(filter-out $@,$(MAKECMDGOALS))

## Stop a specific service
stop/%:
	test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(DOCKER_COMPOSE) stop '$*'

.PHONY: down
down :
	@$(DOCKER_COMPOSE) down --volumes --remove-orphans --rmi all

## Enter a specific service
exec/%:
	@$(DOCKER) exec -it $* /bin/bash

## Clean all (stop before)
.PHONY: clean
clean:
	-$(MAKE) --no-print-directory stop $(filter-out $@,$(MAKECMDGOALS))
	-$(DOCKER_COMPOSE) rm -v --force --stop $(filter-out $@,$(MAKECMDGOALS))
	-$(MAKE) volumerm

## Clean a specific service (stop before)
clean/%:
	@test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(MAKE) --no-print-directory stop/$*
	@test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(DOCKER_COMPOSE) rm -v --force --stop '$*'
	@-test -z "$(wordlist 2,3,$(subst /, ,$*))" && $(MAKE) volumerm

## Purge docker
.PHONY: purge
purge:
	$(DOCKER) system prune --force --all --volumes

## Remove all named volumes
volumerm: 
	@for v in $$( $(MAKE) --no-print-directory volumels ) ; do $(DOCKER) volume rm --force $$v ; done

## Remove a specific named volume
volumerm/%:
	@test -z "$(wordlist 2,3,$(subst /, ,$*))" && { t='$*' ; for v in $$( $(MAKE) --no-print-directory volumels | grep $$t ) ; do $(DOCKER) volume rm --force $$v ; done ; }

volumels :
	@-cat $(COMPOSE_FILE) | sed -e '1,/^volumes:/ d' | sed -e '/^[[:alpha:]]/,$$ d' | sed -e 's/:[[:blank:]]*$$//' | grep -v '^[[:blank:]]*$$' | sed 's/^[[:blank:]]*/'$(TARGET)'_/'

## Logs all
.PHONY: logs
logs:
	@-$(DOCKER_COMPOSE) logs --tail 200 --timestamps $(MAKETARGETS)

## Logs a specific service
logs/%:
	@-$(DOCKER_COMPOSE) logs --tail 200 --timestamps --follow '$*'

## List all services
.PHONY: services
services:
	@-echo "Here is the services list" ; cat $(COMPOSE_FILE) | sed -e '1,/^services:/ d' | sed -e '/^[[:alpha:]]/,$$ d' | grep '^  [^ ]' | sed -e 's/:[[:blank:]]*$$//' | sort -u

## Get docker size
.PHONY: size
size:
	df -h /var/lib/docker ; echo ; docker system df

# Default target
%:
	@:
