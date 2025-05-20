#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Python version installed; we need 3.10-3.11
PYTHON=`command -v python3.11 || command -v python3.10`

.PHONY: install superset venv pre-commit

install: superset pre-commit

superset:
	# Install external dependencies
	pip install -r requirements/development.txt

	# Install Superset in editable (development) mode
	pip install -e .

	# Create an admin user in your metadata database
	superset fab create-admin \
                    --username admin \
                    --firstname "Admin I."\
                    --lastname Strator \
                    --email admin@superset.io \
                    --password general

	# Initialize the database
	superset db upgrade

	# Create default roles and permissions
	superset init

	# Load some data to play with
	superset load-examples

	# Install node packages
	cd superset-frontend; npm ci

update: update-py update-js

update-py:
	# Install external dependencies
	pip install -r requirements/development.txt

	# Install Superset in editable (development) mode
	pip install -e .

	# Initialize the database
	superset db upgrade

	# Create default roles and permissions
	superset init

update-js:
	# Install js packages
	cd superset-frontend; npm ci

venv:
	# Create a virtual environment and activate it (recommended)
	if ! [ -x "${PYTHON}" ]; then echo "You need Python 3.10 or 3.11 installed"; exit 1; fi
	test -d venv || ${PYTHON} -m venv venv # setup a python3 virtualenv
	. venv/bin/activate

activate:
	. venv/bin/activate

pre-commit:
	# setup pre commit dependencies
	pip3 install -r requirements/development.txt
	pre-commit install

format: py-format js-format

py-format: pre-commit
	pre-commit run black --all-files

py-lint: pre-commit
	pylint -j 0 superset

js-format:
	cd superset-frontend; npm run prettier

flask-app:
	flask run -p 8088 --with-threads --reload --debugger

node-app:
	cd superset-frontend; npm run dev-server

build-cypress:
	cd superset-frontend; npm run build-instrumented
	cd superset-frontend/cypress-base; npm ci

open-cypress:
	if ! [ $(port) ]; then cd superset-frontend/cypress-base; CYPRESS_BASE_URL=http://localhost:9000 npm run cypress open; fi
	cd superset-frontend/cypress-base; CYPRESS_BASE_URL=http://localhost:$(port) npm run cypress open

report-celery-worker:
	celery --app=superset.tasks.celery_app:app worker

report-celery-beat:
	celery --app=superset.tasks.celery_app:app beat --pidfile /tmp/celerybeat.pid --schedule /tmp/celerybeat-schedulecd

admin-user:
	superset fab create-admin

############ Docker image targets ############

AIRGAP_REGISTRY ?= lr1-bd-harbor-registry.mip.storage.hpecorp.net/develop
IMG_NAME := hpe-superset/superset
GIT_HASH := $(shell git log -n1 --pretty=%h)
IS_DIRTY := $(shell git diff-index --quiet HEAD -- || echo "-is-dirty")
VERSION := 4.1.2
IMG_TAG ?= $(VERSION)-hpe-ezaf-$(GIT_HASH)$(IS_DIRTY)
DOCKERIZE_TAG := $(VERSION)-dockerize

docker-build:	
	docker build . -t $(IMG_NAME):$(IMG_TAG)
	$(if $(AIRGAP_REGISTRY), docker tag $(IMG_NAME):$(IMG_TAG) $(AIRGAP_REGISTRY)/$(IMG_NAME):$(IMG_TAG))

docker-push:
	docker push $(IMG_NAME):$(IMG_TAG)
	$(if $(AIRGAP_REGISTRY), docker push $(AIRGAP_REGISTRY)/$(IMG_NAME):$(IMG_TAG))

dockerize-build:
	docker build . -f dockerize.Dockerfile -t $(IMG_NAME):$(DOCKERIZE_TAG)
	$(if $(AIRGAP_REGISTRY), docker tag $(IMG_NAME):$(DOCKERIZE_TAG) $(AIRGAP_REGISTRY)/$(IMG_NAME):$(DOCKERIZE_TAG))

dockerize-push:
	docker push $(IMG_NAME):$(DOCKERIZE_TAG)
	$(if $(AIRGAP_REGISTRY), docker push $(AIRGAP_REGISTRY)/$(IMG_NAME):$(DOCKERIZE_TAG))

build-all: docker-build dockerize-build

push-all: docker-push dockerize-push