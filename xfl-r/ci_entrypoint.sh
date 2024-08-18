#!/bin/sh

docker compose -f ci-docker-compose.yml --progress plain build xfl_host postgres_host
docker compose -f ci-docker-compose.yml --progress plain run xfl_host
