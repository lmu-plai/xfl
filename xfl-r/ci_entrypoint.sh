#!/bin/sh

docker compose --progress plain build xfl_host postgres_host
docker compose --progress plain run xfl_host
