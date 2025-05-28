#!/usr/bin/env bash
source ./docker_image.sh
# We want to keep the same exact path of our source code inside the container, to please the paths in the docker-compose files
HOST_SRC_CODE="$(dirname "$(pwd)")"

docker run \
    --name test-builder \
    --platform linux/amd64 \
    -e "OUTPUT_USER_ID=$(id -u "${USER}")" \
    -e "OUTPUT_GROUP_ID=$(id -g "${USER}")" \
    -v "$HOST_SRC_CODE":/source-datadog-agent:ro \
    -e SOURCEDIR=/source-datadog-agent \
    -e WORKDIR="$HOST_SRC_CODE" \
    -v /proc:/host/proc:ro \
    -e HOST_PROC=/host/proc \
    -v /sys:/host/sys:ro \
    -e HOST_SYS=/host/sys \
    -v /etc:/host/etc:ro \
    -e HOST_ETC=/host/etc \
    -v /tmp:/output \
    -e OUTPUTDIR="/output" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /usr/src:/usr/src:ro \
    --network host \
    --privileged \
    --pid host \
     --rm -i -t \
     "$DOCKER_IMAGE" /bin/bash