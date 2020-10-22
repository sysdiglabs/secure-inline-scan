#!/bin/bash

# v2: Updated to use sysdiglabs/secure-inline-scan:2

# This is an example pipeline execution as a Bash script of how to
# execute an inline scan with Sysdig without requiring priviledges.

# The image is locally built, scanned without uploading its contents
# to Sysdig backend, and if it passes the Scan policies, then it's
# pushed to the registry. If it doesn't, nothing is pushed.

# It employs Kaniko for build and Skopeo to push without requiring
# privileged containers, root user or access to Docker socket.

# You can adapt this script steps to the environment or CI/CD engine 
# based on containers of your choice.

set -euf

KEYS=${$KEYS:-"./"}
DOCKER_USER=$(cat $KEYS/DOCKER_USER)
DOCKER_PASS=$(cat $KEYS/DOCKER_PASS)
SYSDIG_SECURE_API_TOKEN=$(cat $KEYS/SYSDIG_SECURE_API_TOKEN)

IMAGE=docker.io/vicenteherrera/leeroy-web-my
REPO=https://github.com/GoogleContainerTools/skaffold
DOCKERFILE=examples/microservices/leeroy-web/Dockerfile
CONTEXT=examples/microservices/leeroy-web/

function clone {
    echo
    echo "> Clone"
    rm -rf repo
    git clone $REPO repo
}

function build {
    echo
    echo "> Build"
    docker run -v $PWD:/workspace \
        gcr.io/kaniko-project/executor:latest \
        --dockerfile=/workspace/repo/$DOCKERFILE \
        --context=/workspace/repo/$CONTEXT \
        --destination=$IMAGE \
        --no-push \
        --oci-layout-path=/workspace/oci \
        --tarPath=/workspace/image.tar
}

function scan {

    echo
    echo "> Scan"

    docker run -v $PWD:/workspace sysdiglabs/secure-inline-scan:2 \
        -s https://secure.sysdig.com \
        --storage-type oci-dir \
        --storage-path /workspace/oci \
        -k $SYSDIG_SECURE_API_TOKEN \
        $IMAGE

}

function push {
    echo
    echo "> Push"

    docker run \
        -v $PWD:/workspace \
        quay.io/skopeo/stable \
        --dest-creds $DOCKER_USER:$DOCKER_PASS \
        --insecure-policy \
        copy \
        oci:/workspace/oci/ \
        docker://$IMAGE

    # alternative: --dest-authfile /home/.docker/config.json
}


# PIPELINE

clone
build
scan
push