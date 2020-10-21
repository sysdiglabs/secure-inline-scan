#!/bin/bash

# Uses sysdiglabs/secure-inline-scan:2

# This is an example script that scans from a private registry
# with Sysdig without requiring priviledges.

# It creates a temporary docker-config.json auth file for dockerhub registry, 
# but can be replaced to use any other registry using Docker credentials.

set -euf

KEYS=${KEYS:-"./"}
DOCKER_USER=$(cat $KEYS/DOCKER_USER)
DOCKER_PASS=$(cat $KEYS/DOCKER_PASS)
SYSDIG_SECURE_API_TOKEN=$(cat $KEYS/SYSDIG_SECURE_API_TOKEN)

DOCKER_AUTH=$(echo -n "$DOCKER_USER:$DOCKER_PASS" | base64)
IMAGE=docker.io/vicenteherrera/leeroy-web-my
REPO=https://github.com/GoogleContainerTools/skaffold
DOCKERFILE=examples/microservices/leeroy-web/Dockerfile
CONTEXT=examples/microservices/leeroy-web/


function docker_auth_create {

    echo
    echo "> Create docker-config.json"

cat <<EOF > "./docker-config.json"
    {
        "auths":{        
            "https://index.docker.io":{
                "username":"${DOCKER_USER}",
                "password":"${DOCKER_PASS}",
                "auth":"${DOCKER_AUTH}",
                "email":"not@val.id"
            }
        }
    }
EOF


}

function scan {

    echo
    echo "> Scan"

    docker run \
        -v $PWD:/workspace \
        sysdiglabs/secure-inline-scan:2 \
        --registry-auth-file /workspace/docker-config.json \
        -k $SYSDIG_SECURE_API_TOKEN \
        -s https://secure.sysdig.com \
        $IMAGE

}


# PIPELINE

docker_auth_create
scan

trap "rm -f docker-config.json" EXIT