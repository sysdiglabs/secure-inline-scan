#!/usr/bin/env bash
docker run --rm -ti -v /var/run/docker.sock:/var/run/docker.sock sysdiglabs/sysdig-inline-scan "$@"
