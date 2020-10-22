#!/bin/bash

kubectl create secret docker-registry regcred \
                    --docker-server=index.docker.io \
                    --docker-username=<username> \
                    --docker-password=<password> \
                    --docker-email=<email> \
                     -n tekton-pipelines