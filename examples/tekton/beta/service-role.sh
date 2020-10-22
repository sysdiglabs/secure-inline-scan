#!/bin/bash

kubectl create clusterrole tutorial-role \
               --verb=* \
               --resource=deployments,deployments.apps

kubectl create clusterrolebinding tutorial-binding \
             --clusterrole=tutorial-role \
             --serviceaccount=default:tutorial-service