#!/usr/bin/env bash

if [[ ! $(which pipenv) ]]; then
   echo "pipenv is required"
   exit 1
fi

if [[ ! $(pipenv run anchore-manager) ]]; then
   pipenv install wheels/*
fi

export ANCHORE_CONFIG_DIR=.
export ANCHORE_SERVICE_DIR=./tmp/anchore_service
export ANCHORE_LOG_LEVEL=INFO
export ANCHORE_ENABLE_METRICS=false
export ANCHORE_DISABLE_METRICS_AUTH=false
export ANCHORE_INTERNAL_SSL_VERIFY=false
export ANCHORE_WEBHOOK_DESTINATION_URL=null
export ANCHORE_HINTS_ENABLED=false
export ANCHORE_FEEDS_ENABLED=true
export ANCHORE_FEEDS_SELECTIVE_ENABLED=true
export ANCHORE_FEEDS_SSL_VERIFY=true
export ANCHORE_ENDPOINT_HOSTNAME=localhost
export ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false
export ANCHORE_CATALOG_NOTIFICATION_INTERVAL_SEC=30
export ANCHORE_FEED_SYNC_INTERVAL_SEC=21600
export ANCHORE_EXTERNAL_PORT=null
export ANCHORE_EXTERNAL_TLS=false
export ANCHORE_AUTHZ_HANDLER=native
export ANCHORE_EXTERNAL_AUTHZ_ENDPOINT=null
export ANCHORE_ADMIN_PASSWORD=foobar
export ANCHORE_ADMIN_EMAIL=admin@myanchore
export ANCHORE_HOST_ID="anchore-quickstart"
export ANCHORE_DB_PORT=5432
export ANCHORE_DB_NAME=postgres
export ANCHORE_DB_USER=postgres
export SET_HOSTID_TO_HOSTNAME=false
export ANCHORE_CLI_USER=admin
export ANCHORE_CLI_PASS=foobar
export ANCHORE_SERVICE_PORT=8228
export ANCHORE_CLI_URL="http://localhost:8228"
export ANCHORE_FEEDS_URL="https://ancho.re/v1/service/feeds"
export ANCHORE_FEEDS_CLIENT_URL="https://ancho.re/v1/account/users"
export ANCHORE_FEEDS_TOKEN_URL="https://ancho.re/oauth/token"
export ANCHORE_GLOBAL_CLIENT_READ_TIMEOUT=0
export ANCHORE_GLOBAL_CLIENT_CONNECT_TIMEOUT=0
export ANCHORE_AUTH_PUBKEY=null
export ANCHORE_AUTH_PRIVKEY=null
export ANCHORE_AUTH_SECRET=null
export ANCHORE_OAUTH_ENABLED=false
export ANCHORE_OAUTH_TOKEN_EXPIRATION=3600
export ANCHORE_AUTH_ENABLE_HASHED_PASSWORDS=false
export AUTHLIB_INSECURE_TRANSPORT=true

pipenv run ./_sysdig-inline-scan.sh $@
