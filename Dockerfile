FROM anchore/anchore-engine:v0.7.3

USER root

RUN curl https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -L -o /usr/local/bin/jq && chmod +x /usr/local/bin/jq

COPY files/ /

ENTRYPOINT ["/sysdig-inline-scan.sh"]
