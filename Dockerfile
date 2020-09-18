FROM anchore/anchore-engine:v0.7.3

USER root

RUN curl https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -L -o /usr/local/bin/jq \
    && chmod +x /usr/local/bin/jq \
    && yum install sudo -yq \
    && echo "anchore ALL = NOPASSWD: /usr/bin/chgrp" >> /etc/sudoers.d/anchore-docker-socker \
    && echo "anchore ALL = NOPASSWD: /usr/bin/chmod g+s /usr/bin/skopeo" >> /etc/sudoers.d/anchore-docker-socker

USER anchore

COPY files/ /

HEALTHCHECK --start-period=0s NONE

ENTRYPOINT ["/sysdig-inline-scan.sh"]
