FROM registry.access.redhat.com/ubi8/ubi:8.2 as anchore-engine-builder

ENV GOPATH=/go
ENV SKOPEO_REPO=https://github.com/airadier/skopeo
#ENV SKOPEO_VERSION=v0.1.41
ENV SKOPEO_VERSION=registry-token-cli-flag

RUN set -ex && \
    echo "installing OS dependencies" && \
    yum update -y && \
    yum install -y gcc make git go gpgme-devel libassuan-devel device-mapper-devel

# stage anchore dependency binaries
RUN set -ex && \
    echo "installing GO" && \
    mkdir -p /go

RUN set -ex && \
    echo "installing Skopeo" && \
    git clone --branch "$SKOPEO_VERSION" "$SKOPEO_REPO" ${GOPATH}/src/github.com/containers/skopeo && \
    cd ${GOPATH}/src/github.com/containers/skopeo && \
    make bin/skopeo DISABLE_CGO=1 && \
    make install-binary

FROM anchore/anchore-engine:v0.7.3

USER root

# Copy skopeo artifacts from build step
COPY --from=anchore-engine-builder /usr/bin/skopeo /usr/bin/skopeo

RUN curl https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -L -o /usr/local/bin/jq \
    && chmod +x /usr/local/bin/jq \
    && yum install sudo -yq \
    && echo "anchore ALL = NOPASSWD: /usr/bin/chgrp" >> /etc/sudoers.d/anchore-docker-socker \
    && echo "anchore ALL = NOPASSWD: /usr/bin/chmod g+s /usr/bin/skopeo" >> /etc/sudoers.d/anchore-docker-socker

USER anchore

COPY files/ /

HEALTHCHECK --start-period=0s NONE

ENTRYPOINT ["/sysdig-inline-scan.sh"]
