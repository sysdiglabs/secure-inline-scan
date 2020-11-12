FROM registry.access.redhat.com/ubi8/ubi:8.2 as anchore-engine-builder

ENV GOPATH=/go
ENV SKOPEO_REPO=https://github.com/airadier/skopeo
#ENV SKOPEO_VERSION=v0.1.41
ENV SKOPEO_VERSION=patched-unparsed-image

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

FROM quay.io/sysdig/anchore:0.8.1.7

USER root

# Copy skopeo artifacts from build step
COPY --from=anchore-engine-builder /usr/bin/skopeo /usr/bin/skopeo

RUN curl https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -L -o /usr/local/bin/jq \
    && chmod +x /usr/local/bin/jq

USER anchore

COPY files/ /

HEALTHCHECK --start-period=0s NONE

ENTRYPOINT ["/sysdig-inline-scan.sh"]
