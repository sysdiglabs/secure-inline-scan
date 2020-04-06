FROM docker:dind

MAINTAINER Sysdig

RUN apk --no-cache add curl bash
COPY inline_scan.sh /bin/inline_scan
