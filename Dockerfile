FROM ubuntu:18.04

MAINTAINER Sysdig

RUN apt update && apt install curl docker.io -y && rm -rf /var/lib/apt/*
COPY inline_scan.sh /bin/inline_scan
