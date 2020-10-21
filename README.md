# Sysdig inline scan

This containerized application is useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/).

---
## Note about older version (1.x)

For version 1.x.y documentation head over [here](./v1.md)

---

## Minimum Requirements

* Sysdig Secure > v2.5.0 access (with token)
* Internet Access to post results to Sysdig Secure
* You can run Docker container

**Note**: For Airgapped environments, we suggest the following:

* docker pull sysdiglabs/secure-inline-scan:2 (if using the inline scan container)
* Open firewall settings to allow traffic to https://secure.sysdig.com/api/scanning or on-prem url

**Note**: For onprem environments, use the -o flag in order to get the correct scan result URL.

## Common scenarios & recipies

### Locally built image (local registry)

```
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    --storage-type docker-daemon \
    --storage-path /var/run/docker.sock \
    <image-name>
```

### Locally build image (docker archive)

Assuming it's avaiable the image tarball at `image.tar`.

```
docker run --rm \
    -v ${PWD}/image.tar:/tmp/image.tar \
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    --storage-type docker-archive \
    --storage-path /tmp/image.tar \
    <image-name>
```


### Public registry image

```
docker run --rm
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    alpine
```

### Private registry image
```
docker run --rm
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    --registry-auth-basic <user:passw> \
    <image-name>
```

Authentication methods available are:
* `--registry-auth-basic` for authenticating via http basic auth
* `--registry-auth-file` for authenticating via docker/skopeo credentials file
* `--registry-auth-token` for authenticating via registry token

## Options

For a complete list of options, please refer to the command's help.

```
docker run --rm sysdiglabs/secure-inline-scan:2 --help
```
## Major changes with v1

### Flags normalizations

* Previously, `-v` flag was reserved for temporary folder path specification. Being now everything inside the container, `-v` with alias `--verbose` is now for verbose output.
* `-C` flag has been lowercased to `-c`

### TLS Verification

Starting from version 2, you'll need to explicitly pass `--sysdig-skip-tls` if targeting an on-prem with non verifiable certificate.

### Supported image types

New image formats are now supported: [ docker-daemon, docker-archive, cri-o, oci-archive, oci-dir ]
To support this, the two options `--storage-type` and `--storage-path` needs to be used.
Some usage examples are listed in the below section.

### Explicit credentials

The cli now requires to explicitly set the credentials when scanning images from private registries.
It is possible to configure them via --registry-auth-file, --registry-auth-basic and --registry-auth-token flags.

### Dropped -P flag

Images will be now downloaded automatically, if needed

### Exit codes

Added different exit codes based on the exit scenario:
```
    0  -> Scan result "pass"
    1  -> Scan result "fail"
    2  -> Wrong script invokation
    3  -> Runtime error
```

### Log file

In case of error, logs can be retrieve from the container at `/tmp/sysdig/info.log`.
Additional information can be logged with `--verbose` flag.

