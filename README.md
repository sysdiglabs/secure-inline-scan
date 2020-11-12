# Sysdig inline scan V2

This containerized application is useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/).

Sysdig inline scan V2 works as an independent container, without any Docker dependency (it can be used in other container runtimes), and can analyze images in different input formats.

---
## Note about older version (1.x)

Sysdig inline scan V1 is still supported. V1 version runs as a script, and requires a working Docker environment (binaries and daemon), or can run as a container, mounting the docker socket inside the container.

For version 1.x.y documentation head over [here](./v1.md)

---

## Minimum Requirements

* Sysdig Secure > v2.5.0 access (with token)
* Internet Access to post results to Sysdig Secure
* You can run Docker container

**Note**: For Airgapped environments, we suggest the following:

* docker pull sysdiglabs/secure-inline-scan:2 (if using the inline scan container)
* Open firewall settings to allow traffic to (choose based on your environment): 
  https://secure.sysdig.com/api/scanning - US East SaaS
  https://us2.app.sysdig.com/internal/scanning/scanning-analysis-collector - US West SaaS
  https://eu1.app.sysdig.com/internal/scanning/scanning-analysis-collector - EMEA SaaS
  Your on-prem url

**Note**: For onprem environments, use the -o flag in order to get the correct scan result URL.

## Common scenarios & recipes

### Scan local image, built using docker

```
#Build the image locally
docker build -t <image-name> .

#Scan the image, available on local docker. Mounting docker socket is required
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    --storage-type docker-daemon \
    --storage-path /var/run/docker.sock \
    <image-name>
```

### Local image (provided docker archive)

Assuming the image <image-name> is avaiable as an image tarball at `image.tar`.

For example, the command `docker save <image-name> -o image.tar` creates a tarball for <image-name>.

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

Example: scan `alpine` image from public registry. The scanner will pull and scan it.

```
docker run --rm \
    sysdiglabs/secure-inline-scan:2 \
    --sysdig-url <omitted> \
    --sysdig-token <omitted> \
    alpine
```

### Private registry image

To scan images from private registries, you might need to provide credentials:

```
docker run --rm \
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

### Containers-storage (cri-o, podman, buildah and others)

Scan images from container runtimes using containers-storage format:

```
#Build an image using buildah from a Dockerfile
buildah build-using-dockerfile -t myimage:latest

#Scan the image. Options '-u root' and '--privileged' might be needed depending
#on the access permissions for /var/lib/containers
docker run \
    -u root --privileged \
    -v /var/lib/containers:/var/lib/containers \
    sysdiglabs/secure-inline-scan:2 \
    --storage-type cri-o \
    --sysdig-token <omitted> \
    localhost/myimage:latest
```

Example for an image pulled with podman

```
podman pull docker.io/library/alpine

#Scan the image. Options '-u root' and '--privileged' might be needed depending
#on the access permissions for /var/lib/containers
docker run \
    -u root --privileged \
    -v /var/lib/containers:/var/lib/containers \
    sysdiglabs/secure-inline-scan:2 \
    --storage-type cri-o \
    --sysdig-token <omitted> \
    docker.io/library/alpine
```

### Other integrations and examples

See the [examples folder at the repository](https://github.com/sysdiglabs/secure-inline-scan/tree/master/examples) for more usage examples and integrations:

* Jenkins in Kubernetes using PodTemplates
* Tekton
* Google Cloud Build
* ...

## Options

For a complete list of options, please refer to the command's help.

```
docker run --rm sysdiglabs/secure-inline-scan:2 --help
```

# Changes from v1.x.x

## New features

* **Docker daemon and runtime are not required anymore**. Docker socket access is only required to scan images directly from the Docker subsystem.

* **New input formats**: docker archive, OCI archive, OCI directory, containers-storage (cri-o and others).

* **Better performance**: improved image conversion process for reduced scanning times.

## Breaking changes

* **Execution mode**: The inline scan is now executed in a different way. You need to directly run the container instead of using the old `inline_scan.sh` wrapper script. This means that you will need to adapt your automations or pipelines to migrate to inline-scan v2

 * **TLS verification**: starting from version 2, you'll need to explicitly pass `--sysdig-skip-tls` if targeting an on-prem with non verifiable certificate.


## Other relevant changes

### Flags normalizations

* Previously, `-v` flag was reserved for temporary folder path specification. Being now everything inside the container, `-v` with alias `--verbose` is now for verbose output.
* `-C` flag has been lowercased to `-c`

### Supported image types

New image formats are now supported: [ docker-daemon, docker-archive, cri-o, oci-archive, oci-dir ]
To support this, the two options `--storage-type` and `--storage-path` needs to be used.
Some usage examples are listed in this document.

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

