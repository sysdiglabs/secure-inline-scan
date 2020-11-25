# Sysdig inline scan

> **_WARNING:_**  This repository contains the deprecated inline-scan script V1
>
> Sysdig Inline Scan V2 is the recommended version.
>
>  Check https://docs.sysdig.com/en/integrate-with-ci-cd-tools.html for more information

## Note about older version (1.x)

[Sysdig inline scan V1](v1.md) is still available, but not supported. V1 version runs as a script, and requires a working Docker environment (binaries and daemon), or can run as a container, mounting the docker socket inside the container.

## Migrating to V2

If running the inline-scan via container:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock sysdiglabs/secure-inline-scan analyze ... <image-to-scan>
```

migration to the new version requires changing the image name to `quay.io/sysdig/secure-inline-scan:2` and adding the `--storage-type=docker-daemon` parameter, and removing the `analyze` option:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock quay.io/sysdig/secure-inline-scan:2 ... <image-to-scan> --storage-type=docker-daemon
```

depending on the `docker.sock`permissions you might need to run as root (adding `-u` to the `docker run` command) or adjusting the permissions in the docker socket.

If you are executing the script as:

```
inline_scan.sh ... <image-to-scan>
```

then you will need to execute the inline-scanner as a container instead, as described previously.

### Breaking changes

* **Execution mode**: The inline scan is now executed in a different way. You need to directly run the container instead of using the old `inline_scan.sh` wrapper script. This means that you might need to adapt your automations or pipelines to migrate to inline-scan v2

 * **TLS verification**: starting from version 2, you'll need to explicitly pass `--sysdig-skip-tls` if targeting an on-prem with non verifiable certificate.

----
