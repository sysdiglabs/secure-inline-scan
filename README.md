# secure-inline-scan

This self-contained container is useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/).

---
## Version 2+ note

For version 2.0 and later documentation head over [here](./v2.md)

---

Here are examples of using the inline scanner in different pipelines.

*   [Gitlab](https://sysdig.com/blog/gitlab-ci-cd-image-scanning/)
*   [Github Actions](https://sysdig.com/blog/image-scanning-github-actions/)
*   [AWS Codepipeline](https://sysdig.com/blog/image-scanning-aws-codepipeline-codebuild/)
*   [Azure Pipelines](https://sysdig.com/blog/image-scanning-azure-pipelines/)
*   [CircleCI](https://sysdig.com/blog/image-scanning-circleci/)

## Minimum Requirements
* Sysdig Secure > v2.5.0 access (with token)
* Internet Access to post results to Sysdig Secure

**Note**: For Airgapped environments, we suggest the following:

* docker pull sysdiglabs/sysdig-inline-scan:latest (if using the inline scan container)
* Open firewall settings to allow traffic to https://secure.sysdig.com/api/scanning

**Note**: For onprem environments, use the -o flag in order to get the correct scan result URL.

## Usage

Here below the different usages are described based on Sysdig installation type.

### OnPrem

#### Script
```
curl -s https://download.sysdig.com/stable/inline_scan_docker.sh | bash -s -- -s <SYSDIG_REMOTE_URL> -o -k <TOKEN> <FULL_IMAGE_NAME>
```

#### Docker run
```
docker run -v /var/run/docker.sock:/var/run/docker.sock sysdiglabs/sysdig-inline-scan:latest -s <SYSDIG_REMOTE_URL> -o -k <TOKEN> <FULL_IMAGE_NAME>
```

---

### SaaS

#### Script
```
curl -s https://download.sysdig.com/stable/inline_scan_docker.sh | bash -s -- -k <TOKEN> <FULL_IMAGE_NAME>
```

#### Docker run
```
docker run -v /var/run/docker.sock:/var/run/docker.sock sysdiglabs/secure-inline-scan:latest -k <TOKEN> <FULL_IMAGE_NAME>
```

---
### Options

The script/docker image support other options that could be set

#### PDF Output (-r)

You can save the report as PDF via `-r <PATH>`.
The `<PATH>` should be an existing directory in which the report PDF will be created.

**Note:** remember to mount the container local path with the host one.
Eg:
```
docker run [...] -v "$PWD/hostfolder:/tmp/containerfolder" [...] -s [...] -R "/tmp/containerfolder" <FULL_IMAGE_NAME>
```
In this way, you'll be able to get the PDF even when the container exits.

#### Complete list

For more control and options, please refer to help documentation

```
    $ docker run sysdiglabs/sysdig-inline-scan

Sysdig Inline Analyzer -- USAGE

  Container for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Usage: ${0##*/} -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

    == GLOBAL OPTIONS ==

    -k <TEXT>   [required] API token for Sysdig Scanning auth
                (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
                Alternatively, set environment variable SYSDIG_API_TOKEN
    -s <URL>    [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
    -o          [optional] Use this flag if targeting onprem sysdig installation
    -a <TEXT>   [optional] Add annotations (ex: -a 'key=value,key=value')
    -f <PATH>   [optional] Path to Dockerfile (ex: -f ./Dockerfile)
    -m <PATH>   [optional] Path to Docker image manifest (ex: -m ./manifest.json)
    -i <TEXT>   [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
    -d <SHA256> [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
    -c          [optional] Remove the image from Sysdig Secure if the scan fails
    -r <PATH>   [optional] Download scan result pdf in a specified local directory (ex: -r /staging/reports)
    -v          [optional] Increase verbosity
    --format <FORMAT>
                [optional] Set output format. Available formats are:

                JSON  Write a valid JSON which can be processed in an automated way

                (Others formats might be included in the future)

    == IMAGE SOURCE OPTIONS ==

    [default] If --storage-type is not specified, pull container image from registry.

        == REGISTRY AUTHENTICATION ==

        When pulling from the registry,
        the credentials in the config file located at /config/auth.json will be
        used (so you can mount a docker config.json file, for example).
        Alternatively, you can provide authentication credentials with:
        --registry-auth-basic username:password  Authenticate using this Bearer <Token>
        --registry-auth-token <TOKEN>            Authenticate using this Bearer <Token>
        --registry-auth-file  <PATH>             Path to file with registry credentials, default /config/auth.json

        == TLS OPTIONS ==

        -n                    Skip TLS certificate validation when pulling image

    --storage-type <SOURCE-TYPE>

        Where <SOURCE-TYPE> can be one of:

        docker-daemon   Get the image from the Docker daemon.
                        Requires /var/run/docker.sock to be mounted in the container
        cri-o           Get the image from containers-storage (CRI-O and others).
                        Requires mounting /etc/containers/storage.conf and /var/lib/containers
        docker-archive  Image is provided as a Docker .tar file (from docker save).
                        Tarfile must be mounted inside the container and path set with --storage-path
        oci-archive     Image is provided as a OCI image tar file.
                        Tarfile must be mounted inside the container and path set with --storage-path
        oci-dir         Image is provided as a OCI image, untared.
                        The directory must be mounted inside the container and path set with --storage-path

    == EXIT CODES ==

    0   Scan result "pass"
    1   Scan result "fail"
    2   Wrong parameters
    3   Error during execution
```

---

## Output Example

#### Analyze the image and post the results to Sysdig Secure.

```
Using temporary path /tmp/sysdig/sysdig-inline-scan-1600171928
Pulling image -- docker.io/alpine:latest
Getting image source signatures
Copying blob sha256:df20fa9351a15782c64e6dddb2d4a6f50bf6d3688060a34c4014b0d9a752eb4c
Copying config sha256:0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b
Writing manifest to image destination
Storing signatures

Repo name: docker.io
Base image name: alpine
Tag name: latest

Repo digest: sha256:41691e1851314e2f37eee22c2a9969500d0dcab259f1357f447ef28155f22efc

Image id: 0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b

using full image name: docker.io/alpine:latest
Image digest found on Sysdig Secure, skipping analysis.
Scan Report -
[
 {
  "sha256:41691e1851314e2f37eee22c2a9969500d0dcab259f1357f447ef28155f22efc": {
   "docker.io/alpine:latest": [
    {
     "detail": {},
     "last_evaluation": "2020-09-15T12:11:42Z",
     "policyId": "default",
     "status": "pass"
    }
   ]
  }
 }
]
Status is pass
View the full result @ https://secure.sysdig.com/#/scanning/scan-results/docker.io%2Falpine%3Alatest/sha256:41691e1851314e2f37eee22c2a9969500d0dcab259f1357f447ef28155f22efc/summaries
PDF report of the scan results can be generated with -r option.
Removing temporary folder created /tmp/sysdig/sysdig-inline-scan-1600171928
```

##### Sample scan results report in PDF format

<img width="1377" alt="node-scan-result-pg1" src="https://user-images.githubusercontent.com/39659445/76037687-8dae4780-5efc-11ea-9f26-9347a5c4334c.png">

