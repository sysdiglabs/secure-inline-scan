# secure-inline-scan

This script is useful for performing local analysis on container images (both from registries and locally built) and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/).

Here are examples of using the inline scanner in different pipelines.

*   [Gitlab](https://sysdig.com/blog/gitlab-ci-cd-image-scanning/)
*   [Github Actions](https://sysdig.com/blog/image-scanning-github-actions/)
*   [AWS Codepipeline](https://sysdig.com/blog/image-scanning-aws-codepipeline-codebuild/)
*   [Azure Pipelines](https://sysdig.com/blog/image-scanning-azure-pipelines/)
*   [CircleCI](https://sysdig.com/blog/image-scanning-circleci/)

## Minimum Requirements
* Sysdig Secure > v2.5.0 access (with token)
* Docker client with daemon running
* Internet Access to post results to Sysdig Secure

**Note**: For Airgapped environments, we suggest the following:

* docker pull docker.io/anchore/inline-scan:v0.6.1 (the version may differ based on the installation)
* docker pull sysdiglabs/secure-inline-scan:latest (if using the inline scan container)
* Open firewall settings to allow traffic to https://secure.sysdig.com/api/scanning

**Note**: For onprem environments, use the -o flag in order to get the correct scan result URL.

## Usage

Here below are described different usages based on Sysdig installation type.

### OnPrem

#### Script
```
curl -s https://download.sysdig.com/stable/inline_scan.sh | bash -s -- analyze -s <SYSDIG_REMOTE_URL> -o -k <TOKEN> <FULL_IMAGE_NAME>
```

#### Docker run
```
docker run -v /var/run/docker.sock:/var/run/docker.sock analyze sysdiglabs/secure-inline-scan:latest -s <SYSDIG_REMOTE_URL> -o -k <TOKEN> <FULL_IMAGE_NAME>
```

---

### SaaS

#### Script
```
curl -s https://download.sysdig.com/stable/inline_scan.sh | bash -s -- analyze -k <TOKEN> <FULL_IMAGE_NAME>
```

#### Docker run
```
docker run -v /var/run/docker.sock:/var/run/docker.sock sysdiglabs/secure-inline-scan:latest analyze -k <TOKEN> <FULL_IMAGE_NAME>
```

---
### Options

The script/docker image support other options that could be set

#### PDF Output (-R)

You can save the report as PDF via `-R <PATH>`.
The `<PATH>` should be an existing directory in which the report PDF will be created.

**Note:** when using the scanner via docker run, remember to mount the container local path with the host one.
Eg:
```
docker run [...] -v "$PWD/hostfolder:/tmp/containerfolder" [...] analyze -s [...] -R "/tmp/containerfolder" <FULL_IMAGE_NAME>
```
In this way, you'll be able to get the PDF even when the container exits.


#### Temporary folder (-v)

In order to analyze the image, the script has to `docker save` the image locally to the filesystem.
By default, it uses the folder `/tmp/sysdig`, but it is customizable via `-v` flag.

Eg: `-v /tmp/another/path` or `-v $PWD/other/tmp`

**IMPORTANT NOTE:** Always specify absolute paths.

**IMPORTANT NOTE:** With this flag, the script will not delete files created nor the folder for safety and debugging reasons. Is up to the user to perform the cleanup. A suggested approach is to always indicate a temporary directory you can safely delete after the analysis.


#### Complete list

For more control and options, please refer to help documentation
```
    $ ./inline_scan.sh analyze help

    Sysdig Inline Analyzer --

  Script for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Images should be built & tagged locally.

    Usage: inline_scan.sh analyze -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -C         [optional] Delete the image from Sysdig Secure if the scan fails
      -P         [optional] Pull container image from registry
      -V         [optional] Increase verbosity
      -v <PATH>  [optional] Use this absolute PATH for intermediate tar files. Path will be created if not existing. Default is /tmp/sysdig (ex: -v /Users/vittorio.camisa/developer/sysdig-secure/secure-inline-scan/temp)
      -R <PATH>  [optional] Download scan result pdf in a specified local directory (ex: -R /staging/reports)
      -o         [optional] Use this flag if targeting onprem sysdig installation
```

---

## Output Example

#### Analyze the image and post the results to Sysdig Secure.

    $ ./inline_scan.sh analyze -s https://secure.sysdig.com -k <token> -P docker.io/alpine:3.10

    Pulling image -- docker.io/alpine:3.10
    3.10: Pulling from library/alpine

    4167d3e14976: Pull complete
    Digest: sha256:7c3773f7bcc969f03f8f653910001d99a9d324b4b9caa008846ad2c3089f5a5f
    Status: Downloaded newer image for alpine:3.10
    docker.io/library/alpine:3.10

    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Saving docker.io/alpine:3.10 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/alpine:3.10.tar

    Analyzing docker.io/alpine:3.10...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:3.10 fulldigest=docker.io/alpine@sha256:7c3773f7bcc969f03f8f653910001d99a9d324b4b9caa008846ad2c3089f5a5f
     Analysis complete!

    Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
    Scan Report -
    [
      {
        "sha256:7c3773f7bcc969f03f8f653910001d99a9d324b4b9caa008846ad2c3089f5a5f": {
          "docker.io/alpine:3.10": [
            {
              "detail": {},
              "last_evaluation": "2020-02-25T01:18:31Z",
              "policyId": "default",
              "status": "pass"
            }
          ]
        }
      }
    ]

    Status is pass

    View the full result @ https://secure.sysdig.com/#/scanning/scan-results/docker.io%2Falpine%3A3.10/sha256:7c3773f7bcc969f03f8f653910001d99a9d324b4b9caa008846ad2c3089f5a5f/summaries
    PDF report of the scan results can be generated with -R option.

    Cleaning up docker container: 27a80f8606e3b577bd2cab4601c79d92db490034d48d8d29f328c51cbad6e604

##### Sample scan results report in PDF format
<img width="1377" alt="node-scan-result-pg1" src="https://user-images.githubusercontent.com/39659445/76037687-8dae4780-5efc-11ea-9f26-9347a5c4334c.png">

