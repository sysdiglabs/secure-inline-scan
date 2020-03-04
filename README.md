# secure-inline-scan

This script is useful for performing image analysis on locally built container image and post the result of the analysis to [Sysdig Secure](https://sysdig.com/products/kubernetes-security/). The only dependency for this script is access to docker-engine, Sysdig Secure endpoint (with the API token) and network connectivity to post image analysis results.

Here are examples of using the inline scanner in different pipelines.

*   [Gitlab](https://sysdig.com/blog/gitlab-ci-cd-image-scanning/)
*   [Github Actions](https://sysdig.com/blog/image-scanning-github-actions/)
*   [AWS Codepipeline](https://sysdig.com/blog/image-scanning-aws-codepipeline-codebuild/)
*   [Azure Pipelines](https://sysdig.com/blog/image-scanning-azure-pipelines/)
*   [CircleCI](https://sysdig.com/blog/image-scanning-circleci/)

## Usage

    $ ./inline_scan.sh help
    
    Sysdig Inline Scanner/Analyzer --
    
      Wrapper script for performing vulnerability scan or image analysis on local container images, utilizing the Sysdig inline_scan container.
      For more detailed usage instructions use the -h option after specifying scan or analyze.
    
        Usage: inline_scan.sh <analyze> [ OPTIONS ]
    
    $ ./inline_scan.sh analyze help

	ERROR - invalid combination of Sysdig secure endpoint : token provided - https://secure.sysdig.com/api/scanning/v1 : test-token


    Sysdig Inline Analyzer --

    Script for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
    After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
    using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

    Images should be built & tagged locally.

    Usage: inline_scan.sh analyze -s <SYSDIG_REMOTE_URL> -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local'). 
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -P  [optional] Pull container image from registry
      -V  [optional] Increase verbosity
      -R  [optional] Download scan result pdf report


  


## Example

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
    You can also run the script with -R option for more info.
    
    Cleaning up docker container: 27a80f8606e3b577bd2cab4601c79d92db490034d48d8d29f328c51cbad6e604

#### Minimum Requirements
    Sysdig Secure v2.5.0
    
    Anchore Engine v0.5.0
    
    Docker client access to pull images from Dockerhub
    
    Internet Access to post results to Sysdig Secure
    
#### Scan Result PDF when running the script with -R option
    ![Screenshot](https://user-images.githubusercontent.com/39659445/75296350-c6a23a00-57e1-11ea-9a55-d1d0b8b7ac1d.png "Scan result PDF")    