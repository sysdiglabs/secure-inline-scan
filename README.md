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

        ERROR - must provide a Sysdig Secure endpoint


Sysdig Inline Analyzer --

  Script for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Images should be built & tagged locally.

    Usage: inline_scan.sh analyze -s <SYSDIG_REMOTE_URL> -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k '924c7ddc-4c09-4d22-bd52-2f7db22f3066')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local'). 
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -P  [optional] Pull container image from registry
      -V  [optional] Increase verbosity

  


## Example

#### Analyze the image and post the results to Sysdig Secure.
      
    $ ./inline_scan.sh analyze -s https://secure.sysdig.com -k <token> -P docker.io/alpine:latest
    
    Pulling image -- docker.io/alpine:latest
    latest: Pulling from library/alpine
    Digest: sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb
    Status: Downloaded newer image for alpine:latest
    docker.io/library/alpine:latest
    
    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Saving docker.io/alpine:latest for local analysis
    Successfully prepared image archive -- /tmp/sysdig/alpine:latest.tar
    
    Analyzing docker.io/alpine:latest...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:latest fulldigest=docker.io/alpine@sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb
     Analysis complete!
    
    Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
    Scan Report - 
    {
      "imageDigest": "sha256:72c42ed48c3a2db31b7dafe17d275b634664a708d901ec9fd57b1529280f01fb",
      "at": "2019-10-10T21:48:15Z",
      "tag": "docker.io/alpine:latest",
      "status": "pass",
      "policyBundleId": "default",
      "finalAction": "warn",
      "finalActionReason": "policy_evaluation",
      "nStops": 0,
      "nWarns": 1,
      "policies": [
       {
        "policyId": "default",
        "policyName": "DefaultPolicy",
        "nStops": 0,
        "nWarns": 1,
        "rules": [
         {
          "gate": "dockerfile",
          "trigger": "instruction",
          "nStops": 0,
          "nWarns": 1
         }
        ]
       }
      ]
     }
    Status is pass
    
    Cleaning up docker container: 8afa781af45748a1ec4dcf02e87cf03d89d69c9b3f1e4adcbc1d684cabd106ff
