# secure-inline-scan

This script is useful for performing image analysis on locally built container image and post the result of the analysis to sysdig secure. The only dependency for this script is access to docker-engine, Sysdig Secure endpoint (with the API token) and network connectivity to post image analysis results.

## Usage

    ./inline_scan.sh analyze
 
    ERROR - must specify an image to analyze
 
 
    Sysdig Inline Analyzer --
     
      Script for performing analysis on local docker images, utilizing the Sysdig analyzer subsystem.
      After image is analyzed, the resulting Anchore image archive is sent to a remote Sysdig installation
      using the -r <URL> option. This allows inline_analysis data to be persisted & utilized for reporting.
     
      Images should be built & tagged locally.
     
        Usage: inline_scan.sh analyze -s <SYSDIG_REMOTE_URL> -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>
     
          -s <TEXT>  [required] URL to Sysdig Scanning API endpoint (ex: -r 'https://secure-sysdig.com')
          -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k '924c7ddc-4c09-4d22-bd52-2f7db22f3066')
          -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
          -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
          -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
          -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
          -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
          -t <TEXT>  [optional] Specify timeout for image analysis in seconds. Defaults to 300s. (ex: -t 500)
          -g  [optional] Generate an image digest from docker save tarball
          -P  [optional] Pull docker image from registry
          -V  [optional] Increase verbosity


## Example
  
    ./inline_scan.sh analyze -s https://secure-staging3.sysdig.com -k <token> -g -P docker.io/alpine:3.2
    Pulling image -- docker.io/alpine:3.2
    3.2: Pulling from library/alpine
    95f5ecd24e43: Pull complete
    Digest: sha256:e9a2035f9d0d7cee1cdd445f5bfa0c5c646455ee26f14565dce23cf2d2de7570
    Status: Downloaded newer image for alpine:3.2
    docker.io/library/alpine:3.2
     
    Pulling docker.io/anchore/inline-scan:dev
    dev: Pulling from anchore/inline-scan
    Digest: sha256:50fb6ec97569e4af59870b02e91d28aecebac51ec464621b4ea18e103c26615f
    Status: Image is up to date for anchore/inline-scan:dev
    docker.io/anchore/inline-scan:dev
    Saving docker.io/alpine:3.2 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/alpine:3.2.tar
     
    Analyzing docker.io/alpine:3.2...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:3.2 fulldigest=docker.io/alpine@sha256:98f5f2d17bd1c8ba230ea9a8abc21b8d7fc8727c34a4de62d000f29393cf3089
     Analysis complete!
     
    Sending analysis archive to https://secure-staging3.sysdig.com/api/scanning/v1
    {}
    Cleaning up docker container: 2177a7042fafce1bc70d12dcb041ec3da7eb8e90d683eb95d9aa74f54b018f7c 
