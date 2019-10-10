# secure-inline-scan

This script is useful for performing image analysis on locally built container image and post the result of the analysis to sysdig secure. The only dependency for this script is access to docker-engine, Sysdig Secure endpoint (with the API token) and network connectivity to post image analysis results.

## Usage

    $ /inline_scan.sh analyze
      
      	ERROR - must specify an image to analyze
      
      
      Sysdig Inline Analyzer --
      
        Script for performing analysis on local docker images, utilizing the Sysdig analyzer subsystem.
        After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
        using the -s <URL> option. This allows inline_analysis data to be persisted & utilized for reporting.
      
        Images should be built & tagged locally.
      
          Usage: inline_scan.sh analyze -s <SYSDIG_REMOTE_URL> -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>
      
            -s <TEXT>  [required] URL to Sysdig Secure URL (ex: -s 'https://secure-sysdig.com')
            -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k '924c7ddc-4c09-4d22-bd52-2f7db22f3066')
            -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
            -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
            -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
            -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
            -t <TEXT>  [optional] Specify timeout for image analysis in seconds. Defaults to 300s. (ex: -t 500)
            -P  [optional] Pull docker image from registry
            -V  [optional] Increase verbosity


## Example

#### Analyze the image and post the results to Sysdig Secure.
      
    ./inline_scan.sh analyze -s https://secure.sysdig.com -k <token> -P docker.io/perl:5.30
    Pulling image -- docker.io/perl:5.30
    5.30: Pulling from library/perl
    Digest: sha256:5f3bd735d306a56e308dad312249cd437d2f4d118d85561c8352b5488455e74e
    Status: Image is up to date for perl:5.30
    docker.io/library/perl:5.30
    
    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Saving docker.io/perl:5.30 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/perl:5.30.tar
    
    Analyzing docker.io/perl:5.30...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/perl:5.30 fulldigest=docker.io/perl@sha256:5f3bd735d306a56e308dad312249cd437d2f4d118d85561c8352b5488455e74e
     Analysis complete!
    
    Sending analysis archive to https://secure-staging.sysdig.com/api/scanning/v1
    Scan Report - {
      "imageDigest": "sha256:5f3bd735d306a56e308dad312249cd437d2f4d118d85561c8352b5488455e74e",
      "at": "2019-10-10T00:44:15Z",
      "tag": "docker.io/perl:5.30",
      "status": "fail",
      "policyBundleId": "default",
      "finalAction": "stop",
      "finalActionReason": "policy_evaluation",
      "nStops": 20,
      "nWarns": 329,
      "policies": [
       {
        "policyId": "default",
        "policyName": "DefaultPolicy",
        "nStops": 20,
        "nWarns": 329,
        "rules": [
         {
          "gate": "dockerfile",
          "trigger": "instruction",
          "nStops": 0,
          "nWarns": 1
         },
         {
          "gate": "vulnerabilities",
          "trigger": "package",
          "nStops": 20,
          "nWarns": 328
         }
        ]
       }
      ]
     }
    Status is fail
    
    Cleaning up docker container: d31e15fab0293d0e400d42022358ee4f4b95277e07651c3f40f3173afe674178
