# secure-inline-scan

This script is useful for performing image analysis on locally built container image and post the result of the analysis to sysdig secure. The only dependency for this script is access to docker-engine, Sysdig Secure endpoint (with the API token) and network connectivity to post image analysis results.

## Usage

    $ ./inline_scan.sh 
    
    Sysdig Inline Scanner/Analyzer --
    
      Wrapper script for performing vulnerability scan or image analysis on local docker images, utilizing the Sysdig inline_scan container.
      For more detailed usage instructions use the -h option after specifying scan or analyze.
    
        Usage: inline_scan.sh <scan|analyze> [ OPTIONS ]
    
    
            ERROR - must specify operation ('scan' or 'analyze')

## Example

#### Analyze the image and post the results to Sysdig Secure.
      
    ./inline_scan.sh analyze -s https://secure.sysdig.com -k <token> -g -P docker.io/alpine:3.2
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
     
    Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
    {}
    Cleaning up docker container: 2177a7042fafce1bc70d12dcb041ec3da7eb8e90d683eb95d9aa74f54b018f7c 


#### Perform the image scan locally

    $ ./inline_scan.sh scan -p docker.io/alpine:3.2
    Pulling image -- docker.io/alpine:3.2
    3.2: Pulling from library/alpine
    Digest: sha256:e9a2035f9d0d7cee1cdd445f5bfa0c5c646455ee26f14565dce23cf2d2de7570
    Status: Image is up to date for alpine:3.2
    docker.io/library/alpine:3.2
    
    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Starting Anchore Engine
    Starting Postgresql... Postgresql started successfully!
    Starting Docker registry... Docker registry started successfully!
    Waiting for Anchore Engine to be available.
    
            Status: not_ready..
    
    Anchore Engine is available!
    
    
    Preparing docker.io/alpine:3.2 for analysis
    
    Getting image source signatures
    Copying blob sha256:2f0b1957d1f7074296e0d6388139b7a968e8c051f8b6227f3610757f7407af05
     5.38 MB / 5.38 MB  0s
    Copying config sha256:98f5f2d17bd1c8ba230ea9a8abc21b8d7fc8727c34a4de62d000f29393cf3089
     1.48 KB / 1.48 KB  0s
    Writing manifest to image destination
    Storing signatures
    
    Image archive loaded into Anchore Engine using tag -- alpine:3.2
    Waiting for analysis to complete...
    
            Status: not_analyzed.
            Status: analyzing
            Status: analyzed
    
    Analysis completed!
    
    
            Policy Evaluation - alpine:3.2
    -----------------------------------------------------------
    
    Image Digest: sha256:d9d7670078b3a5fc76256a3b8f5ddf5f4be98d17de92c3aa26809520e7cb2d48
    Full Tag: localhost:5000/alpine:3.2
    Image ID: 98f5f2d17bd1c8ba230ea9a8abc21b8d7fc8727c34a4de62d000f29393cf3089
    Status: pass
    Last Eval: 2019-09-26T16:00:26Z
    Policy ID: 2c53a13c-1765-11e8-82ef-23527761d060
    Final Action: warn
    Final Action Reason: policy_evaluation
    
    Gate                   Trigger                               Detail                                                                                     Status        
    dockerfile             instruction                           Dockerfile directive 'HEALTHCHECK' not found, matching condition 'not_exists' check        warn          
    vulnerabilities        stale_feed_data                       The vulnerability feed for this image distro is older than MAXAGE (2) days                 warn          
    vulnerabilities        vulnerability_data_unavailable        Feed data unavailable, cannot perform CVE scan for distro: alpine:3.2.3                    warn          
    
    
    Cleaning up docker container: 19216-inline-anchore-engine
