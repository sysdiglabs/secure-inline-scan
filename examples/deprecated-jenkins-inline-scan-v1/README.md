# Jenkins pipeline integration

The following are the log outputs for a successful / failure run when used in Jenkins pipeline.
Success / Failure status is based on exit code 0/1 from the script which in turn is predicated on image policies configured in Sysdig Secure.

TO-DO: Update output

## Build Success

    + curl -s https://raw.githubusercontent.com/sysdiglabs/secure-inline-scan/master/inline_scan.sh
    + bash -s analyze -s https://secure.sysdig.com -k <token> -P docker.io/alpine:3.7
    Using temporary path /tmp/sysdig/sysdig-inline-scan-1603910120
    Pulling image -- docker.io/alpine:3.7
    3.7: Pulling from library/alpine
    Digest: sha256:8421d9a84432575381bfabd248f1eb56f3aa21d9d7cd2511583c68c9b7511d10
    Status: Image is up to date for alpine:3.7
    Retrieving remote Anchore version from Sysdig Secure APIs
    Found Anchore version from Sysdig Secure APIs 0.8.1
    Pulling docker.io/anchore/anchore-engine:v0.8.1
    v0.8.1: Pulling from anchore/anchore-engine
    Digest: sha256:43e0a7fd25483c7b6d8889d892ac353d4e3f137a6c681b871269b67b2d4b5ec2
    Status: Image is up to date for anchore/anchore-engine:v0.8.1

    Repo name: docker.io
    Base image name: alpine
    Tag name: 3.7

    Image id: 6d1ef012b5674ad8a127ecfa9b5e6f5178d171b90ee462846974177fd9bdd39f

    using full image name: docker.io/alpine:3.7
    Saving alpine:3.7 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/sysdig-inline-scan-1603910120/alpine:3.7.tar
    Analysis complete for image sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b - archive file is located at /tmp/image-analysis-archive.tgz
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:3.7 fulldigest=docker.io/alpine@sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b
    Analysis complete!

    Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
    Calling sync import endpoint
    Scan Report -
    [
    {
      "sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b": {
      "docker.io/alpine:3.7": [
        {
        "detail": {},
        "last_evaluation": "2020-10-28T18:36:07Z",
        "policyId": "default",
        "status": "pass"
        }
      ]
      }
    }
    ]
    Status is pass
    View the full result @ https://secure.sysdig.com/#/scanning/scan-results/docker.io%2Falpine%3A3.7/sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b/summaries
    PDF report of the scan results can be generated with -R option.

    Cleaning up docker container: d547ac778f20aaf745db4493744cff5baff19d78a8d799544fad2e9b256e2c23
    Removing temporary folder created /tmp/sysdig/sysdig-inline-scan-1603910120
    [Pipeline] }
    [Pipeline] // stage
    [Pipeline] }
    [Pipeline] // withEnv
    [Pipeline] }
    [Pipeline] // node
    [Pipeline] End of Pipeline
    Finished: SUCCESS
  


## Build Failure
      
    + bash -s analyze -s https://secure.sysdig.com -k <token> -P docker.io/node:10
    + curl -s https://raw.githubusercontent.com/sysdiglabs/secure-inline-scan/master/inline_scan.sh
    Using temporary path /tmp/sysdig/sysdig-inline-scan-1603910214
    Pulling image -- docker.io/node:10
    10: Pulling from library/node
    0400ac8f7460: Pulling fs layer
    fa8559aa5ebb: Pulling fs layer
    da32bfbbc3ba: Pulling fs layer
    e1dc6725529d: Pulling fs layer
    572866ab72a6: Pulling fs layer
    63ee7d0b743d: Pulling fs layer
    a9e4c546ba77: Pulling fs layer
    8d474dc2d651: Pulling fs layer
    377542fd754b: Pulling fs layer
    572866ab72a6: Waiting
    63ee7d0b743d: Waiting
    a9e4c546ba77: Waiting
    8d474dc2d651: Waiting
    e1dc6725529d: Waiting
    377542fd754b: Waiting
    da32bfbbc3ba: Verifying Checksum
    da32bfbbc3ba: Download complete
    fa8559aa5ebb: Verifying Checksum
    fa8559aa5ebb: Download complete
    0400ac8f7460: Verifying Checksum
    0400ac8f7460: Download complete
    63ee7d0b743d: Verifying Checksum
    63ee7d0b743d: Download complete
    0400ac8f7460: Pull complete
    fa8559aa5ebb: Pull complete
    da32bfbbc3ba: Pull complete
    e1dc6725529d: Verifying Checksum
    e1dc6725529d: Download complete
    a9e4c546ba77: Verifying Checksum
    a9e4c546ba77: Download complete
    8d474dc2d651: Verifying Checksum
    8d474dc2d651: Download complete
    377542fd754b: Verifying Checksum
    377542fd754b: Download complete
    e1dc6725529d: Pull complete
    572866ab72a6: Verifying Checksum
    572866ab72a6: Download complete
    572866ab72a6: Pull complete
    63ee7d0b743d: Pull complete
    a9e4c546ba77: Pull complete
    8d474dc2d651: Pull complete
    377542fd754b: Pull complete
    Digest: sha256:f67d6f3fd49cf4797dec6c9aa950be8a344aed88f0928adc92e3eae618a78ae0
    Status: Downloaded newer image for node:10
    Retrieving remote Anchore version from Sysdig Secure APIs
    Found Anchore version from Sysdig Secure APIs 0.8.1
    Pulling docker.io/anchore/anchore-engine:v0.8.1
    v0.8.1: Pulling from anchore/anchore-engine
    Digest: sha256:43e0a7fd25483c7b6d8889d892ac353d4e3f137a6c681b871269b67b2d4b5ec2
    Status: Image is up to date for anchore/anchore-engine:v0.8.1


    Repo name: docker.io
    Base image name: node
    Tag name: 10

    Image id: 2457d5f85d32212d0f80913876bb7c2fdc51cfdbc34c8841390b0e2cabb5fcbf

    using full image name: docker.io/node:10
    Saving node:10 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/sysdig-inline-scan-1603910214/node:10.tar
    Analysis complete for image sha256:f67d6f3fd49cf4797dec6c9aa950be8a344aed88f0928adc92e3eae618a78ae0 - archive file is located at /tmp/image-analysis-archive.tgz
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/node:10 fulldigest=docker.io/node@sha256:f67d6f3fd49cf4797dec6c9aa950be8a344aed88f0928adc92e3eae618a78ae0
    Analysis complete!

    Sending analysis archive to https://secure.sysdig.com/api/scanning/v1
    Calling sync import endpoint
    Scan Report - 
    [
      {
        "sha256:636ef87129d69cb758968d81123a1d15a521a24eeab35c2d63ebb41c0f87b0ad": {
          "docker.io/node:10": [
            {
              "detail": {},
              "last_evaluation": "2020-10-29T22:09:02Z",
              "policyId": "default",
              "status": "fail"
            }
          ]
        }
      }
    ]
    
    Status is fail

    View the full result @ https://secure.sysdig.com/#/scanning/scan-results/docker.io%2Fnode%3A10/sha256:f67d6f3fd49cf4797dec6c9aa950be8a344aed88f0928adc92e3eae618a78ae0/summaries
    PDF report of the scan results can be generated with -R option.

    Cleaning up docker container: 195d1fb4677daf99d3f1f6749d0f53121d424ff616fe10575be1b6135ac001f9
    Removing temporary folder created /tmp/sysdig/sysdig-inline-scan-1603910214
    [Pipeline] }
    [Pipeline] // stage
    [Pipeline] }
    [Pipeline] // withEnv
    [Pipeline] }
    [Pipeline] // node
    [Pipeline] End of Pipeline
    ERROR: script returned exit code 1
    Finished: FAILURE