# Jenkins pipeline integration

The following are the log outputs for a successful / failure run when used in Jenkins pipeline.
Success / Failure status is based on image policies configured in Sysdig Secure.

## Build Success

    + curl -s https://raw.githubusercontent.com/sysdiglabs/secure-inline-scan/master/inline_scan.sh
    + bash -s analyze -s https://secure.sysdig.com -k <token> -P docker.io/alpine:3.7
    Pulling image -- docker.io/alpine:3.7
    3.7: Pulling from library/alpine
    Digest: sha256:8421d9a84432575381bfabd248f1eb56f3aa21d9d7cd2511583c68c9b7511d10
    Status: Image is up to date for alpine:3.7
    docker.io/library/alpine:3.7
    
    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Saving docker.io/alpine:3.7 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/alpine:3.7.tar
    
    Analyzing docker.io/alpine:3.7...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/alpine:3.7 fulldigest=docker.io/alpine@sha256:6d1ef012b5674ad8a127ecfa9b5e6f5178d171b90ee462846974177fd9bdd39f
     Analysis complete!
    
    Sending analysis archive to https://secure-staging2.sysdig.com/api/scanning/v1
    Scan Report - 
    [
      {
        "sha256:6d1ef012b5674ad8a127ecfa9b5e6f5178d171b90ee462846974177fd9bdd39f": {
          "docker.io/alpine:3.7": [
            {
              "detail": {},
              "last_evaluation": "2019-10-16T22:17:59Z",
              "policyId": "default",
              "status": "pass"
            }
          ]
        }
      }
    ]
    
    Status is pass
    
    Cleaning up docker container: 484bc6eb987bba77ec12473dc83bcdcd8db93b24d40c9450270bcba2f319145e
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
    Pulling image -- docker.io/node:10
    10: Pulling from library/node
    Digest: sha256:a2bc0489b71f88b358d2ed66efe0025b1896032ca6fd52df780426ce1acd18be
    Status: Image is up to date for node:10
    docker.io/library/node:10
    
    Using local image for scanning -- docker.io/anchore/inline-scan:v0.5.0
    Saving docker.io/node:10 for local analysis
    Successfully prepared image archive -- /tmp/sysdig/node:10.tar
    
    Analyzing docker.io/node:10...
    [MainThread] [anchore_manager.cli.analyzers/exec()] [INFO] using fulltag=docker.io/node:10 fulldigest=docker.io/node@sha256:636ef87129d69cb758968d81123a1d15a521a24eeab35c2d63ebb41c0f87b0ad
     Analysis complete!
    
    Sending analysis archive to https://secure-staging2.sysdig.com/api/scanning/v1
    Scan Report - 
    [
      {
        "sha256:636ef87129d69cb758968d81123a1d15a521a24eeab35c2d63ebb41c0f87b0ad": {
          "docker.io/node:10": [
            {
              "detail": {},
              "last_evaluation": "2019-10-16T22:09:02Z",
              "policyId": "default",
              "status": "fail"
            }
          ]
        }
      }
    ]
    
    Status is fail
    
    Cleaning up docker container: 28e713d7c1fd8e832f92e2ea8b5d9175b0b90400ec2ef01c982acd62f0a536e0
    [Pipeline] }
    [Pipeline] // stage
    [Pipeline] }
    [Pipeline] // withEnv
    [Pipeline] }
    [Pipeline] // node
    [Pipeline] End of Pipeline
    ERROR: script returned exit code 1
    Finished: FAILURE