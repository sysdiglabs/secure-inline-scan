# Google Cloud Build

`cloudbuild.yaml` contains an example for a workflow for Google Cloud Build with these steps:

* Build the docker image for the current repo
* Get the secret value for Sysdig Secure API Token
* Execute Sysdig inline image scanner, stop the workflow if it fails
* Push the image to a registry

![Cloud Build workflow with Sysdig inline image scanning](cloud-build-workflow-inline-scan.drawio.svg)

## References

More details on Sysdig blog article: https://sysdig.com/blog/securing-google-cloud-run/
