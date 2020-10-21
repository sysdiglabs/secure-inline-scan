# Tekton inline scanning with Sysdig

This repository contains instructions and examples of how to use Sysdig inline scanning to detect vulnerabilities and misconfiguration in a Tekton CI/CD pipeline, using the **alpha** and **beta** Tekton API.

They have been tested and can be used for **vanilla Kubernetes** as well as on **OpenShift**, as Sysdig inline scanning doesn't require a privileged container.

For more information about Sysdig, visit [https://sysdig.com](https://sysdig.com).

## Inline Image Scanning

Sysdig inline image sanning can be used in Tekton, without requiring a docker-in-docker setup, mounting the Docker socket or privileged access.

You have to define a scanning step after building an image in a Tekton task, so it then scans a local folder with the image contents in OCI format, without pushing it to a registry or sending the image contents to Sysdig backend. This is a brief code extract for how to do it (for Tekton v1beta1 API):

```yaml
  - name: scan
    image: sysdiglabs/secure-inline-scan:2
    args:
      - --storage-type
      - oci-dir
      - --storage-path
      - /workspace/oci
      - -s
      - https://secure.sysdig.com
      - $(outputs.resources.builtImage.url)
    env:
      - name: SYSDIG_API_TOKEN
        valueFrom:
          secretKeyRef:
            name: sysdig-secrets
            key: sysdig-secure-api-key
```

You'll need to add a secret for your Sysdig Secure API token, and reference it in the service account definition that executes the pipeline, as you can see in the [full pipeline example for beta Tekton API](./beta/tekton-inline-scan-localbuild-beta.yaml).

## Build-scan-push Tekton Task

The example pipeline describen in the [official Tekton tutorial](https://github.com/tektoncd/pipeline/blob/master/docs/tutorial.md) uses `kaniko` to build and push the image in a single step. 

To have a task that builds the image, scans it locally, and only pushes it to the registry if it is in compliance with scanning policies, we have to tell `kaniko` in the first step to not push the image, and add a last additional step to push it using `skopeo` (as `kaniko` can't push an image without rebuilding it, which would waste resources).

```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: build-docker-image-from-git-source
spec:
  params:
    - name: pathToDockerFile
      type: string
      description: The path to the dockerfile to build
      default: $(resources.inputs.docker-source.path)/Dockerfile
    - name: pathToContext
      type: string
      description: |
        The build context used by Kaniko
        (https://github.com/GoogleContainerTools/kaniko#kaniko-build-contexts)
      default: $(resources.inputs.docker-source.path)
  resources:
    inputs:
      - name: docker-source
        type: git
    outputs:
      - name: builtImage
        type: image
  steps:
    - name: build
      image: gcr.io/kaniko-project/executor:v0.16.0
      command:
        - /kaniko/executor
      args:
        - --dockerfile=$(params.pathToDockerFile)
        - --destination=$(resources.outputs.builtImage.url)
        - --context=$(params.pathToContext)
        - --oci-layout-path=/workspace/oci
        - --no-push

    - name: scan
      image: sysdiglabs/secure-inline-scan:2
      args:
        - --storage-type
        - oci-dir
        - --storage-path
        - /workspace/oci
        - -s
        - https://secure.sysdig.com
        - $(outputs.resources.builtImage.url)
      env:
        - name: SYSDIG_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: sysdig-secrets
              key: sysdig-secure-api-key

    - name: push
      image: quay.io/skopeo/stable:v1.1.1
      command:
        - /usr/bin/skopeo
      args:
        - --insecure-policy
        - --dest-authfile
        - /tekton/home/.docker/config.json
        - copy
        - oci:/workspace/oci/
        - docker://$(outputs.resources.builtImage.url)

```

## Full pipeline examples with inline scanning for alpha and beta Tekton API

You can find full pipelines examples for both **alpha** and **beta** Tekton API in the following files of this repo:

* [pipeline-example-alpha.yaml](./alpha/tekton-inline-scan-localbuild-alpha.yaml).
* [pipeline-example-beta.yaml](./beta/tekton-inline-scan-locallbuild-beta.yaml).

They are quite similar, but each derives from the tutorial examples given for those versions of the API. Main difference is how registry credential secrets were recommended to be handled, but the task for build-scan-push is almost identical.

### Tekton beta API example

Follow these steps to test the Tekton beta API example from this repo.

```console
oc new-project tekton-pipelines
oc adm policy add-scc-to-user anyuid -z tekton-pipelines-controller
```

* Modify `beta/sample-registry-secrets.sh` script with your registry credentials.
* Modify `beta/sample-sysdig-secrets.yaml` and paste your Sysdig Secure API key.
* Modify `beta/tekton-inlin-scan-beta.yaml` file, at line 32 substitude `index.docker.io/your_user/leeroy-web` for the image tag you want to use on your registry account.

If you use OpenShift instead of Kubernetes, execute these commands to create a project and specify anyuid to the Tekton pipeline controller so it can run containers with root user (required by Tekton).

```bash
oc new-project tekton-pipelines
oc ad

* Execute these commands:

```bash
# Deploy Tekton v0.16.3
kubectl apply -f https://github.com/tektoncd/pipeline/releases/download/v0.16.3/release.notags.yaml

# Deploy Dashboard v0.9.0
kubectl apply -f https://github.com/tektoncd/dashboard/releases/download/v0.9.0/tekton-dashboard-release.yaml

# Check that Tekton and dashboard pod status are ready
kubectl get pods -n tekton-pipelines

# Prepare example
cd beta
./sample-registry-secrets-beta.sh
kubectl apply -f sample-sysdig-secrets.yaml -n tekton-pipelines
./service-role.sh

# Execute example
kubectl create -f tekton-inline-scan-localbuild-beta.yaml -n tekton-pipelines

# Open proxy connection to dashboard
kubectl port-forward svc/tekton-dashboard -n tekton-pipelines 9097:9097

# Browse dashboard web page at http://[::1]:9097
```

### Tekton alpha API example

Follow these steps to test the Tekton beta API example from this repo.

* Modify `alpha/sample-registry-secrets-beta.yaml` file with your registry credentials.
* Modify `alpha/sample-sysdig-secrets.yaml` and paste your Sysdig Secure API key.
* Modify `alpha/tekton-inlin-scan-alpha.yaml` file, at line 153 substitude `docker.io/username/leeroy-web2a` for the image tag you want to use on your registry account.

If you use OpenShift instead of Kubernetes, execute these commands to create a project and specify anyuid to the Tekton pipeline controller so it can run containers with root user (required by Tekton).

```bash
oc new-project tekton-pipelines
oc adm policy add-scc-to-user anyuid -z tekton-pipelines-controller
```

* Execute these commands:

```bash
# Deploy Tekton v0.10.2
kubectl apply -f https://github.com/tektoncd/pipeline/releases/download/v0.10.2/release.notags.yaml

# Deploy Dashboard v0.5.1
kubectl apply -f https://github.com/tektoncd/dashboard/releases/download/v0.5.1/tekton-dashboard-release.yaml

# Check that Tekton and dashboard pod status are ready
kubectl get pods -n tekton-pipelines

# Prepare example
cd alpha
kubectl apply -f sample-registry-secrets.yaml
kubectl apply -f sample-sysdig-secrets.yaml

# Execute example
kubectl apply -f tekton-inline-scan-localbuild-localbuild-alpha.yaml

# Open proxy connection to dashboard
kubectl port-forward svc/tekton-dashboard -n tekton-pipelines 9097:9097

# Browse dashboard web page at http://[::1]:9097
```

## References

* [Sysdig Inline Scan](https://github.com/sysdiglabs/secure-inline-scan), _code repository_ and _direct project documentation_. This is the main source of truth for Sysdig inline scanning.
* [Inline Scanning](https://docs.sysdig.com/en/integrate-with-ci-cd-tools.html#UUID-8945ddee-8c45-58b4-7d85-e06c4235d03c_UUID-5d107c7b-457e-3862-51b5-01bdd9699105), _Sysdig Documentation Hub_.
* [Securing Tekton pipelines in OpenShift with Sysdig](https://sysdig.com/blog/securing-tekton-pipelines-openshift/), _blogpost_.
  ⚠**Deprecated information**.

