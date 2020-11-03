#!/usr/bin/env bash

set -eou pipefail

########################
### GLOBAL VARIABLES ###
########################

# Required for tekton which overrides $HOME variables
export HOME=/home/anchore

ANALYZE_CMD=()
SCAN_IMAGE=""
VALIDATED_OPTIONS=""
# Vuln scan option variable defaults
DOCKERFILE=""
TMP_PATH="/tmp/sysdig"
DEST_IMAGE_PATH="${TMP_PATH}/oci-image"
# Analyzer option variable defaults
SYSDIG_BASE_SCANNING_URL="https://secure.sysdig.com"
SYSDIG_BASE_SCANNING_API_URL="https://api.sysdigcloud.com"
SYSDIG_SCANNING_URL="http://localhost:9040/api/scanning"
SYSDIG_ANCHORE_URL="http://localhost:9040/api/scanning/v1/anchore"
SYSDIG_ANNOTATIONS=""
SYSDIG_IMAGE_DIGEST="sha256:123456890abcdefg"
SYSDIG_IMAGE_ID="123456890abcdefg"
MANIFEST_FILE="./manifest.json"
PDF_DIRECTORY="$PWD"
GET_CALL_STATUS=''
GET_CALL_RETRIES=300
DETAIL=false
SKOPEO_REGISTRY_CONF=()
SKOPEO_AUTH=(--authfile /config/auth.json)
SKOPEO_COPY_AUTH=(--authfile /config/auth.json)
CURL_FLAGS=""
declare -A TIME_PROFILE

exit_with_error() {
    if [[ -z "${silent_flag:-}" ]]; then
        printf "\nERROR:\n%b\n\n" "$1" >&2
    fi
    if [[ -n "${json_flag:-}" ]]; then
        jq -n --arg error "$1" --rawfile log "${TMP_PATH}"/info.log '{status: "error", error: $error, log: $log}' 2>&1 || printf "\nERROR:\n%b\n\n" "$1" >&2
    fi
    exit 3
}

print_info() {
    if [[ -z "${silent_flag:-}" ]]; then
        echo "$1" | tee -a ${TMP_PATH}/info.log
    else
        echo "$1" >> ${TMP_PATH}/info.log
    fi
}

print_info_pipe() {
    INDENT=${1:-}
    while IFS= read -r line; do print_info "${INDENT}${line}"; done
    print_info "${INDENT}${line}"
}


display_usage_short() {
cat >&2 << EOF
Use -h or --help to display usage
EOF

}

display_usage() {
    cat >&2 << EOF
Sysdig Inline Analyzer -- USAGE

  Container for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Usage: ${0##*/} -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

    == GLOBAL OPTIONS ==

    -k <TEXT>   [required] API token for Sysdig Scanning auth
                (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
                Alternatively, set environment variable SYSDIG_API_TOKEN
                Alias: --sysdig-token
    -s <URL>    [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com).
                Alias: --sysdig-url
    --sysdig-skip-tls
                [optional] skip tls verification when calling secure endpoints
    -o          [optional] Use this flag if targeting onprem sysdig installation
                Alias: --on-prem
    -a <TEXT>   [optional] Add annotations (ex: -a 'key=value,key=value')
                Alias: --annotations
    -f <PATH>   [optional] Path to Dockerfile (ex: -f ./Dockerfile)
                Alias: --dockerfile
    -m <PATH>   [optional] Path to Docker image manifest (ex: -m ./manifest.json)
                Alias: --manifest
    -i <TEXT>   [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
                Alias: --image-id
    -d <SHA256> [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
                Alias: --digest
    -c          [optional] Remove the image from Sysdig Secure if the scan fails
    -r <PATH>   [optional] Download scan result pdf in a specified local directory (ex: -r /staging/reports)
                Alias: --report-folder
    -v          [optional] Increase verbosity
                Alias: --verbose
    --format <FORMAT>
                [optional] Set output format. Available formats are:

                JSON  Write a valid JSON which can be processed in an automated way

                (Others formats might be included in the future)
    --time-profile
                Output information about the time elapsed in the different stages of the scan process


    == IMAGE SOURCE OPTIONS ==

    [default] If --storage-type is not specified, pull container image from registry.
            
        == REGISTRY AUTHENTICATION ==
        
        When pulling from the registry,
        the credentials in the config file located at /config/auth.json will be
        used (so you can mount a docker config.json file, for example).
        Alternatively, you can provide authentication credentials with:
        --registry-auth-basic username:password  Authenticate using this Bearer <Token>
        --registry-auth-token <TOKEN>            Authenticate using this Bearer <Token>
        --registry-auth-file  <PATH>             Path to file with registry credentials, default /config/auth.json

        == TLS OPTIONS ==

        -n                    Skip TLS certificate validation when pulling image

    --storage-type <SOURCE-TYPE> 

        Where <SOURCE-TYPE> can be one of:

        docker-daemon   Get the image from the Docker daemon.
                        Requires /var/run/docker.sock to be mounted in the container
        cri-o           Get the image from containers-storage (CRI-O and others).
                        Requires mounting /etc/containers/storage.conf and /var/lib/containers
        docker-archive  Image is provided as a Docker .tar file (from docker save).
                        Tarfile must be mounted inside the container and path set with --storage-path
        oci-archive     Image is provided as a OCI image tar file.
                        Tarfile must be mounted inside the container and path set with --storage-path
        oci-dir         Image is provided as a OCI image, untared.
                        The directory must be mounted inside the container and path set with --storage-path

    --storage-path <PATH>   Specifies the path to the source of the image to scan, that has to be 
                            mounted inside the container, it is required if --storage-type is set to 
                            docker-archive, oci-archive or oci-dir

    == EXIT CODES ==

    0   Scan result "pass"
    1   Scan result "fail"
    2   Wrong parameters
    3   Error during execution

EOF
}

main() {
    trap 'cleanup' EXIT ERR SIGTERM
    trap 'interupt' SIGINT

    get_and_validate_analyzer_options "$@"
    SCAN_IMAGE="${VALIDATED_OPTIONS[0]}" 
    touch "${TMP_PATH}"/info.log
    check_dependencies
    inspect_image
    start_analysis
    display_report
}

get_and_validate_analyzer_options() {
    RETCODE=0
    PARSED_ARGS=$(getopt -n "ERROR" -o k:s:a:f:i:d:m:ocvr:hn:l: --long help,format:,registry-auth-token:,registry-auth-basic:,registry-auth-file:,storage-type:,storage-path:,sysdig-token:,sysdig-url:,sysdig-skip-tls,annotations:,dockerfile:,image-id:,digest:,manifest:,on-prem,verbose,report-folder:,registry-skip-tls,time-profile -- "$@") || RETCODE=$?

    if [ "$RETCODE" != "0" ]; then
        printf "\n" >&2
        display_usage_short
        exit 2
    fi

    eval set -- "$PARSED_ARGS"

    #Parse options
    while :
    do
        case "$1" in
            -h | --help) display_usage; exit;;
            -k | --sysdig-token ) SYSDIG_API_TOKEN="$2"; shift 2;;
            -s | --sysdig-url ) SYSDIG_BASE_SCANNING_URL="${2%%}"; SYSDIG_BASE_SCANNING_API_URL="${SYSDIG_BASE_SCANNING_URL}"; shift 2;;
            --sysdig-skip-tls ) CURL_FLAGS="-k"; shift;;
            -a | --annotations ) SYSDIG_ANNOTATIONS="$2"; shift 2;;
            -f | --dockerfile ) DOCKERFILE="$2"; shift 2;;
            -i | --image-id ) i_flag=true; SYSDIG_IMAGE_ID="$2"; shift 2;;
            -d | --digest ) d_flag=true; SYSDIG_IMAGE_DIGEST="$2"; shift 2;;
            -m | --manifest ) m_flag=true; MANIFEST_FILE="$2"; shift 2;;
            -o | --on-prem ) o_flag=true; shift;;
            -c ) clean_flag=true; shift;;
            -v | --verbose ) v_flag=true; DETAIL=true; shift;;
            -r | --report-folder ) r_flag=true; PDF_DIRECTORY="$2"; shift 2;;
            -n | --registry-skip-tls ) n_flag=true; shift;;
            --registry-auth-basic ) SKOPEO_AUTH=(--creds "$2"); SKOPEO_COPY_AUTH=(--src-creds "$2"); shift 2;;
            --registry-auth-token ) SKOPEO_AUTH=(--registry-token "$2"); SKOPEO_COPY_AUTH=(--src-registry-token "$2"); shift 2;;
            --registry-auth-file  ) SKOPEO_AUTH=(--authfile "$2"); SKOPEO_COPY_AUTH=(--src-authfile "$2"); shift 2;;
            --storage-type )
                case "$2" in
                    docker-daemon ) D_flag=true;;
                    cri-o ) C_flag=true;;
                    docker-archive ) T_flag=true;;
                    oci-archive ) O_flag=true;;
                    oci-dir ) U_flag=true;;
                    * )
                        printf "ERROR: unsupported storage type '%s'\n\n" "$2" >&2
                        display_usage_short
                        exit 2
                        ;;
                esac
                shift 2
                ;;
            --storage-path ) SOURCE_PATH="$2"; shift 2;;
            --format )
                case "$2" in
                    JSON )
                        json_flag=true
                        silent_flag=true
                        DETAIL=true
                        ;;
                    * )
                        printf "ERROR: unsupported output format '%s'\n\n" "$2" >&2
                        display_usage_short
                        exit 2
                        ;;
                esac
                shift 2
                ;;
            --time-profile ) time_flag=true; shift;;
            --) shift; break ;;
            *) printf "ERROR: Unexpected option: %s - this should not happen.\n" "$1"; exit 2;;
        esac
    done

    SYSDIG_SCANNING_URL="${SYSDIG_BASE_SCANNING_API_URL}"/api/scanning/v1
    SYSDIG_ANCHORE_URL="${SYSDIG_SCANNING_URL}"/anchore

    # Check for invalid options
    if [[ "${#@}" -gt 1 ]]; then
        printf "ERROR: only 1 image can be analyzed at a time\n\n" >&2
        display_usage_short
        exit 2
    elif [[ "${#@}" -lt 1 ]]; then
        printf "ERROR: must specify an image to analyze\n\n" >&2
        display_usage_short
        exit 2
    elif [[ ! "${SYSDIG_API_TOKEN:-}" ]]; then
        printf "ERROR: must provide the Sysdig Secure API token\n\n" >&2
        display_usage_short
        exit 2
    elif [[ "${SYSDIG_BASE_SCANNING_URL: -1}" == '/' ]]; then
        printf "ERROR: must specify Sysdig url - %s without trailing slash\n\n" "${SYSDIG_BASE_SCANNING_URL}" >&2
        display_usage_short
        exit 2
    elif [[ "${d_flag:-}" && ${SYSDIG_IMAGE_DIGEST} != *"sha256:"* ]]; then
        printf "ERROR: must specify a valid sha256:<digestID>: %s\n\n" "${SYSDIG_IMAGE_DIGEST}" >&2
        display_usage_short
        exit 2
    elif [[ "${r_flag:-}" ]] && [[ "${PDF_DIRECTORY: -1}" == '/' ]]; then
        printf "ERROR: must specify file path - %s without trailing slash\n\n" "${PDF_DIRECTORY}" >&2
        display_usage_short
        exit 2
    elif [[ -n "${T_flag:-}" ]] || [[ -n "${O_flag:-}" ]]|| [[ -n "${U_flag:-}" ]]; then
        if [[ -z "${SOURCE_PATH:-}" ]]; then
            printf "ERROR: must specify storage path with option --storage-path\n\n" >&2
            display_usage_short
            exit 2
        fi
    fi

    if [[ "${v_flag:-}" ]]; then
        set -x
    fi

    if [[ -n "${SYSDIG_ANNOTATIONS}" ]]; then
        # transform all commas to spaces & cast to an array
        local annotation_array
        IFS=" " read -r -a annotation_array <<< "${SYSDIG_ANNOTATIONS//,/ }"
        # get count of = in annotation string
        local number_keys=${SYSDIG_ANNOTATIONS//[^=]}
        # compare number of elements in array with number of = in annotation string
        if [[ "${#number_keys}" -ne "${#annotation_array[@]}" ]]; then
            exit_with_error "${SYSDIG_ANNOTATIONS} is not a valid input for -a option"
        fi
    fi

    TMP_PATH="${TMP_PATH}/sysdig-inline-scan-$(date +%s)"
    mkdir -p "${TMP_PATH}"
    if [[ "${v_flag:-}" ]]; then
        print_info "Using temporary path ${TMP_PATH}"
    fi

    VALIDATED_OPTIONS=( "$@" )
}

time_start() {
    if [[ -n "${time_flag:-}" ]]; then
        TIME_PROFILE[$1]=$(date +%s%3N)
    fi
}

time_end() {
    if [[ -n "${time_flag:-}" ]]; then
        END=$(date +%s%3N)
        print_info "Time elapsed($1): $((END - TIME_PROFILE[$1]))ms"
    fi
}

check_dependencies() {

    if command -v sha256sum >/dev/null 2>&1; then
        SHASUM_COMMAND="sha256sum"
    else
        if command -v shasum >/dev/null 2>&1; then
            SHASUM_COMMAND="shasum -a 256"
        else
            exit_with_error "sha256sum or shasum command is required but missing"
        fi
    fi

    if [[ ! $(which skopeo) ]]; then
        # shellcheck disable=SC2016
        exit_with_error 'Skopeo is not installed or cannot be found in $PATH'
    elif ! curl -sS ${CURL_FLAGS} -o /dev/null --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/anchore/status" 2> "${TMP_PATH}"/curl.err; then
        exit_with_error "Invalid token for specific Sysdig secure endpoint (${SYSDIG_SCANNING_URL}).\n$(cat "${TMP_PATH}"/curl.err)"
    elif [[ -n "${DOCKERFILE:-}" ]] && [[ ! -f "${DOCKERFILE}" ]]; then
        exit_with_error "Dockerfile ${DOCKERFILE} does not exist"
    elif [[ "${m_flag:-}" ]] && [[ ! -f "${MANIFEST_FILE}" ]];then
        exit_with_error "Manifest ${MANIFEST_FILE} does not exist"
    elif [[ "${r_flag:-}" ]] && [[ ! -d "${PDF_DIRECTORY}" ]];then
        exit_with_error "Directory ${PDF_DIRECTORY} does not exist"
    fi

    if [[ "${D_flag:-false}" == true ]]; then
        # Make sure we can access the docker sock...
        DOCKERGID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null) || exit_with_error "Cannot access /var/run/docker.sock"
        #  ...by changing the group of skopeo, which has "setgid" flag
        sudo /usr/bin/chgrp "${DOCKERGID}" /usr/bin/skopeo
        sudo /usr/bin/chmod g+s /usr/bin/skopeo
    fi
}

inspect_image() {
    # Skopeo requires specifying a tag
    TAG=$(echo "${SCAN_IMAGE}" | cut -d : -s -f 2)
    if [[ -n "${TAG// }" ]]; then
        IMAGE_NAME=${SCAN_IMAGE}
    else
        IMAGE_NAME="${SCAN_IMAGE}:latest"
    fi

    if [[ "${n_flag:-false}" == true ]]; then
        # Allow pull from insecure registries
        SKOPEO_REGISTRY_CONF=(--registries-conf="${TMP_PATH}"/registries.conf)
        cat > "${TMP_PATH}"/registries.conf <<EOF
[[registry]]
location = "$(echo ${IMAGE_NAME} | cut -d '/' -f 1)"
insecure = true
EOF
    fi

    # Make sure image is available locally
    if [[ "${T_flag:-false}" == true ]]; then
        print_info "Inspecting image from Docker archive file -- ${SOURCE_PATH}"
        SOURCE_IMAGE="docker-archive:${SOURCE_PATH}"
    elif [[ "${O_flag:-false}" == true ]]; then
        SOURCE_IMAGE="oci-archive:${SOURCE_PATH}"
        print_info "Inspecting image from OCI archive file -- ${SOURCE_PATH}"
    elif [[ "${U_flag:-false}" == true ]]; then
        print_info "Inspecting image from OCI directory -- ${SOURCE_PATH}"
        SOURCE_IMAGE="oci:${SOURCE_PATH}"
        # Avoid a 'skopeo copy' command
        DEST_IMAGE_PATH=${SOURCE_PATH}
    elif [[ "${C_flag:-false}" == true ]]; then
        print_info "Inspecting image from containers-storage -- ${IMAGE_NAME}"
        SOURCE_IMAGE="containers-storage:${IMAGE_NAME}"
    elif [[ "${D_flag:-false}" == true ]]; then
        print_info "Inspecting image from Docker daemon -- ${IMAGE_NAME}"
        SOURCE_IMAGE="docker-daemon:${IMAGE_NAME}"
    else
        print_info "Inspecting image from remote repository -- ${IMAGE_NAME}"
        SOURCE_IMAGE="docker://${IMAGE_NAME}"
    fi 
    time_start "Get manifest"
    MANIFEST=$(skopeo inspect "${SKOPEO_REGISTRY_CONF[@]}" "${SKOPEO_AUTH[@]}" --raw "${SOURCE_IMAGE}" 2> "${TMP_PATH}"/err.log) || find_image_error "${IMAGE_NAME}"
    time_end "Get manifest"
    time_start "Inspect image"
    INSPECT=$(skopeo inspect "${SKOPEO_REGISTRY_CONF[@]}" "${SKOPEO_AUTH[@]}" "${SOURCE_IMAGE}" 2> "${TMP_PATH}"/err.log) || find_image_error "${IMAGE_NAME}"
    time_end "Inspect image"

    FULL_IMAGE_NAME=$(echo -n "${INSPECT}" | jq -r .Name 2> "${TMP_PATH}"/err.log || exit_with_error "Parsing inspect JSON document.\n$(cat "${TMP_PATH}"/err.log)")
    REPO_TAG=$(echo -n "${INSPECT}" | jq -r '.RepoTags[0] // empty')
    if [[ ! "${i_flag-""}" ]]; then
        MANIFEST_TYPE=$(echo -n "${MANIFEST}" | jq -r .mediaType)
        if [[ "${MANIFEST_TYPE}" == "application/vnd.docker.distribution.manifest.list.v2+json" ]]; then
            # If we have retrieved a manifest list, resolve to the linux/amd64 manifest hash and check config from there
            PLATFORM_DIGEST=$(echo "${MANIFEST}" | jq -r '.manifests[] | select((.platform.os == "linux") and (.platform.architecture == "amd64")) | .digest')
            time_start "Get child manifest"
            REAL_MANIFEST=$(skopeo inspect "${SKOPEO_REGISTRY_CONF[@]}" "${SKOPEO_AUTH[@]}" --raw docker://"${FULL_IMAGE_NAME}@${PLATFORM_DIGEST}")
            time_end "Get child manifest"
            SYSDIG_IMAGE_ID=$(echo -n "${REAL_MANIFEST}" | jq -r '.config.digest // empty' | cut -f2 -d ":" )
        else
            #TODO(airadier): Probably this works, but the later OCI config digest will differ from the docker or other sources config digest
            SYSDIG_IMAGE_ID=$(echo -n "${MANIFEST}" | jq -r '.config.digest // empty' | cut -f2 -d ":" )
        fi
    fi

    # Calculate "repo digest" from the RAW manifest
    REPO_DIGEST=$(echo -n "${MANIFEST}" | ${SHASUM_COMMAND} | cut -d ' ' -f 1)
}

convert_image() {
    if [[ "${SOURCE_IMAGE}" != "oci:${DEST_IMAGE_PATH}" ]]; then
        print_info "Converting image..."
        time_start "Convert image"
        skopeo copy "${SKOPEO_REGISTRY_CONF[@]}" "${SKOPEO_COPY_AUTH[@]}" "${SOURCE_IMAGE}" "oci:${DEST_IMAGE_PATH}" 2> "${TMP_PATH}"/err.log | print_info_pipe "  " || find_image_error "${IMAGE_NAME}"
        time_end "Convert image"
    fi
}

find_image_error() {
    exit_with_error "Failed to retrieve the image specified in script input - $1.\nPlease pull remote image, or build/tag all local images before attempting analysis again.\n$(cat "${TMP_PATH}"/err.log)"
}

start_analysis() {

    if [[ ! "${d_flag-""}" ]]; then
        SYSDIG_IMAGE_DIGEST="sha256:${REPO_DIGEST}"
    fi

    FULLTAG="${SCAN_IMAGE}"

    if [[ "${FULLTAG}" =~ "@sha256:" ]]; then
        FULLTAG=$(echo "${FULLTAG}" | awk '{ gsub("@sha256:.*", ":latest"); print $0}')
    elif [[ ! "${FULLTAG}" =~ [:]+ ]]; then
        FULLTAG="${FULLTAG}:latest"
    fi

    if [[ -z ${REPO_TAG} ]]; then
        # local built image, has not digest and refers to no registry
        FULLTAG="localbuild/${FULLTAG}"
    else
        # switch docker.io vs rest-of-the-world registries
        # Note: FULL_IMAGE_NAME comes from Skopeo and already includes `docker.io` if it's a legit dockerhub image
        if [[ "${FULL_IMAGE_NAME}" =~ ^docker.io* ]] && [[ ! "${FULLTAG}" =~ ^docker.io* ]]; then
            # Forcing docker.io registry
            FULLTAG="docker.io/${FULLTAG}"
        else
            FULLTAG="${FULLTAG}"
        fi
    fi

    print_info "  Full image:  ${FULL_IMAGE_NAME}"
    print_info "  Full tag:    ${FULLTAG}"
    print_info "  Repo digest: ${SYSDIG_IMAGE_DIGEST}"
    print_info "  Image id:    ${SYSDIG_IMAGE_ID}"

    time_start "Check scan status"
    get_scan_result
    time_end "Check scan status"

    if [[ "${GET_CALL_STATUS}" != 200 ]]; then
        convert_image
        perform_analysis
        post_analysis
        get_scan_result_with_retries
    else
        print_info "Image digest found on Sysdig Secure, skipping analysis."
    fi
}

perform_analysis() {
    export ANCHORE_DB_HOST=x
    export ANCHORE_DB_USER=x
    export ANCHORE_DB_PASSWORD=x 

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('anchore-manager analyzers exec ${DEST_IMAGE_PATH} ${TMP_PATH}/image-analysis-archive.tgz')

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('--digest "${SYSDIG_IMAGE_DIGEST}" --image-id "${SYSDIG_IMAGE_ID}"')

    if [[ -n "${SYSDIG_ANNOTATIONS}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--annotation "${SYSDIG_ANNOTATIONS},added-by=sysdig-inline-scanner"')
    else
        ANALYZE_CMD+=('--annotation "added-by=sysdig-inline-scanner"')
    fi
    if [[ "${m_flag-""}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--manifest "${MANIFEST_FILE}"')
    fi
    if [[ -n "${DOCKERFILE}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--dockerfile "${DOCKERFILE}"')
    fi
    if [[ "${v_flag-""}" ]]; then
        export ANCHORE_CLI_DEBUG=y
    fi

    # finally, get the account from Sysdig for the input username
    HCODE=$(curl -sS ${CURL_FLAGS} -o "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account" 2> /dev/null)
    if [[ "${HCODE}" == 404 ]]; then
	    HCODE=$(curl -sS ${CURL_FLAGS} -o "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account" 2> /dev/null)
    fi

    if [[ "${HCODE}" == 200 ]] && [[ -f "${TMP_PATH}/sysdig_output.log" ]]; then
        # shellcheck disable=SC2034
        ANCHORE_ACCOUNT=$(jq -r '.name' "${TMP_PATH}/sysdig_output.log")
        # shellcheck disable=SC2016
	    ANALYZE_CMD+=('--account-id "${ANCHORE_ACCOUNT}"')
    else
        exit_with_error "Unable to fetch account information from anchore-engine for specified user\n***SERVICE RESPONSE  - Code ${HCODE}****\n$(cat "${TMP_PATH}"/sysdig_output.log 2> /dev/null)\n***END SERVICE RESPONSE****"
    fi

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('--tag "${FULLTAG}"')

    print_info "Analyzing image..."
    time_start "Analyze image"
    eval "${ANALYZE_CMD[*]}" > "${TMP_PATH}"/analyze.out 2>&1 || true
    time_end "Analyze image"

    if [[ -f "${TMP_PATH}/image-analysis-archive.tgz" ]]; then
        if [[ "${v_flag:-}" ]]; then
            print_info_pipe "  " < "${TMP_PATH}"/analyze.out
        fi
        print_info "Analysis complete!"
    else
        exit_with_error "Cannot find image analysis archive. An error occured during analysis.\n$(cat "${TMP_PATH}"/analyze.out)"
    fi
}

post_analysis() {
    # Posting the archive to the secure backend (sync import)
    print_info "Sending analysis result to Secure backend"
    time_start "Post analysis - sync"
    HCODE=$(curl -sS ${CURL_FLAGS} -o "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/sync/import/images" 2> /dev/null)
    time_end "Post analysis - sync"

    if [[ "${HCODE}" != 200 ]]; then
        if [[ "${HCODE}" == 404 ]]; then
            # Posting the archive to the secure backend (async import)
            print_info "  Calling async import endpoint"
            time_start "Post analysis - async"
            HCODE=$(curl -sS ${CURL_FLAGS} -o "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images" 2> /dev/null)
            time_end "Post analysis - async"
            if [[ "${HCODE}" != 200 ]]; then
                exit_with_error "Unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/import/images\n***SERVICE RESPONSE - Code ${HCODE}****\n$(cat "${TMP_PATH}"/sysdig_output.log 2> /dev/null)\n***END SERVICE RESPONSE****"
            fi
            return
        fi
        exit_with_error "Unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/sync/import/images\n***SERVICE RESPONSE - Code ${HCODE}****\n$(cat "${TMP_PATH}"/sysdig_output.log 2> /dev/null)\n***END SERVICE RESPONSE****"
	fi

}

get_scan_result() {
    GET_CALL_STATUS=$(curl -s ${CURL_FLAGS} -o "${TMP_PATH}"/sysdig_report.log --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}" || exit 0)
}

get_scan_result_with_retries() {
    # Fetching the result of each scanned digest
    for ((i=0;  i < GET_CALL_RETRIES; i++)); do
        time_start "Get scan result"
        get_scan_result
        time_end "Get scan result"
        if [[ "${GET_CALL_STATUS}" == 200 ]]; then
            return
        fi
        if [[ "${GET_CALL_STATUS}" != 404 ]]; then
            print_info "x" && sleep 10
        else
            print_info "." && sleep 1
        fi
    done
    exit_with_error "Unable to fetch scan result"
}

display_report() {

    status=$(jq -r ".[0][][][0].status // empty" "${TMP_PATH}"/sysdig_report.log)

    if [[ -z "${json_flag:-}" ]]; then
        print_info "Scan Report:"
        print_info_pipe < "${TMP_PATH}"/sysdig_report.log
    fi

    if [[ "${r_flag-""}" ]]; then
        print_info "Downloading PDF Scan result for image digest: ${SYSDIG_IMAGE_DIGEST}"
        get_scan_result_pdf_by_digest
    fi

    if [[ "${status}" = "pass" ]]; then
        print_info "Status is pass"
        print_scan_result_summary_message
    else
        print_info "Status is fail"
        print_scan_result_summary_message

        if [[ "${clean_flag:-}" ]]; then
            print_info "Cleaning image from Anchore"
            time_start "Clean image from backend"
            curl -X DELETE -sS ${CURL_FLAGS} -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}?force=true" >/dev/null 2>&1
            time_end "Clean image from backend"
        fi
    fi

    if [[ -n "${json_flag:-}" ]]; then
        jq -c -n \
            --arg status "${status}" \
            --arg tag "${FULLTAG}" \
            --arg digest "${SYSDIG_IMAGE_DIGEST}" \
            --slurpfile reports "${TMP_PATH}"/sysdig_report.log \
            --rawfile log "${TMP_PATH}"/info.log \
            '{status: $status, tag: $tag, digest: $digest, log: $log, scanReport: $reports[0]}' \
            2>&1 || exit_with_error "Cannot write JSON output"
    fi

   if [[ "${status}" != "pass" ]]; then
        exit 1
    fi
}

urlencode() {
    # urlencode <string>
    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "%s" "$c" ;;
            *) printf '%%%02X' "'$c"
        esac
    done
}

print_scan_result_summary_message() {
    if [[ ! "${v_flag-""}" && ! "${r_flag-""}" && ! "${json_flag-""}" ]]; then
        if [[ ! "${status}" = "pass" ]]; then
            print_info "Result Details:"
            curl -sS ${CURL_FLAGS} --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=true" 2>&1 | jq -c | print_info_pipe
        fi
    fi

    if [[ -z "${clean_flag:-}" ]]; then
        ENCODED_TAG=$(urlencode "${FULLTAG}")
        if [[ "${o_flag:-}" ]]; then
            print_info "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/secure/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST}/summaries"
        else
            print_info "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST}/summaries"
        fi
    fi

    print_info "PDF report of the scan results can be generated with -r option."
}

get_scan_result_pdf_by_digest() {
    date_format=$(date +'%Y-%m-%d')
    time_start "Get PDF report"
    curl -sS ${CURL_FLAGS} --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${FULLTAG##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST}/report?tag=${FULLTAG}"  2> "${TMP_PATH}"/curl.err || exit_with_error "Error downloading PDF report.\n$(cat "${TMP_PATH}"/curl.err)"
    time_end "Get PDF report"
}

interupt() {
    cleanup 130
}

cleanup() {
    local ret="$?"
    if [[ "${#@}" -ge 1 ]]; then
        local ret="$1"
    fi
    set +e

    if [[ "${v_flag:-}" ]]; then
        print_info "Removing temporary folder created ${TMP_PATH}"
    fi
    rm -rf "${TMP_PATH}"

    exit "${ret}"
}

main "$@"
