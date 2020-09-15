#!/usr/bin/env bash

set -eou pipefail

#TODO:
# - Previous inline-scan.sh downloaded the same anchore/anchore-engine version to match the backend version. Might this be an issue?
# - Add a --json or similar option to do all the output in valid JSON format that can be processed and automated (i.e. for Jenkins plugin)
# - We do the pulling / conversion before checking if already scanned. Inspect before pulling / converting?
# - Check digest calculation when there is no RepoDigest
# - Check Image ID different from OCI config than docker Config 

########################
### GLOBAL VARIABLES ###
########################

ANALYZE_CMD=()
SCAN_IMAGE=""
VALIDATED_OPTIONS=""
# Vuln scan option variable defaults
DOCKERFILE="./Dockerfile"
TMP_PATH="/tmp/sysdig"
# Analyzer option variable defaults
SYSDIG_BASE_SCANNING_URL="https://secure.sysdig.com"
SYSDIG_BASE_SCANNING_API_URL="https://api.sysdigcloud.com"
SYSDIG_SCANNING_URL="http://localhost:9040/api/scanning"
SYSDIG_ANCHORE_URL="http://localhost:9040/api/scanning/v1/anchore"
SYSDIG_ANNOTATIONS="foo=bar"
SYSDIG_IMAGE_DIGEST="sha256:123456890abcdefg"
SYSDIG_IMAGE_ID="123456890abcdefg"
SYSDIG_API_TOKEN="test-token"
MANIFEST_FILE="./manifest.json"
PDF_DIRECTORY="$PWD"
GET_CALL_STATUS=''
GET_CALL_RETRIES=300
DETAIL=false

if command -v sha256sum >/dev/null 2>&1; then
    SHASUM_COMMAND="sha256sum"
else
    if command -v shasum >/dev/null 2>&1; then
        SHASUM_COMMAND="shasum -a 256"
    else
        printf "ERROR: sha256sum or shasum command is required but missing\n"
        exit 1
    fi
fi

display_usage() {
    cat << EOF

Sysdig Inline Analyzer --

  Container for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Images should be built & tagged locally.

    Usage: ${0##*/} -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG|TARFILE|DIRECTORY>

      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')

      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -c         [optional] Remove the image from Sysdig Secure if the scan fails


      -r <PATH>  [optional] Download scan result pdf in a specified local directory (ex: -r /staging/reports)
      -o         [optional] Use this flag if targeting onprem sysdig installation
      -v         [optional] Increase verbosity

      IMAGE SOURCES

      [Default]  If no flag is specified, try to get the image from the Docker daemon. 
                 Requires /var/run/docker.sock to be mounted in the container

      -T         Image is provided as a Docker .tar file (from docker save) in the location
                 specified by TARFILE (need to mount it in the container)

      -O         Image is provided as a OCI image tar file in the location specified
                 by TARFILE (need to mount it in the container)

      -D         Image is provided as a OCI image, untared, in the location specified
                 by DIRECTORY (need to mount it in the container)

      -C         Get the image from container-storage (CRI-O and others).
                 Requires mounting /etc/containers/storage.conf and /var/lib/containers

      -P         Pull container image from registry
EOF
}

main() {
    trap 'cleanup' EXIT ERR SIGTERM
    trap 'interupt' SIGINT

    if [[ "$#" -lt 1 ]] || [[ "$1" == 'help' ]]; then
        display_usage >&2
        exit 1
    else
        get_and_validate_analyzer_options "$@"
        convert_image "${VALIDATED_OPTIONS[@]}"
        start_analysis
    fi
}

get_and_validate_analyzer_options() {
    #Parse options
    while getopts ':k:s:a:f:i:d:m:ocvr:hTODCP' option; do
        case "${option}" in
            k  ) k_flag=true; SYSDIG_API_TOKEN="${OPTARG}";;
            s  ) s_flag=true; SYSDIG_BASE_SCANNING_URL="${OPTARG%%}"; SYSDIG_BASE_SCANNING_API_URL="${SYSDIG_BASE_SCANNING_URL}";;
            a  ) a_flag=true; SYSDIG_ANNOTATIONS="${OPTARG}";;
            f  ) f_flag=true; DOCKERFILE="${OPTARG}";;
            i  ) i_flag=true; SYSDIG_IMAGE_ID="${OPTARG}";;
            d  ) d_flag=true; SYSDIG_IMAGE_DIGEST="${OPTARG}";;
            m  ) m_flag=true; MANIFEST_FILE="${OPTARG}";;
            o  ) o_flag=true;;
            c  ) clean_flag=true;;
            v  ) v_flag=true;;
            r  ) r_flag=true; PDF_DIRECTORY="${OPTARG}";;
            h  ) display_usage; exit;;
            T  ) T_flag=true;;
            O  ) O_flag=true;;
            D  ) D_flag=true;;
            C  ) C_flag=true;;
            P  ) P_flag=true;;
            \? ) printf "\n\t%s\n\n" "Invalid option: -${OPTARG}" >&2; display_usage >&2; exit 1;;
            :  ) printf "\n\t%s\n\n" "Option -${OPTARG} requires an argument." >&2; display_usage >&2; exit 1;;
        esac
    done
    shift "$((OPTIND - 1))"

    SYSDIG_SCANNING_URL="${SYSDIG_BASE_SCANNING_API_URL}"/api/scanning/v1
    SYSDIG_ANCHORE_URL="${SYSDIG_SCANNING_URL}"/anchore
    # Check for invalid options
    if [[ ! $(which skopeo) ]]; then
        # shellcheck disable=SC2016
        printf '\n\t%s\n\n' 'ERROR - Skopeo is not installed or cannot be found in $PATH' >&2
        display_usage >&2
        exit 1
    elif [[ "${#@}" -gt 1 ]]; then
        printf '\n\t%s\n\n' "ERROR - only 1 image can be analyzed at a time" >&2
        display_usage >&2
        exit 1
    elif [[ "${#@}" -lt 1 ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify an image to analyze" >&2
        display_usage >&2
        exit 1
    elif [[ "${s_flag:-}" ]] && [[ ! "${k_flag:-}" ]]; then
        printf '\n\t%s\n\n' "ERROR - must provide the Sysdig Secure API token" >&2
        display_usage >&2
        exit 1
    elif [[ "${SYSDIG_BASE_SCANNING_URL: -1}" == '/' ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify Sysdig url - ${SYSDIG_BASE_SCANNING_URL} without trailing slash" >&2
        display_usage >&2
        exit 1
    elif [[ "${d_flag:-}" && ${SYSDIG_IMAGE_DIGEST} != *"sha256:"* ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify a valid sha256:<digestID>: ${SYSDIG_IMAGE_DIGEST}" >&2
        display_usage >&2
        exit 1
    elif ! curl -k -s --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/anchore/status" > /dev/null; then
        printf '\n\t%s\n\n' "ERROR - invalid combination of Sysdig secure endpoint" >&2
        display_usage >&2
        exit 1
    elif [[ "${a_flag:-}" ]]; then
        # transform all commas to spaces & cast to an array
        local annotation_array
        IFS=" " read -r -a annotation_array <<< "${SYSDIG_ANNOTATIONS//,/ }"
        # get count of = in annotation string
        local number_keys=${SYSDIG_ANNOTATIONS//[^=]}
        # compare number of elements in array with number of = in annotation string
        if [[ "${#number_keys}" -ne "${#annotation_array[@]}" ]]; then
            printf '\n\t%s\n\n' "ERROR - ${SYSDIG_ANNOTATIONS} is not a valid input for -a option" >&2
            display_usage >&2
            exit 1
        fi
    elif [[ "${f_flag:-}" ]] && [[ ! -f "${DOCKERFILE}" ]]; then
        printf '\n\t%s\n\n' "ERROR - Dockerfile: ${DOCKERFILE} does not exist" >&2
        display_usage >&2
        exit 1
    elif [[ "${m_flag:-}" ]] && [[ ! -f "${MANIFEST_FILE}" ]];then
        printf '\n\t%s\n\n' "ERROR - Manifest: ${MANIFEST_FILE} does not exist" >&2
        display_usage >&2
        exit 1
    elif [[ "${r_flag:-}" ]] && [[ ! -d "${PDF_DIRECTORY}" ]];then
        printf '\n\t%s\n\n' "ERROR - Directory: ${PDF_DIRECTORY} does not exist" >&2
        display_usage >&2
        exit 1
    elif [[ "${r_flag:-}" ]] && [[ "${PDF_DIRECTORY: -1}" == '/' ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify file path - ${PDF_DIRECTORY} without trailing slash" >&2
        display_usage >&2
        exit 1
    fi

    if [[ "${v_flag:-}" ]]; then
        DETAIL=true
        set -x
    fi

    TMP_PATH="${TMP_PATH}/sysdig-inline-scan-$(date +%s)"
    mkdir -p "${TMP_PATH}"
    echo "Using temporary path ${TMP_PATH}"

    VALIDATED_OPTIONS=( "$@" )
}

convert_image() {

    # Skopeo requires specifying a tag
    TAG=$(echo "$1" | cut -d : -s -f 2)
    if [[ -n "${TAG// }" ]] || [[ "${T_flag:-false}" == true ]] || [[ "${O_flag:-false}" == true ]] || [[ "${D_flag:-false}" == true ]]; then
        IMAGE_NAME=$1
    else
        IMAGE_NAME="${1}:latest"
    fi

    DEST_IMAGE="oci:${TMP_PATH}/oci-image"
    # Make sure image is available locally, add to FAILED_IMAGES array if not
    if [[ "${T_flag:-false}" == true ]]; then
        echo "Getting image from Docker archive file -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw docker-archive:"${IMAGE_NAME}")
        skopeo copy docker-archive:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${O_flag:-false}" == true ]]; then
        echo "Getting image from OCI archive file -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw oci-archive:"${IMAGE_NAME}")
        skopeo copy oci-archive:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${D_flag:-false}" == true ]]; then
        echo "Getting image from OCI directory -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw oci:"${IMAGE_NAME}")
        skopeo copy oci:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${C_flag:-false}" == true ]]; then
        echo "Getting image from container-storage -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw container-storage:"${IMAGE_NAME}")
        skopeo copy container-storage:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${P_flag:-false}" == true ]]; then
        echo "Pulling image -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw docker://"${IMAGE_NAME}")
        skopeo copy docker://"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    else
        echo "Getting image from Docker daemon -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw docker-daemon:"${IMAGE_NAME}")
        skopeo copy docker-daemon:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    fi 

    # Calculate "repo digest" from the RAW manifest
    REPO_DIGEST=$(echo -n "${MANIFEST}" | ${SHASUM_COMMAND} | cut -d ' ' -f 1)

    SCAN_IMAGE=$1
}

find_image_error() {
    printf '\n%s\n\n' "WARNING - Please pull remote image, or build/tag all local images before attempting analysis again" >&2
    printf '\n\t%s\n\n' "ERROR - Failed to retrive docker image specified in script input: $1" >&2
    display_usage >&2
    exit 1
}

start_analysis() {

    #TODO: Skopeo does not provide IMAGE_ID, and /import/images does not support it. Sysdig specific? How can we replace it?
    if [[ ! "${i_flag-""}" ]]; then
        # Probably this works
        SYSDIG_IMAGE_ID=$(skopeo inspect --raw oci:"${TMP_PATH}"/oci-image | jq -r .config.digest | cut -f2 -d ":" )
    fi

    if [[ ! "${d_flag-""}" ]]; then
        get_repo_digest_id
    fi

    FULLTAG="${SCAN_IMAGE}"

    #TODO: How do we do this with Skopeo? RepoTags comes empty
    if [[ "${FULLTAG}" =~ "@sha256:" ]]; then
        local repoTag
        #repoTag=$(docker inspect --format="{{- if .RepoTags -}}{{ index .RepoTags 0 }}{{- else -}}{{- end -}}" "${SCAN_IMAGES[0]}" | cut -f 2 -d ":")
        repoTag=$(skopeo inspect oci:"${TMP_PATH}"/oci-image | jq -r '.RepoTags[0] // empty' )
        #TODO: "latest" as default? should we use "sysdig-line-scan"?
        FULLTAG=$(echo "${FULLTAG}" | awk -v tag_var=":${repoTag:-latest}" '{ gsub("@sha256:.*", tag_var); print $0}')
    elif [[ ! "${FULLTAG}" =~ [:]+ ]]; then
        #TODO: "latest" as default? should we use "sysdig-line-scan"?
        FULLTAG="${FULLTAG}:latest"
    fi

    printf '%s\n\n' "Image id: ${SYSDIG_IMAGE_ID}"

    #TODO: Check that case for local build images (no registry) works, and localbuild/ is added
    #FULL_IMAGE_NAME=$(docker inspect --format="{{- if .RepoDigests -}}{{index .RepoDigests 0}}{{- else -}}{{- end -}}" "${SCAN_IMAGES[0]}" | cut -d "@" -f 1)
    FULL_IMAGE_NAME=$(skopeo inspect oci:"${TMP_PATH}"/oci-image | jq -r .Name)
    if [[ -z ${FULL_IMAGE_NAME} ]]; then
        # local built image, has not digest and refers to no registry
        FULLTAG="localbuild/${FULLTAG}"
    else
        # switch docker.io vs rest-of-the-world registries
        # using (light) docker rule for naming: if it has a "." or a ":" we assume the image is from some specific registry
        # see: https://github.com/docker/distribution/blob/master/reference/normalize.go#L91
        IS_DOCKER_IO=$(echo "${FULL_IMAGE_NAME}" | grep '\.\|\:' || echo "")
        if [[ -z ${IS_DOCKER_IO} ]] && [[ ! "${FULLTAG}" =~ ^docker.io* ]]; then
            # Forcing docker.io registry
            FULLTAG="docker.io/${FULLTAG}"
        else
            FULLTAG="${FULLTAG}"
        fi

    fi

    echo "using full image name: ${FULLTAG}"
    get_scan_result_code
    if [[ "${GET_CALL_STATUS}" != 200 ]]; then
        post_analysis
    else
        echo "Image digest found on Sysdig Secure, skipping analysis."
    fi
    get_scan_result_with_retries
}

post_analysis() {
    export ANCHORE_DB_HOST=x
    export ANCHORE_DB_USER=x
    export ANCHORE_DB_PASSWORD=x 

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('anchore-manager analyzers exec ${TMP_PATH}/oci-image ${TMP_PATH}/image-analysis-archive.tgz')

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('--digest "${SYSDIG_IMAGE_DIGEST}" --image-id "${SYSDIG_IMAGE_ID}"')

    if [[ "${a_flag-""}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--annotation "${SYSDIG_ANNOTATIONS},added-by=sysdig-inline-scanner"')
    else
        ANALYZE_CMD+=('--annotation "added-by=sysdig-inline-scanner"')
    fi
    if [[ "${m_flag-""}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--manifest "${MANIFEST_FILE}"')
    fi
    if [[ "${f_flag-""}" ]]; then
        # shellcheck disable=SC2016
        ANALYZE_CMD+=('--dockerfile "${DOCKERFILE}"')
    fi
    if [[ "${v_flag-""}" ]]; then
        export ANCHORE_CLI_DEBUG=y
    fi

    # finally, get the account from Sysdig for the input username
    HCODE=$(curl -sSk --output "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account")
    if [[ "${HCODE}" == 404 ]]; then
	    HCODE=$(curl -sSk --output "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account")
    fi

    if [[ "${HCODE}" == 200 ]] && [[ -f "${TMP_PATH}/sysdig_output.log" ]]; then
        # shellcheck disable=SC2034
        ANCHORE_ACCOUNT=$(grep '"name"' "${TMP_PATH}/sysdig_output.log" | awk -F'"' '{print $4}')
        # shellcheck disable=SC2016
	    ANALYZE_CMD+=('--account-id "${ANCHORE_ACCOUNT}"')
    else
        printf '\n\t%s\n\n' "ERROR - unable to fetch account information from anchore-engine for specified user"
        if [[ -f ${TMP_PATH}/sysdig_output.log ]]; then
            printf '%s\n\n' "***SERVICE RESPONSE****">&2
            cat "${TMP_PATH}"/sysdig_output.log >&2
            printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
        fi
        exit 1
    fi

    # shellcheck disable=SC2016
    ANALYZE_CMD+=('--tag "${FULLTAG}"')

    echo
    eval "${ANALYZE_CMD[*]}"

    if [[ -f "${TMP_PATH}/image-analysis-archive.tgz" ]]; then
        printf '%s\n' " Analysis complete!"
        printf '\n%s\n' "Sending analysis archive to ${SYSDIG_SCANNING_URL%%/}"
    else
        printf '\n\t%s\n\n' "ERROR Cannot find image analysis archive. An error occured during analysis."  >&2
        display_usage >&2
        exit 1
    fi

    # Posting the archive to the secure backend (sync import)
    printf '%s\n' " Calling sync import endpoint"
    HCODE=$(curl -sSk --output "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/sync/import/images")

    if [[ "${HCODE}" != 200 ]]; then
        if [[ "${HCODE}" == 404 ]]; then
            # Posting the archive to the secure backend (async import)
            printf '%s\n' " Calling async import endpoint"
            HCODE=$(curl -sSk --output "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images")
            if [[ "${HCODE}" != 200 ]]; then
                printf '\n\t%s\n\n' "ERROR - unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/import/images" >&2
                if [ -f "${TMP_PATH}/sysdig_output.log" ]; then
                printf '%s\n\n' "***SERVICE RESPONSE****">&2
                cat "${TMP_PATH}/sysdig_output.log" >&2
                printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
                fi
                exit 1
            fi
            return
        fi
	    printf '\n\t%s\n\n' "ERROR - unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/sync/import/images" >&2
	    if [ -f "${TMP_PATH}/sysdig_output.log" ]; then
		printf '%s\n\n' "***SERVICE RESPONSE****">&2
		cat "${TMP_PATH}/sysdig_output.log" >&2
		printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
	    fi
	    exit 1
	fi

}

# This is done instead of the -g option, as we want to tie the RepoDigest value present in the image
# with the image id as much as possible, instead of generating our own digest or via skopeo.
get_repo_digest_id() {

    #TODO: Is this correct? See https://github.com/sysdiglabs/secure-inline-scan/issues/55
    REPO=$(echo "${SCAN_IMAGE}" | rev |  cut -d / -f 2 | rev)
    BASE_IMAGE=$(echo "${SCAN_IMAGE}" | rev | cut -d / -f 1 | rev | cut -d : -f 1)
    TAG=$(echo "${SCAN_IMAGE}" | rev | cut -d / -f 1 | rev | cut -s -d : -f 2)

    if [[ -z "${TAG// }" ]]; then
        TAG='latest'
    fi

    # Generate Image digest ID for given image, if repo digest is not present
    if [[ -z "${REPO_DIGEST:-}" ]]; then
        printf '%s\n' " Unable to compute the digest from docker inspect ${SCAN_IMAGE}!"
        printf '%s\n' " Consider running with -d option with a valid sha256:<digestID>."
        SYSDIG_IMAGE_DIGEST=$(docker inspect "${SCAN_IMAGE}" | ${SHASUM_COMMAND} | awk '{ print $1 }' | tr -d "\n")
        SYSDIG_IMAGE_DIGEST="sha256:${SYSDIG_IMAGE_DIGEST}"
    else # Use parsed digest from array of digests based on docker inspect result
        SYSDIG_IMAGE_DIGEST="sha256:${REPO_DIGEST}"
    fi

    printf '\n%s\n' "Repo name: ${REPO}"
    #TODO(airadier): Not working correctly for @sha256:xxxx notation
    printf '%s\n' "Base image name: ${BASE_IMAGE}"
    #TODO(airadier): Not working correctly for @sha256:xxxx notation
    printf '%s\n\n' "Tag name: ${TAG}"
    printf '%s\n\n' "Repo digest: ${SYSDIG_IMAGE_DIGEST}"
}

get_scan_result_code() {
    GET_CALL_STATUS=$(curl -sk -o /dev/null --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}")
}

get_scan_result_with_retries() {
    # Fetching the result of each scanned digest
    for ((i=0;  i < GET_CALL_RETRIES; i++)); do
        get_scan_result_code
        if [[ "${GET_CALL_STATUS}" == 200 ]]; then
            status=$(curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}" | grep "status" | cut -d : -f 2 | awk -F\" '{ print $2 }')
            status=$(echo "${status}" | tr -d '\n')
            break
        fi
        echo -n "." && sleep 1
    done

    printf "Scan Report - \n"
    curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}"

    if [[ "${r_flag-""}" ]]; then
        printf "\nDownloading PDF Scan result for image id: %s / digest: %s" "${SYSDIG_IMAGE_ID}" "${SYSDIG_IMAGE_DIGEST}"
        get_scan_result_pdf_by_digest
    fi

    if [[ "${status}" = "pass" ]]; then
        printf "\nStatus is pass\n"
        print_scan_result_summary_message
        exit 0
    else
        printf "\nStatus is fail\n"
        print_scan_result_summary_message
        if [[ "${clean_flag:-}" ]]; then
            echo "Cleaning image from Anchore"
            curl -X DELETE -s -k -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}?force=true"
        fi
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
    if [[ ! "${v_flag-""}"  && ! "${r_flag-""}" ]]; then
        if [[ ! "${status}" = "pass" ]]; then
            echo "Result Details: "
            curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=true"
        fi
    fi

    if [[ -z "${clean_flag:-}" ]]; then
        ENCODED_TAG=$(urlencode "${FULLTAG}")
        if [[ "${o_flag:-}" ]]; then
            echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/secure/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST}/summaries"
        else
            echo "View the full result @ ${SYSDIG_BASE_SCANNING_URL}/#/scanning/scan-results/${ENCODED_TAG}/${SYSDIG_IMAGE_DIGEST}/summaries"
        fi
    fi
    printf "PDF report of the scan results can be generated with -r option.\n"
}

get_scan_result_pdf_by_digest() {
    date_format=$(date +'%Y-%m-%d')
    curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${FULLTAG##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST}/report?tag=${FULLTAG}"
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

    echo "Removing temporary folder created ${TMP_PATH}"
    rm -rf "${TMP_PATH}"

    exit "${ret}"
}

main "$@"
