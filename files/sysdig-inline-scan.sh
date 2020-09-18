#!/usr/bin/env bash

set -eou pipefail

#TODO:
# - Previous inline-scan.sh downloaded the same anchore/anchore-engine version to match the backend version. Might this be an issue?
# - Add a --json or similar option to do all the output in valid JSON format that can be processed and automated (i.e. for Jenkins plugin)
# - Check digest calculation when there is no RepoDigest
# - Check Image ID (SYSDIG_IMAGE_ID) different from OCI config than docker Config 
# - Keep compatibility using same parameters as older script? Or define a new set of params, and use --long params?

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
        SCAN_IMAGE="${VALIDATED_OPTIONS[0]}" 
        inspect_image
        start_analysis
        display_report
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

    if [[ "${v_flag:-}" ]]; then
        DETAIL=true
        set -x
    fi

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
    elif ! curl -ksS -o /dev/null --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/anchore/status"; then
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

    TMP_PATH="${TMP_PATH}/sysdig-inline-scan-$(date +%s)"
    mkdir -p "${TMP_PATH}"
    echo "Using temporary path ${TMP_PATH}"

    VALIDATED_OPTIONS=( "$@" )
}

inspect_image() {
    # Skopeo requires specifying a tag
    TAG=$(echo "${SCAN_IMAGE}" | cut -d : -s -f 2)
    if [[ -n "${TAG// }" ]] || [[ "${T_flag:-false}" == true ]] || [[ "${O_flag:-false}" == true ]] || [[ "${D_flag:-false}" == true ]]; then
        IMAGE_NAME=${SCAN_IMAGE}
    else
        IMAGE_NAME="${SCAN_IMAGE}:latest"
    fi

    # Make sure image is available locally
    if [[ "${T_flag:-false}" == true ]]; then
        echo "Inspecting image from Docker archive file -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw docker-archive:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect docker-archive:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    elif [[ "${O_flag:-false}" == true ]]; then
        echo "Inspecting image from OCI archive file -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw oci-archive:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect oci-archive:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    elif [[ "${D_flag:-false}" == true ]]; then
        echo "Inspecting image from OCI directory -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw oci:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect oci:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    elif [[ "${C_flag:-false}" == true ]]; then
        echo "Inspecting image from container-storage -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw container-storage:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect container-storage:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    elif [[ "${P_flag:-false}" == true ]]; then
        echo "Inspecting image from remote repository -- ${IMAGE_NAME}"
        MANIFEST=$(skopeo inspect --raw docker://"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect docker://"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    else
        echo "Inspecting image from Docker daemon -- ${IMAGE_NAME}"
        # Make sure we can access the docker sock...
        DOCKERGID=$(stat -c '%g' /var/run/docker.sock)
        #  ...by changing the group of skopeo, which has "setgid" flag
        sudo /usr/bin/chgrp "${DOCKERGID}" /usr/bin/skopeo
        sudo /usr/bin/chmod g+s /usr/bin/skopeo
        MANIFEST=$(skopeo inspect --raw docker-daemon:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
        INSPECT=$(skopeo inspect docker-daemon:"${IMAGE_NAME}") || find_image_error "${IMAGE_NAME}"
    fi 

    FULL_IMAGE_NAME=$(echo -n "${INSPECT}" | jq -r .Name)
    REPO_TAG=$(echo -n "${INSPECT}" | jq -r '.RepoTags[0] // empty')

    # Calculate "repo digest" from the RAW manifest
    REPO_DIGEST=$(echo -n "${MANIFEST}" | ${SHASUM_COMMAND} | cut -d ' ' -f 1)
}

convert_image() {


    DEST_IMAGE="oci:${TMP_PATH}/oci-image"
    if [[ "${T_flag:-false}" == true ]]; then
        echo "Converting image from Docker archive file -- ${IMAGE_NAME}"
        skopeo copy docker-archive:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${O_flag:-false}" == true ]]; then
        echo "Converting image from OCI archive file -- ${IMAGE_NAME}"
        skopeo copy oci-archive:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${D_flag:-false}" == true ]]; then
        echo "Converting image from OCI directory -- ${IMAGE_NAME}"
        skopeo copy oci:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${C_flag:-false}" == true ]]; then
        echo "Converting image from container-storage -- ${IMAGE_NAME}"
        skopeo copy container-storage:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    elif [[ "${P_flag:-false}" == true ]]; then
        echo "Converting image pulled from remote repository -- ${IMAGE_NAME}"
        skopeo copy docker://"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    else
        echo "Converting image from Docker daemon -- ${IMAGE_NAME}"
        skopeo copy docker-daemon:"${IMAGE_NAME}" "${DEST_IMAGE}" || find_image_error "${IMAGE_NAME}"
    fi 
}

find_image_error() {
    printf '\n%s\n\n' "WARNING - Please pull remote image, or build/tag all local images before attempting analysis again" >&2
    printf '\n\t%s\n\n' "ERROR - Failed to retrieve the image specified in script input: $1" >&2
    display_usage >&2
    exit 1
}

start_analysis() {

    if [[ ! "${d_flag-""}" ]]; then
        SYSDIG_IMAGE_DIGEST="sha256:${REPO_DIGEST}"
    fi

    FULLTAG="${SCAN_IMAGE}"

    if [[ "${FULLTAG}" =~ "@sha256:" ]]; then
        #TODO: "latest" as default? should we use "sysdig-line-scan"?
        FULLTAG=$(echo "${FULLTAG}" | awk -v tag_var=":${REPO_TAG:-latest}" '{ gsub("@sha256:.*", tag_var); print $0}')
    elif [[ ! "${FULLTAG}" =~ [:]+ ]]; then
        #TODO: "latest" as default? should we use "sysdig-line-scan"?
        FULLTAG="${FULLTAG}:latest"
    fi

    if [[ -z ${REPO_TAG} ]]; then
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

    printf '%s\n' "Repo digest: ${SYSDIG_IMAGE_DIGEST}"
    printf '%s\n' "Full image name: ${FULLTAG}"

    get_scan_result
    if [[ "${GET_CALL_STATUS}" != 200 ]]; then
        convert_image
        perform_analysis
        post_analysis
        get_scan_result_with_retries
    else
        echo "Image digest found on Sysdig Secure, skipping analysis."
    fi
}

perform_analysis() {
    export ANCHORE_DB_HOST=x
    export ANCHORE_DB_USER=x
    export ANCHORE_DB_PASSWORD=x 

    if [[ ! "${i_flag-""}" ]]; then
        #TODO(airadier): Probably this works, but the OCI config digest will differ from the docker config digest
        SYSDIG_IMAGE_ID=$(skopeo inspect --raw oci:"${TMP_PATH}"/oci-image | jq -r .config.digest | cut -f2 -d ":" )
    fi

    printf '%s\n' "Image id: ${SYSDIG_IMAGE_ID}"

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
    HCODE=$(curl -ksS -o "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account")
    if [[ "${HCODE}" == 404 ]]; then
	    HCODE=$(curl -ksS -o "${TMP_PATH}"/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account")
    fi

    if [[ "${HCODE}" == 200 ]] && [[ -f "${TMP_PATH}/sysdig_output.log" ]]; then
        # shellcheck disable=SC2034
        ANCHORE_ACCOUNT=$(jq -r '.name' "${TMP_PATH}/sysdig_output.log")
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
}

post_analysis() {

    # Posting the archive to the secure backend (sync import)
    printf '%s\n' " Calling sync import endpoint"
    HCODE=$(curl -ksS -o "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/sync/import/images")

    if [[ "${HCODE}" != 200 ]]; then
        if [[ "${HCODE}" == 404 ]]; then
            # Posting the archive to the secure backend (async import)
            printf '%s\n' " Calling async import endpoint"
            HCODE=$(curl -ksS -o "${TMP_PATH}/sysdig_output.log" --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images")
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

get_scan_result() {
    GET_CALL_STATUS=$(curl -ks -o "${TMP_PATH}"/sysdig_report.log --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}")
}

get_scan_result_with_retries() {
    # Fetching the result of each scanned digest
    for ((i=0;  i < GET_CALL_RETRIES; i++)); do
        get_scan_result
        if [[ "${GET_CALL_STATUS}" == 200 ]]; then
            break
        fi
        echo -n "." && sleep 1
    done
}

display_report() {

    status=$(jq -r ".[0][\"${SYSDIG_IMAGE_DIGEST}\"][\"${FULLTAG}\"][0].status" "${TMP_PATH}"/sysdig_report.log)

    printf "Scan Report - \n"
    cat "${TMP_PATH}"/sysdig_report.log

    if [[ "${r_flag-""}" ]]; then
        printf "\nDownloading PDF Scan result for image digest: %s" "${SYSDIG_IMAGE_DIGEST}"
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
            curl -X DELETE -ksS -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}?force=true"
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
            curl -ksS --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=true"
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
    curl -ksS --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${FULLTAG##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST}/report?tag=${FULLTAG}"
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
