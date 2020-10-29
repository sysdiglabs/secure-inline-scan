#!/usr/bin/env bash

# NOTE: This script is left is just as a backward compatibility measure for those that uses the raw github URL.

set -eou pipefail

########################
### GLOBAL VARIABLES ###
########################

# If using a locally built stateless CI container, export SYSDIG_CI_IMAGE=<image_name>.
# This will override the image name from Dockerhub.
DOCKER_NAME="${RANDOM:-temp}-inline-anchore-engine"
INLINE_SCAN_IMAGE="${INLINE_SCAN_IMAGE:-}"
DOCKER_ID=""
VULN_SCAN=false
CREATE_CMD=()
COPY_CMDS=()
IMAGE_NAMES=()
SCAN_IMAGES=()
FAILED_IMAGES=()
VALIDATED_OPTIONS=""
# Vuln scan option variable defaults
DOCKERFILE="./Dockerfile"
# shellcheck disable=SC2034
TIMEOUT=300
TMP_PATH="/tmp/sysdig"
# Analyzer option variable defaults
SYSDIG_BASE_SCANNING_API_URL="https://api.sysdigcloud.com"
SYSDIG_BASE_SCANNING_URL="https://secure.sysdig.com"
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
Sysdig Inline Scanner/Analyzer --

  Wrapper script for performing vulnerability scan or image analysis on local docker images, utilizing the Sysdig inline_scan container.
  For more detailed usage instructions use the -h option after specifying scan or analyze.

    Usage: ${0##*/} <analyze> [ OPTIONS ]

EOF
}

display_usage_analyzer() {
    cat << EOF
Sysdig Inline Analyzer --

  Script for performing analysis on local container images, utilizing the Sysdig analyzer subsystem.
  After image is analyzed, the resulting image archive is sent to a remote Sysdig installation
  using the -s <URL> option. This allows inline analysis data to be persisted & utilized for reporting.

  Images should be built & tagged locally.

    Usage: ${0##*/} analyze -k <API Token> [ OPTIONS ] <FULL_IMAGE_TAG>

      -k <TEXT>  [required] API token for Sysdig Scanning auth (ex: -k 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')
      -s <TEXT>  [optional] Sysdig Secure URL (ex: -s 'https://secure-sysdig.svc.cluster.local').
                 If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com).
      -a <TEXT>  [optional] Add annotations (ex: -a 'key=value,key=value')
      -f <PATH>  [optional] Path to Dockerfile (ex: -f ./Dockerfile)
      -i <TEXT>  [optional] Specify image ID used within Sysdig (ex: -i '<64 hex characters>')
      -d <PATH>  [optional] Specify image digest (ex: -d 'sha256:<64 hex characters>')
      -m <PATH>  [optional] Path to Docker image manifest (ex: -m ./manifest.json)
      -C         [optional] Delete the image from Sysdig Secure if the scan fails
      -P         [optional] Pull container image from registry
      -V         [optional] Increase verbosity
      -v <PATH>  [optional] Use this absolute PATH for intermediate tar files. Path will be created if not existing. Default is /tmp/sysdig (ex: -v $PWD/temp)
      -R <PATH>  [optional] Download scan result pdf in a specified local directory (ex: -R /staging/reports)
      -o         [optional] Use this flag if targeting onprem sysdig installation

EOF
}

main() {
    trap 'cleanup' EXIT ERR SIGTERM
    trap 'interupt' SIGINT

    printf "**************************** DEPRECATION WARNING ****************************\n"
    printf "You are using an old version of the Sysdig Inline Scanner. V2 is available.\n"
    printf "Check https://github.com/sysdiglabs/secure-inline-scan for more information.\n"
    printf "*****************************************************************************\n\n"

    if [[ "$#" -lt 1 ]] || { [[ "$1" != 'analyze' ]] && [[ "$1" != 'help' ]]; }; then
        display_usage >&2
        printf '\n\t%s\n\n' "ERROR - must specify operation ('analyze')" >&2
        exit 1
    fi
    if [[ "$1" == 'help' ]]; then
        display_usage >&2
        exit 1
    elif [[ "$1" == 'analyze' ]]; then
        shift "$((OPTIND))"
        get_and_validate_analyzer_options "$@"
        get_and_validate_images "${VALIDATED_OPTIONS[@]}"
        prepare_inline_container
        CREATE_CMD+=('anchore-manager analyzers exec /anchore-engine/image.tar /tmp/image-analysis-archive.tgz')
        start_analysis
    fi
}

get_and_validate_analyzer_options() {
    #Parse options
    while getopts ':k:s:a:d:f:i:m:R:v:CPVho' option; do
        case "${option}" in
            k  ) k_flag=true; SYSDIG_API_TOKEN="${OPTARG}";;
            s  ) s_flag=true; SYSDIG_BASE_SCANNING_URL="${OPTARG%%}";SYSDIG_BASE_SCANNING_API_URL="${SYSDIG_BASE_SCANNING_URL}";;
            a  ) a_flag=true; SYSDIG_ANNOTATIONS="${OPTARG}";;
            f  ) f_flag=true; DOCKERFILE="${OPTARG}";;
            i  ) i_flag=true; SYSDIG_IMAGE_ID="${OPTARG}";;
            d  ) d_flag=true; SYSDIG_IMAGE_DIGEST="${OPTARG}";;
            m  ) m_flag=true; MANIFEST_FILE="${OPTARG}";;
            o  ) o_flag=true;;
            P  ) P_flag=true;;
            C  ) clean_flag=true;;
            V  ) V_flag=true;;
            R  ) R_flag=true; PDF_DIRECTORY="${OPTARG}";;
            v  ) TMP_PATH="${OPTARG}";;
            h  ) display_usage_analyzer; exit;;
            \? ) printf "\n\t%s\n\n" "Invalid option: -${OPTARG}" >&2; display_usage_analyzer >&2; exit 1;;
            :  ) printf "\n\t%s\n\n" "Option -${OPTARG} requires an argument." >&2; display_usage_analyzer >&2; exit 1;;
        esac
    done
    shift "$((OPTIND - 1))"

    SYSDIG_SCANNING_URL="${SYSDIG_BASE_SCANNING_API_URL}"/api/scanning/v1
    SYSDIG_ANCHORE_URL="${SYSDIG_SCANNING_URL}"/anchore
    # Check for invalid options
    if [[ ! $(which docker) ]]; then
        # shellcheck disable=SC2016
        printf '\n\t%s\n\n' 'ERROR - Docker is not installed or cannot be found in $PATH' >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${#@}" -gt 1 ]]; then
        printf '\n\t%s\n\n' "ERROR - only 1 image can be analyzed at a time" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${#@}" -lt 1 ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify an image to analyze" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${s_flag:-}" ]] && [[ ! "${k_flag:-}" ]]; then
        printf '\n\t%s\n\n' "ERROR - must provide the Sysdig Secure API token" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${SYSDIG_BASE_SCANNING_URL: -1}" == '/' ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify Sysdig url - ${SYSDIG_BASE_SCANNING_URL} without trailing slash" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${d_flag:-}" && ${SYSDIG_IMAGE_DIGEST} != *"sha256:"* ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify a valid sha256:<digestID>: ${SYSDIG_IMAGE_DIGEST}" >&2
        display_usage_analyzer >&2
        exit 1
    elif ! curl -k -s --fail -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/anchore/status" > /dev/null; then
        printf '\n\t%s\n\n' "ERROR - invalid combination of Sysdig secure endpoint" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${f_flag:-}" ]] && [[ ! -f "${DOCKERFILE}" ]]; then
        printf '\n\t%s\n\n' "ERROR - Dockerfile: ${DOCKERFILE} does not exist" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${m_flag:-}" ]] && [[ ! -f "${MANIFEST_FILE}" ]];then
        printf '\n\t%s\n\n' "ERROR - Manifest: ${MANIFEST_FILE} does not exist" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${R_flag:-}" ]] && [[ ! -d "${PDF_DIRECTORY}" ]];then
        printf '\n\t%s\n\n' "ERROR - Directory: ${PDF_DIRECTORY} does not exist" >&2
        display_usage_analyzer >&2
        exit 1
    elif [[ "${R_flag:-}" ]] && [[ "${PDF_DIRECTORY: -1}" == '/' ]]; then
        printf '\n\t%s\n\n' "ERROR - must specify file path - ${PDF_DIRECTORY} without trailing slash" >&2
        display_usage_analyzer >&2
        exit 1
    fi

    if [[ "${a_flag:-}" ]]; then
        # transform all commas to spaces & cast to an array
        local annotation_array
        IFS=" " read -r -a annotation_array <<< "${SYSDIG_ANNOTATIONS//,/ }"
        # get count of = in annotation string
        local number_keys=${SYSDIG_ANNOTATIONS//[^=]}
        # compare number of elements in array with number of = in annotation string
        if [[ "${#number_keys}" -ne "${#annotation_array[@]}" ]]; then
            printf '\n\t%s\n\n' "ERROR - ${SYSDIG_ANNOTATIONS} is not a valid input for -a option" >&2
            display_usage_analyzer >&2
            exit 1
        fi
    fi

    if [[ "${V_flag:-}" ]]; then
        DETAIL=true
        set -x
    fi

    if [[ ! $TMP_PATH == /* ]]; then
        printf '\n\t%s\n\n' "ERROR - Use absolute path with -v flag. Actual value is '${TMP_PATH}'" >&2
        display_usage_analyzer >&2
        exit 1
    else
        TMP_PATH="${TMP_PATH}/sysdig-inline-scan-$(date +%s)"
        mkdir -p "${TMP_PATH}"
        echo "Using temporary path ${TMP_PATH}"
    fi

    VALIDATED_OPTIONS=( "$@" )
}

get_and_validate_images() {
    # Add all unique positional input params to IMAGE_NAMES array
    for i in "$@"; do
        if [[ ! "${IMAGE_NAMES[*]:-}" =~ $i ]]; then
            IMAGE_NAMES+=("$i")
        fi
    done

    # Make sure all images are available locally, add to FAILED_IMAGES array if not
    for i in "${IMAGE_NAMES[@]-}"; do
        if { [[ "${p_flag:-false}" == true ]] && [[ "${VULN_SCAN:-false}" == true ]]; } || [[ "${P_flag:-false}" == true ]]; then
            echo "Pulling image -- $i"
            docker pull "$i" || true
        fi

        docker inspect "$i" &> /dev/null || FAILED_IMAGES+=("$i")

        if [[ ! "${FAILED_IMAGES[*]:-}" =~ $i ]]; then
            SCAN_IMAGES+=("$i")
        fi
    done

    # Give error message on any invalid image names
    if [[ "${#FAILED_IMAGES[@]}" -gt 0 ]]; then
        printf '\n%s\n\n' "WARNING - Please pull remote image, or build/tag all local images before attempting analysis again" >&2

        if [[ "${#FAILED_IMAGES[@]}" -ge "${#IMAGE_NAMES[@]}" ]]; then
            printf '\n\t%s\n\n' "ERROR - no local docker images specified in script input: ${0##*/} ${IMAGE_NAMES[*]}" >&2
            display_usage >&2
            exit 1
        fi

        for i in "${FAILED_IMAGES[@]}"; do
            printf '\t%s\n' "Could not find image locally -- $i" >&2
        done
    fi
}

prepare_inline_container() {
    # Retrieve dynamically from secure the Anchore version for compatibility reasons
    if [[ -z "$INLINE_SCAN_IMAGE" ]]; then
        printf 'Retrieving remote Anchore version from Sysdig Secure APIs\n'
        SCANNING_ANCHORE_STATUS=$(curl -sSkf  -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/anchore/status")
        INLINE_SCAN_IMAGE_VERSION=$(echo "${SCANNING_ANCHORE_STATUS}" | grep -o -E '"version":[ \t]?".*"' | awk -F ":" '{print $2}' | awk -F '"' '{print $2}')

        if [[ -z ${INLINE_SCAN_IMAGE_VERSION} ]]; then
            printf "Failed to retrieve Anchore version from Sysdig Secure APIs. Got response %s \n" "${SCANNING_ANCHORE_STATUS}"
            printf "\nTry again or set a specific image via INLINE_SCAN_IMAGE environment variable"
            exit 1
        fi

        printf "Found Anchore version from Sysdig Secure APIs %s" "${INLINE_SCAN_IMAGE_VERSION}"
        INLINE_SCAN_IMAGE="docker.io/anchore/anchore-engine:v${INLINE_SCAN_IMAGE_VERSION}"
    else
        printf 'Using set inline scan image'
    fi

    printf '\n%s\n' "Pulling ${INLINE_SCAN_IMAGE}"
    docker pull "${INLINE_SCAN_IMAGE}"

    # setup command arrays to eval & run after adding all required options
    # shellcheck disable=SC2016
    CREATE_CMD=('docker create --name "${DOCKER_NAME}"')

    if [[ "${t_flag-""}" ]]; then
        # shellcheck disable=SC2016
        CREATE_CMD+=('-e TIMEOUT="${TIMEOUT}"')
    fi
    if [[ "${V_flag-""}" ]]; then
        CREATE_CMD+=('-e VERBOSE=true')
    fi

    CREATE_CMD+=('-e ANCHORE_DB_HOST=useless -e ANCHORE_DB_USER=useless -e ANCHORE_DB_PASSWORD=useless')
    # shellcheck disable=SC2016
    CREATE_CMD+=('"${INLINE_SCAN_IMAGE}"')
}

start_analysis() {

    if [[ ! "${i_flag-""}" ]]; then
        SYSDIG_IMAGE_ID=$(docker image inspect "$i" -f "{{.Id}}" | cut -f2 -d ":" )
    fi

    if [[ ! "${d_flag-""}" ]]; then
        get_repo_digest_id
    fi

    FULLTAG="${SCAN_IMAGES[0]}"

    if [[ "${FULLTAG}" =~ "@sha256:" ]]; then
        local repoTag
        repoTag=$(docker inspect --format="{{- if .RepoTags -}}{{ index .RepoTags 0 }}{{- else -}}{{- end -}}" "${SCAN_IMAGES[0]}" | cut -f 2 -d ":")
        FULLTAG=$(echo "${FULLTAG}" | awk -v tag_var=":${repoTag:-latest}" '{ gsub("@sha256:.*", tag_var); print $0}')
    elif [[ ! "${FULLTAG}" =~ [:]+ ]]; then
        FULLTAG="${FULLTAG}:latest"
    fi

    printf '%s\n\n' "Image id: ${SYSDIG_IMAGE_ID}"

    FULL_IMAGE_NAME=$(docker inspect --format="{{- if .RepoDigests -}}{{index .RepoDigests 0}}{{- else -}}{{- end -}}" "${SCAN_IMAGES[0]}" | cut -d "@" -f 1)
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
    # shellcheck disable=SC2016
    CREATE_CMD+=('--digest "${SYSDIG_IMAGE_DIGEST}" --image-id "${SYSDIG_IMAGE_ID}"')

    if [[ "${a_flag-""}" ]]; then
        # shellcheck disable=SC2016
        CREATE_CMD+=('--annotation "${SYSDIG_ANNOTATIONS},added-by=sysdig-inline-scanner"')
    else
        CREATE_CMD+=('--annotation "added-by=sysdig-inline-scanner"')
    fi
    if [[ "${m_flag-""}" ]]; then
        # shellcheck disable=SC2016
        CREATE_CMD+=('--manifest "${MANIFEST_FILE}"')
        # shellcheck disable=SC2016
        COPY_CMDS+=('docker cp "${MANIFEST_FILE}" "${DOCKER_NAME}:/anchore-engine/$(basename ${MANIFEST_FILE})";')
    fi
    if [[ "${f_flag-""}" ]]; then
        # shellcheck disable=SC2016
        CREATE_CMD+=('--dockerfile "/anchore-engine/$(basename ${DOCKERFILE})"')
        # shellcheck disable=SC2016
        COPY_CMDS+=('docker cp "${DOCKERFILE}" "${DOCKER_NAME}:/anchore-engine/$(basename ${DOCKERFILE})";')
    fi

    # finally, get the account from Sysdig for the input username
    mkdir -p /tmp/sysdig
    HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_SCANNING_URL%%/}/account")
    if [[ "${HCODE}" == 404 ]]; then
	HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL%%/}/account")
    fi

    if [[ "${HCODE}" == 200 ]] && [[ -f "/tmp/sysdig/sysdig_output.log" ]]; then
  # shellcheck disable=SC2034
	ANCHORE_ACCOUNT=$(grep '"name"' /tmp/sysdig/sysdig_output.log | awk -F'"' '{print $4}')
  # shellcheck disable=SC2016
	CREATE_CMD+=('--account-id "${ANCHORE_ACCOUNT}"')
    else
	printf '\n\t%s\n\n' "ERROR - unable to fetch account information from anchore-engine for specified user"
	if [[ -f /tmp/sysdig/sysdig_output.log ]]; then
	    printf '%s\n\n' "***SERVICE RESPONSE****">&2
	    cat /tmp/sysdig/sysdig_output.log >&2
	    printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
	fi
	exit 1
    fi


    # shellcheck disable=SC2016
    CREATE_CMD+=('--tag "${FULLTAG}"')
    DOCKER_ID=$(eval "${CREATE_CMD[*]}")
    eval "${COPY_CMDS[*]-}"
    save_and_copy_images
    echo
    docker start -ia "${DOCKER_NAME}"

    # Copying files manually because volumes can't be trusted to work in docker-in-docker environments
    docker cp -a "${DOCKER_NAME}:/tmp/image-analysis-archive.tgz" "${TMP_PATH}/image-analysis-archive.tgz"

    if [[ -f "${TMP_PATH}/image-analysis-archive.tgz" ]]; then
        printf '%s\n' " Analysis complete!"
        printf '\n%s\n' "Sending analysis archive to ${SYSDIG_SCANNING_URL%%/}"
    else
        printf '\n\t%s\n\n' "ERROR Cannot find image analysis archive. An error occured during analysis."  >&2
        display_usage_analyzer >&2
        exit 1
    fi

    # Posting the archive to the secure backend (sync import)
    printf '%s\n' " Calling sync import endpoint"
    HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/sync/import/images")

	if [[ "${HCODE}" != 200 ]]; then
        if [[ "${HCODE}" == 404 ]]; then
            # Posting the archive to the secure backend (async import)
            printf '%s\n' " Calling async import endpoint"
            HCODE=$(curl -sSk --output /tmp/sysdig/sysdig_output.log --write-out "%{http_code}" -H "Content-Type: multipart/form-data" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -H "imageId: ${SYSDIG_IMAGE_ID}" -H "digestId: ${SYSDIG_IMAGE_DIGEST}" -H "imageName: ${FULLTAG}" -F "archive_file=@${TMP_PATH}/image-analysis-archive.tgz" "${SYSDIG_SCANNING_URL}/import/images")
            if [[ "${HCODE}" != 200 ]]; then
                printf '\n\t%s\n\n' "ERROR - unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/import/images" >&2
                if [ -f /tmp/sysdig/sysdig_output.log ]; then
                printf '%s\n\n' "***SERVICE RESPONSE****">&2
                cat /tmp/sysdig/sysdig_output.log >&2
                printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
                fi
                exit 1
            fi
            return
        fi
	    printf '\n\t%s\n\n' "ERROR - unable to POST image metadata to ${SYSDIG_SCANNING_URL%%/}/sync/import/images" >&2
	    if [ -f /tmp/sysdig/sysdig_output.log ]; then
		printf '%s\n\n' "***SERVICE RESPONSE****">&2
		cat /tmp/sysdig/sysdig_output.log >&2
		printf '\n%s\n' "***END SERVICE RESPONSE****" >&2
	    fi
	    exit 1
	fi
}

# This is done instead of the -g option, as we want to tie the RepoDigest value present in the image
# with the image id as much as possible, instead of generating our own digest or via skopeo.
get_repo_digest_id() {
    # Check to see if repo digest exists
    DIGESTS=$(docker inspect --format="{{.RepoDigests}}" "${SCAN_IMAGES[0]}")

    REPO=$(echo "${IMAGE_NAMES[0]}" | rev |  cut -d / -f 2 | rev)
    BASE_IMAGE=$(echo "${IMAGE_NAMES[0]}" | rev | cut -d / -f 1 | rev | cut -d : -f 1)
    TAG=$(echo "${IMAGE_NAMES[0]}" | rev | cut -d / -f 1 | rev | cut -d : -s -f 2)


    if [[ -z "${TAG// }" ]]; then
        TAG='latest'
    fi

    for DIGEST in "${DIGESTS[@]}"
    do
        if [[ ${DIGEST} == *"${REPO}/${BASE_IMAGE}:${TAG}"* || ${DIGEST} == *"${REPO}/${BASE_IMAGE}"* || ${DIGEST} == *"${BASE_IMAGE}"* ]]; then
            REPO_DIGEST=$(echo "${DIGEST}" | rev | cut -d : -f 1 | rev | tr -d ']' | cut -d ' ' -f 1)
        fi
    done

    # Generate Image digest ID for given image, if repo digest is not present
    if [[ -z "${REPO_DIGEST:-}" ]]; then
        printf '%s\n' " Unable to compute the digest from docker inspect ${SCAN_IMAGES[0]}!"
        printf '%s\n' " Consider running with -d option with a valid sha256:<digestID>."
        SYSDIG_IMAGE_DIGEST=$(docker inspect "${SCAN_IMAGES[0]}" | ${SHASUM_COMMAND} | awk '{ print $1 }' | tr -d "\n")
        SYSDIG_IMAGE_DIGEST="sha256:${SYSDIG_IMAGE_DIGEST}"
    else # Use parsed digest from array of digests based on docker inspect result
        SYSDIG_IMAGE_DIGEST="sha256:${REPO_DIGEST}"
    fi

    printf '\n%s\n' "Repo name: ${REPO}"
    printf '%s\n' "Base image name: ${BASE_IMAGE}"
    printf '%s\n\n' "Tag name: ${TAG}"
}

get_scan_result_code() {
    GET_CALL_STATUS=$(curl -sk -o /dev/null --write-out "%{http_code}" --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}" || exit 0)
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
        if [[ "${GET_CALL_STATUS}" != 404 ]]; then
            echo -n "x" && sleep 10
        else
            echo -n "." && sleep 1
        fi 
    done

    printf "Scan Report - \n"
    curl -s -k --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" "${SYSDIG_ANCHORE_URL}/images/${SYSDIG_IMAGE_DIGEST}/check?tag=${FULLTAG}&detail=${DETAIL}"

    if [[ "${R_flag-""}" ]]; then
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
    if [[ ! "${V_flag-""}"  && ! "${R_flag-""}" ]]; then
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
    printf "PDF report of the scan results can be generated with -R option.\n"
}

get_scan_result_pdf_by_digest() {
    date_format=$(date +'%Y-%m-%d')
    curl -sk --header "Content-Type: application/json" -H "Authorization: Bearer ${SYSDIG_API_TOKEN}" -o "${PDF_DIRECTORY}/${date_format}-${FULLTAG##*/}-scan-result.pdf" "${SYSDIG_SCANNING_URL}/images/${SYSDIG_IMAGE_DIGEST}/report?tag=${FULLTAG}"
}

save_and_copy_images() {
    local base_image_name
    base_image_name=$(echo "${FULLTAG}" | rev | cut -d '/' -f 1 | rev )
    echo "Saving ${base_image_name} for local analysis"
    save_file_name="${base_image_name}.tar"
    local save_file_path
    save_file_path="${TMP_PATH}/${save_file_name}"

    local image_name
    image_name=$(echo "${SCAN_IMAGES[0]}" | rev | cut -d '/' -f 1 | rev )
    if [[ ! "${image_name}" =~ [:]+ ]]; then
        docker save "${SCAN_IMAGES[0]}:latest" -o "${save_file_path}"
    else
        docker save "${SCAN_IMAGES[0]}" -o "${save_file_path}"
    fi
    chmod 777 "${save_file_path}"

    if [[ -f "${save_file_path}" ]]; then
        chmod +r "${save_file_path}"
        printf '%s' "Successfully prepared image archive -- ${save_file_path}"
    else
        printf '\n\t%s\n\n' "ERROR - unable to save docker image to ${save_file_path}." >&2
        display_usage >&2
        exit 1
    fi

    # Copying files manually because volumes can't be trusted to work in docker-in-docker environments
    docker cp "${save_file_path}" "${DOCKER_NAME}:/anchore-engine/image.tar"
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

    if [[ -z "${DOCKER_ID-""}" ]]; then
        DOCKER_ID="${DOCKER_NAME:-$(docker ps -a | grep 'inline-anchore-engine' | awk '{print $1}')}"
    fi

    for id in ${DOCKER_ID}; do
        local -i timeout=0
        while (docker ps -a | grep "${id:0:10}") > /dev/null && [[ "${timeout}" -lt 12 ]]; do
            docker kill "${id}" &> /dev/null
            docker rm "${id}" &> /dev/null
            printf '\n%s\n' "Cleaning up docker container: ${id}"
            ((timeout=timeout+1))
            sleep 5
        done

        if [[ "${timeout}" -ge 12 ]]; then
            exit 1
        fi
        unset DOCKER_ID
    done

    echo "Removing temporary folder created ${TMP_PATH}"
    rm -rf "${TMP_PATH}"

    exit "${ret}"
}

main "$@"
