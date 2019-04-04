#!/bin/bash

function abs_path() {
    if [[ "${1}" = /* ]]; then
        echo "${1}"
    else
        echo "$(pwd)/${1}"
    fi
}

function get_keys_by_prefix() {
    KEY_1=""
    KEY_2=""

    for i in $(find "${1}" -name "${2}*"); do
        if [ -z "${KEY_1}" ]; then
            KEY_1="${i}"
            continue
        fi

        if [ -z "${KEY_2}" ]; then
            KEY_2="${i}"
            continue
        fi

        break

    done

    if [ -z "${KEY_2}" ]; then
        KEY_2="${KEY_1}"
    fi
}

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

DESTINATION_FILE="${1}"

PRIVATE_KEYS_DIR="${HOME}/current-credentials/key_storage/private"

get_keys_by_prefix "${PRIVATE_KEYS_DIR}" "auth_"
AUTH_KEY="${KEY_1}"

get_keys_by_prefix "${PRIVATE_KEYS_DIR}" "firmware_"
FW_KEY="${KEY_1}"

CONFIG_DIR=$(dirname "${DESTINATION_FILE}")

if [ ! -d "${CONFIG_DIR}" ]; then
    mkdir -p "${CONFIG_DIR}"
fi

echo "---------------------------"
echo "DESTINATION_FILE = ${DESTINATION_FILE}"
echo "PRIVATE_KEYS_DIR = ${PRIVATE_KEYS_DIR}"
echo "AUTH_KEY = ${AUTH_KEY}"
echo "FW_KEY = ${FW_KEY}"
echo "---------------------------"

echo "[MAIN]" 										> "${DESTINATION_FILE}"
echo "auth_key_path = ${AUTH_KEY}" 			        >> "${DESTINATION_FILE}"
echo "firmware_key_path = ${FW_KEY}" 				>> "${DESTINATION_FILE}"
echo "" 											>> "${DESTINATION_FILE}"

cat "${DESTINATION_FILE}"
