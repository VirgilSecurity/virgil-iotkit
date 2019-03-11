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

INITIALIZER=$(abs_path "${1}")
MODE="${2}"
ADDITIONAL_COMMAND="${3}"


if [ ! -d "${WORK_DIR}" ]; then
    WORK_DIR="${HOME}"
fi

BASE_PATH="${WORK_DIR}/current-credentials"

if [ ! -d "${BASE_PATH}" ]; then
    echo "BASE_PATH <${BASE_PATH}> doesn't exists"
    exit 1
fi

PRIVATE_KEYS_DIR="${BASE_PATH}/key_storage/private"
get_keys_by_prefix "${PRIVATE_KEYS_DIR}" "factory_"
FACTORY_KEY="${KEY_1}"

PUBLIC_KEYS_DIR="${BASE_PATH}/key_storage/pubkeys"
TRUST_LIST_DIR="${BASE_PATH}/key_storage/trust_lists"
get_keys_by_prefix "${TRUST_LIST_DIR}" "TrustList_"
TRUST_LIST="${KEY_1}"

get_keys_by_prefix "${PUBLIC_KEYS_DIR}" "recovery_"
RECOVERY_1="${KEY_1}"
RECOVERY_2="${KEY_2}"

get_keys_by_prefix "${PUBLIC_KEYS_DIR}" "auth_"
AUTH_1="${KEY_1}"
AUTH_2="${KEY_2}"

get_keys_by_prefix "${PUBLIC_KEYS_DIR}" "tl_service_"
TL_1="${KEY_1}"
TL_2="${KEY_2}"

get_keys_by_prefix "${PUBLIC_KEYS_DIR}" "firmware_"
FW_1="${KEY_1}"
FW_2="${KEY_2}"

CARD_REQUESTS_FILE="${WORK_DIR}/soraa_cards_requests.txt"
INFO_FILE="${WORK_DIR}/soraa_info_output.txt"

FACTORY_TRANSFER_PRIVATE_KEY_PATH="${BASE_PATH}/factory-file-transfer/factory-sender-key/private.key"
FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD_PATH="${BASE_PATH}/factory-file-transfer/factory-sender-key/password.txt"
REGISTRAR_TRANSFER_PUBLIC_KEY_PATH="${BASE_PATH}/factory-file-transfer/registrar-key/public.key"

echo "---------------------------"
echo "INITIALIZER = ${INITIALIZER}"
echo "FACTORY_KEY = ${FACTORY_KEY}"
echo "TRUST_LIST = ${TRUST_LIST}"
echo "RECOVERY_1 = ${RECOVERY_1}"
echo "RECOVERY_2 = ${RECOVERY_2}"
echo "AUTH_1 = ${AUTH_1}"
echo "AUTH_2 = ${AUTH_2}"
echo "TL_1 = ${TL_1}"
echo "TL_2 = ${TL_2}"
echo "FW_1 = ${FW_1}"
echo "FW_2 = ${FW_2}"
echo "CARD_REQUESTS_FILE = ${CARD_REQUESTS_FILE}"
echo "INFO_FILE = ${INFO_FILE}"
echo "FACTORY_TRANSFER_PRIVATE_KEY_PATH = ${FACTORY_TRANSFER_PRIVATE_KEY_PATH}"
echo "FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD_PATH = ${FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD_PATH}"
echo "REGISTRAR_TRANSFER_PUBLIC_KEY_PATH = ${REGISTRAR_TRANSFER_PUBLIC_KEY_PATH}"
echo "---------------------------"

FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD=$(cat ${FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD_PATH})

pushd "${SCRIPT_FOLDER}/.."

    if [ "${MODE}" == "stg" ]; then
        "${INITIALIZER}" "${ADDITIONAL_COMMAND}"                                \
                     --factory_key "${FACTORY_KEY}"                             \
                     --file_transfer_key "${FACTORY_TRANSFER_PRIVATE_KEY_PATH}"      \
                     --file_transfer_key_pass "${FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD}" \
                     --file_recipient_key "${REGISTRAR_TRANSFER_PUBLIC_KEY_PATH}"    \
                     --output "${CARD_REQUESTS_FILE}"                           \
                     --device_info_output "${INFO_FILE}"                        \
                     --auth_pub_key_1 "${AUTH_1}"                               \
                     --auth_pub_key_2 "${AUTH_2}"                               \
                     --rec_pub_key_1 "${RECOVERY_1}"                            \
                     --rec_pub_key_2 "${RECOVERY_2}"                            \
                     --tl_pub_key_1 "${TL_1}"                                   \
                     --tl_pub_key_2 "${TL_2}"                                   \
                     --fw_pub_key_1 "${FW_1}"                                   \
                     --fw_pub_key_2 "${FW_2}"                                   \
                     --trust_list "${TRUST_LIST}"
    else
        "${INITIALIZER}" "${ADDITIONAL_COMMAND}"                                \
                    --file_transfer_key "${FACTORY_TRANSFER_PRIVATE_KEY_PATH}"  \
                    --file_transfer_key_pass "${FACTORY_TRANSFER_PRIVATE_KEY_PASSWORD}" \
                    --file_recipient_key "${REGISTRAR_TRANSFER_PUBLIC_KEY_PATH}"     \
                    --output "${CARD_REQUESTS_FILE}"                            \
                    --device_info_output "${INFO_FILE}"                         \
                    --auth_pub_key_1 "${AUTH_1}"                                \
                    --auth_pub_key_2 "${AUTH_2}"                                \
                    --rec_pub_key_1 "${RECOVERY_1}"                             \
                    --rec_pub_key_2 "${RECOVERY_2}"                             \
                    --tl_pub_key_1 "${TL_1}"                                    \
                    --tl_pub_key_2 "${TL_2}"                                    \
                    --fw_pub_key_1 "${FW_1}"                                    \
                    --fw_pub_key_2 "${FW_2}"                                    \
                    --trust_list "${TRUST_LIST}"
    fi
popd
