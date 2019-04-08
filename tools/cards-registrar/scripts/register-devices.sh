#/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REGISTRAR_APP=${1}
EXEL_MODE="${2}"
DATA_FILE=${3}

BASE_PATH="${HOME}/current-credentials"

if [ ! -d "${BASE_PATH}" ]; then
	echo "There is no directory BASE_PATH == ${BASE_PATH}"
	exit 1
fi

REGISTRAR_PASSWORD=$(cat "${BASE_PATH}/factory-file-transfer/registrar-key/password.txt")
BASE_URL=$(cat "${BASE_PATH}/virgil-app/base-url.txt")
APP_ID=$(cat "${BASE_PATH}/virgil-app/app_id.txt")
API_KEY_ID=$(cat "${BASE_PATH}/virgil-app/api_key_id.txt")

pushd "${SCRIPT_FOLDER}/.."

if [ "${EXEL_MODE}" == "xls" ]; then
	"${REGISTRAR_APP}" --data "${DATA_FILE}" \
               --xls_input \
               --file_key "${BASE_PATH}/factory-file-transfer/registrar-key/private.key" \
               --file_key_pass "${REGISTRAR_PASSWORD}" \
               --file_sender_key "${BASE_PATH}/factory-file-transfer/factory-sender-key/public.key" \
               --app_id "${APP_ID}" \
               --api_key_id "${API_KEY_ID}" \
               --api_key "${BASE_PATH}/virgil-app/api_private.key" \
               --base_url "${BASE_URL}" \
               --iot_priv_key "${BASE_PATH}/virgil-app/iot-private.key"
else
	"${REGISTRAR_APP}" --data "${HOME}/virgil_iot_cards_requests.txt" \
               --file_key "${BASE_PATH}/factory-file-transfer/registrar-key/private.key" \
               --file_key_pass "${REGISTRAR_PASSWORD}" \
               --file_sender_key "${BASE_PATH}/factory-file-transfer/factory-sender-key/public.key" \
               --app_id "${APP_ID}" \
               --api_key_id "${API_KEY_ID}" \
               --api_key "${BASE_PATH}/virgil-app/api_private.key" \
               --base_url "${BASE_URL}" \
               --iot_priv_key "${BASE_PATH}/virgil-app/iot-private.key"
fi
popd