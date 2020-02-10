#!/bin/bash

#
#   Global variables
#
SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"
API_URL="https://api-iot.virgilsecurity.com"

#
#   Functions
#
check_error() {
   local RES=$?
   local WHAT=${1}
   if [[ $RES != 0 ]]; then
        echo "============================================"
        echo "FAILED: ${WHAT}"
        echo "============================================"
        exit $RES
   else
        echo "============================================"
        echo "SUCCESS: ${WHAT}"
        echo "============================================"
   fi
}

function show_help() {
    echo "Usage: $0 -t APP_TOKEN [-o OUTPUT_FOLDER]"
    echo "-t, --app-token          Virgil AppToken"
    echo "-o, --output-folder      path to folder to store tools output"
    exit 1
}

#
#   Process options
#
while [[ "$#" > 0 ]]; do case $1 in
  -t|--app-token) APP_TOKEN="$2"; shift;shift;;
  -o|--output-folder) OUTPUT_FOLDER="$2"; shift;shift;;
*) show_help; shift; shift;;
esac; done

[[ -z ${APP_TOKEN} ]] && show_help

if [[ -z "${OUTPUT_FOLDER}" ]]; then
    OUTPUT_FOLDER="${SCRIPT_FOLDER}/output"
fi

#
#   Install Virgil Trust Provisioner and requirements for helper scripts
#
pushd ${SCRIPT_FOLDER}/../tools/virgil-trust-provisioner
    pip3 install .
    check_error "Install Trust Provisioner"
popd

pushd ${SCRIPT_FOLDER}/helpers
    pip3 install -r requirements.txt
    check_error "Install requirements for helper scripts"
popd

#
#   Generate provision
#
python3 ${SCRIPT_FOLDER}/helpers/generate-provision.py \
    --virgil-app-token=${APP_TOKEN} \
    --iot-api-url=${API_URL} \
    --output-folder=${OUTPUT_FOLDER}
check_error "Generating provision package"
echo "Provision package is located at: ${OUTPUT_FOLDER}/provision-pack"
echo

#
#   Create script for Virgil Device Initializer launch
#
script_content=$(python3 ${SCRIPT_FOLDER}/helpers/generate-initializer-sh.py --output-folder=${OUTPUT_FOLDER})
check_error "Generating script for Virgil Device Initializer launch"

cat <<< "$script_content" > run-initializer.sh
chmod 755 run-initializer.sh

echo
echo "Devices provisioning can be performed by the following script:"
echo "$(pwd)/run-initializer.sh"
echo
