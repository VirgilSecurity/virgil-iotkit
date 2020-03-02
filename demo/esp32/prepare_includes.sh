#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LIB_FOLDER="${SCRIPT_FOLDER}/../../sdk"
rm -rf ${SCRIPT_FOLDER}/include/virgil/iot      || true
mkdir -p ${SCRIPT_FOLDER}/include/virgil/iot

cp -rf ${LIB_FOLDER}/high-level/include/virgil/iot/high-level                                         ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/firmware/include/virgil/iot/firmware                                     ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/logger/include/virgil/iot/logger                                         ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/protocols/snap/include/virgil/iot/protocols                              ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/provision/include/virgil/iot/provision                                   ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/provision/trust_list/include/virgil/iot/trust_list                       ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/modules/crypto/secmodule/include/virgil/iot/secmodule                            ${SCRIPT_FOLDER}/include/virgil/iot

cp -rf ${LIB_FOLDER}/default-impl/crypto/vs-soft-secmodule/include/virgil/iot/vs-soft-secmodule       ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/helpers/status_code/include/virgil/iot/status_code                               ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/helpers/macros/include/virgil/iot/macros                                         ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/helpers/update/include/virgil/iot/update                                         ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${LIB_FOLDER}/helpers/storage_hal/include/virgil/iot/storage_hal                               ${SCRIPT_FOLDER}/include/virgil/iot
