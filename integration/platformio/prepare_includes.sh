#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

rm -rf ${SCRIPT_FOLDER}/include/virgil/iot      || true
mkdir -p ${SCRIPT_FOLDER}/include/virgil/iot

cp -rf ${SCRIPT_FOLDER}/src/modules/firmware/include/virgil/iot/firmware                                     ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/modules/logger/include/virgil/iot/logger                                         ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/modules/protocols/snap/include/virgil/iot/protocols                              ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/modules/provision/include/virgil/iot/provision                                   ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/modules/provision/trust_list/include/virgil/iot/trust_list                       ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/modules/crypto/secmodule/include/virgil/iot/secmodule                            ${SCRIPT_FOLDER}/include/virgil/iot

cp -rf ${SCRIPT_FOLDER}/src/default-impl/crypto/vs-soft-secmodule/include/virgil/iot/vs-soft-secmodule       ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/helpers/status_code/include/virgil/iot/status_code                               ${SCRIPT_FOLDER}/include/virgil/iot
cp -rf ${SCRIPT_FOLDER}/src/helpers/macros/include/virgil/iot/macros                                         ${SCRIPT_FOLDER}/include/virgil/iot
