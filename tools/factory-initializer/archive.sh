#!/usr/bin/env bash
# factory-initializer/archive.sh
#
# Build and archive factory-initializer executable
# and related files required for factory operations
# into a platform-specific build directory.
# Exclude crypto files _not_ required for factory operations.
#
# shell variables in ALL_CAPS may ovveride those in called scripts

set -euo pipefail

if test $# -ne 1; then
    echo "Invalid number of arguments"
    echo "Usage: $0 <credentials>"
    echo "Example: $0 iot-production"
    exit 1
fi

target=factory-initializer
initializer=${target}-${1}

script_dir=$( cd $( dirname ${BASH_SOURCE[0]} ) && pwd )
export BUILD_DIR=${BUILD_DIR:-${script_dir}/_build/$( uname -m )}
${script_dir}/build.sh

src_root=$( cd ${script_dir}/../.. && pwd )

initializer_arc=${BUILD_DIR}/${initializer}.tar
rm -f ${initializer_arc}

pushd ${script_dir}
current_credentials=current-credentials
rm -f ${current_credentials}
ln -s ${1} ${current_credentials}
tar cf ${initializer_arc} ${current_credentials} scripts -C ${BUILD_DIR} iot-device-initializer
rm -f ${current_credentials}
tar rf ${initializer_arc} -C ${src_root}/crypto/credentials \
    --exclude=${1}'/key_storage/private*' \
    --exclude=${1}'/factory-file-transfer/registrar-key*' \
    ${1}/name.txt \
    ${1}/trust-list-type.txt \
    ${1}/factory-file-transfer \
    ${1}/key_storage
tar rf ${initializer_arc} -C ${src_root}/crypto/credentials \
    ${1}/factory-file-transfer/registrar-key/public.key
gzip -9nc ${initializer_arc} > ${BUILD_DIR}/${initializer}.tgz
rm -f ${initializer_arc}
popd
