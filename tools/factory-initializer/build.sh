#!/usr/bin/env bash
# factory-initializer/build.sh
#
# build factory-initializer executable
# - support xcode builds into $TARGET_TEMP_DIR
# - `cmake` output also into $BUILD_DIR (supports multiple platforms)
# - when "clean", remove $BUILD_DIR
#
# shell variables in ALL_CAPS may come from above

set -eo pipefail

src_dir=$( cd $( dirname ${BASH_SOURCE[0]} ) && pwd )
target=factory-initializer

# build into $TARGET_TEMP_DIR when specific (such as by xcode)
[[ -w ${TARGET_TEMP_DIR} ]] && BUILD_DIR=${TARGET_TEMP_DIR}/${target}
BUILD_DIR=${BUILD_DIR:-${src_dir}/_build/$( uname -m )}

LOG=${LOG:-${BUILD_DIR}/${target}.log}

ACTION=${ACTION:-${1}}
if [[ $ACTION == "clean" ]]; then
    echo ------- clean ${target} -------
    echo removing \'${BUILD_DIR}\'
    rm -rf "${BUILD_DIR}"
    exit
fi

mkdir -p "${BUILD_DIR}"
pushd "${BUILD_DIR}"
date > "${LOG}"
echo ------- cmake ${target} ------- >> "${LOG}"
set -o pipefail && cmake -B"${BUILD_DIR}" -H"${src_dir}" 2>&1 | tee -a "${LOG}"
echo ------- make ${target} ------- >> "${LOG}"
set -o pipefail && make -j8 2>&1 | tee -a "${LOG}"
popd
