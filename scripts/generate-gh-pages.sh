#!/bin/bash

# generate-gh-pages.sh ~/Work/virgil-iot-sdk debug ~/Work/virgil-iot-sdk.gh-pages

GIT_ORIGIN="origin"

CMAKE_PROJECT_DIR=$1    #"~/Work/virgil-iot-sdk"
CMAKE_OUTPUT_DIR="${CMAKE_PROJECT_DIR}/$2"     #"${CMAKE_PROJECT_DIR}/debug"
CMAKE_TARGET="documentation"

DOC_PAGES_DIR="${CMAKE_PROJECT_DIR}/docs/doxygen/html"
GH_PAGES_DIR=$3     #"~/Work/virgil-iot-sdk.gh-pages"


CUR_DIRECTORY=`pwd`

echo ---------------  Prepage output directory  -------------

cd ${GH_PAGES_DIR}
git rm -rf *

echo ----------------  Generate documentation  --------------

cd ${CMAKE_PROJECT_DIR}
CUR_HASH=`git rev-parse HEAD`
CUR_COMMENT=`git log -1 --pretty=%B`
cmake --build ${CMAKE_OUTPUT_DIR} --target ${CMAKE_TARGET}
cp -R -f ${DOC_PAGES_DIR}/ ${GH_PAGES_DIR}

echo ------------  Commit documentation changes  ------------

cd ${GH_PAGES_DIR}
git add *
git commit -m "Documentation changes for commit '${CUR_COMMENT}' ${CUR_HASH}"
git push ${GIT_ORIGIN} gh-pages

cd ${CUR_DIRECTORY}
