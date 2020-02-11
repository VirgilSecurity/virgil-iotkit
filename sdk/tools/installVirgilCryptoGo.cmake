set(VSCRYPT "${GOPATH}/src/gopkg.in/virgilsecurity/virgil-crypto-go.v5")
set(VSLIB "${VSCRYPT}/lib/libvirgil_crypto_go.a")
set(TMP_SH "${GOTMP}/virgil-crypto-go-deps.sh")
set(DEPS_SH "${CMAKE_CURRENT_BINARY_DIR}/virgil-crypto-go-deps.sh")
file(WRITE ${TMP_SH} "cd ${CMAKE_CURRENT_LIST_DIR} && ${CMAKE_Go_COMPILER} get -d ./... && if [ -d ${VSCRYPT} ] && [ ! -f ${VSLIB} ]; then make -C ${VSCRYPT}; fi")

add_custom_command(
        OUTPUT ${DEPS_SH}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${TMP_SH}" "${DEPS_SH}"
        COMMAND chmod +x "${DEPS_SH}"
)

add_custom_target(virgil-crypto-go-install-deps
        COMMAND env GOPATH=${GOPATH} ${DEPS_SH}
        DEPENDS ${DEPS_SH}
        )
