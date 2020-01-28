#include <virgil/iot/tests/helpers.h>
#include <private/private_helpers.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>

static const char not_before[] = "20131231235959";
static const char not_after[] = "20401231235959";
static const uint8_t test_object_id[8] = {1, 2, 3, 4, 5};
/******************************************************************************/
static bool
_test_generate_self_signed_x509(vs_secmodule_impl_t *secmodule_impl) {
    unsigned char cert[RESULT_BUF_SIZE];
    uint16_t cert_sz;

    CHECK_RET(VS_CODE_OK == secmodule_impl->x509_create_selfsign(test_object_id,
                                                                 sizeof(test_object_id),
                                                                 not_before,
                                                                 not_after,
                                                                 cert,
                                                                 sizeof(cert),
                                                                 &cert_sz),
              false,
              "Unable to generate x509 self signed cert");
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "cert = ", cert, cert_sz);

    return true;
}

/******************************************************************************/
uint16_t
test_x509(vs_secmodule_impl_t *secmodule_impl) {
    uint16_t failed_test_result = 0;
    START_TEST("x509 certificate");
    TEST_CASE_OK("Prepare keystorage",
                 vs_test_erase_otp_provision(secmodule_impl) && vs_test_create_device_key(secmodule_impl));

    TEST_CASE_OK("Generate self signed x509 certificate", _test_generate_self_signed_x509(secmodule_impl));

terminate:
    return failed_test_result;
}
