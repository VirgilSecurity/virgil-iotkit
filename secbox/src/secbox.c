#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>
#include <stdlib-config.h>

static const vs_secbox_hal_impl_t *_hal_mpl = NULL;

/******************************************************************************/
int
vs_secbox_configure_hal(const vs_secbox_hal_impl_t *impl) {
    VS_IOT_ASSERT(impl);
    VS_IOT_ASSERT(impl->init);

    _hal_mpl = impl;
    return impl->init();
}

/******************************************************************************/
int
vs_secbox_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    VS_IOT_ASSERT(_hal_mpl);
    VS_IOT_ASSERT(_hal_mpl->save);
    VS_IOT_ASSERT(element_info);
    VS_IOT_ASSERT(in_data);
    return _hal_mpl->save(element_info, in_data, data_sz);
}

/******************************************************************************/
int
vs_secbox_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, uint16_t data_sz) {
    VS_IOT_ASSERT(_hal_mpl);
    VS_IOT_ASSERT(_hal_mpl->load);

    return _hal_mpl->load(element_info, out_data, data_sz);
}

/******************************************************************************/
int
vs_secbox_del(vs_secbox_element_info_t *element_info) {
    VS_IOT_ASSERT(_hal_mpl);
    VS_IOT_ASSERT(_hal_mpl->del);
    VS_IOT_ASSERT(element_info);

    return _hal_mpl->del(element_info);
}