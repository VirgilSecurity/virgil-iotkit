#include <stdint.h>
#include <stddef.h>

#include <secbox.h>
#include <sdmp/PRVS.h>
#include <hal/macro.h>

static const vs_secbox_hal_impl_t *_hal_mpl = NULL;

/******************************************************************************/
int
vs_secbox_configure_hal(const vs_secbox_hal_impl_t *impl) {
    _hal_mpl = impl;
    return 0;
}

/******************************************************************************/
int
vs_secbox_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, size_t data_sz) {
    VS_ASSERT(_hal_mpl);
    VS_ASSERT(_hal_mpl->save);
    VS_ASSERT(element_info);
    VS_ASSERT(in_data);
    return _hal_mpl->save(element_info, in_data, data_sz);
}

/******************************************************************************/
int
vs_secbox_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, size_t buf_sz, size_t *out_sz) {
    VS_ASSERT(_hal_mpl);
    VS_ASSERT(_hal_mpl->load);

    return _hal_mpl->load(element_info, out_data, buf_sz, out_sz);
}

/******************************************************************************/
int
vs_secbox_del(vs_secbox_element_info_t *element_info) {
    VS_ASSERT(_hal_mpl);
    VS_ASSERT(_hal_mpl->del);
    VS_ASSERT(element_info);

    return _hal_mpl->del(element_info);
}