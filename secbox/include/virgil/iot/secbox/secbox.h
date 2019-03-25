

typedef int (*vs_secbox_save_hal_t)();
typedef int (*vs_secbox_load_hal_t)();
typedef int (*vs_secbox_del_hal_t)();

typedef struct {
    vs_secbox_save_hal_t save;
    vs_secbox_load_hal_t load;
    vs_secbox_del_hal_t del;
} vs_secbox_hal_impl_t;

int
vs_secbox_configure_hal(const vs_secbox_hal_impl_t *impl);

int
vs_secbox_save();

int
vs_secbox_load();

int
vs_secbox_del();