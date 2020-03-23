/* Wear levelling and FAT filesystem example.
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.

   This sample shows how to store files inside a FAT filesystem.
   FAT filesystem is stored in a partition inside SPI flash, using the
   flash wear levelling library.
*/

#include <sdkconfig.h>
#include <platform/init/idf/flash_data.h>

typedef struct partition_stat_s {
    wl_handle_t wl_handle;
    char *flash_part;
} partition_stat_t;

// Handle of the wear levelling library instance
static partition_stat_t _part_stat[FF_VOLUMES];

//*************************************************************************************************************
static partition_stat_t *
_search_flash_part(const char *flash_part, partition_stat_t **free_part_stat) {
    int i;

    if (NULL != free_part_stat) {
        *free_part_stat = NULL;
        for (i = 0; i < FF_VOLUMES; i++) {
            if (NULL == _part_stat[i].flash_part) {
                *free_part_stat = &_part_stat[i];
                break;
            }
        }
    }

    for (i = 0; i < FF_VOLUMES; i++) {
        if (NULL != _part_stat[i].flash_part) {
            if (0 == strncmp(_part_stat[i].flash_part, flash_part, CONFIG_SPIFFS_OBJ_NAME_LEN)) {
                return &_part_stat[i];
            }
        }
    }

    return NULL;
}

//*************************************************************************************************************
esp_err_t
flash_data_deinit(const char *flash_part) {
    char tmp_path[CONFIG_SPIFFS_OBJ_NAME_LEN];
    esp_err_t err;

    partition_stat_t *p_stat = _search_flash_part(flash_part, NULL);
    CHECK_RET(NULL != p_stat, ESP_ERR_INVALID_STATE, "Partition has already unmounted");

    snprintf(tmp_path, sizeof(tmp_path), "/%s", flash_part);
    err = esp_vfs_fat_spiflash_unmount(tmp_path, p_stat->wl_handle);
    if (err != ESP_OK) {
        VS_LOG_ERROR("Failed to unmount FATFS (%s)", esp_err_to_name(err));
    } else {
        VS_IOT_FREE(p_stat->flash_part);
        p_stat->flash_part = NULL;
    }
    return err;
}

//*************************************************************************************************************
esp_err_t
flash_data_init(const char *flash_part) {
    char tmp_path[CONFIG_SPIFFS_OBJ_NAME_LEN];
    esp_err_t err;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4, .format_if_mount_failed = true, .allocation_unit_size = CONFIG_WL_SECTOR_SIZE};

    partition_stat_t *free_part_stat = NULL;

    CHECK_RET(NULL == _search_flash_part(flash_part, &free_part_stat),
              ESP_ERR_INVALID_STATE,
              "Partition has already mounted");
    CHECK_RET(NULL != free_part_stat, ESP_ERR_NO_MEM, "Free logical volume slot has not found");

    snprintf(tmp_path, sizeof(tmp_path), "/%s", flash_part);
    VS_LOG_DEBUG("Mounting %s -> %S", flash_part, tmp_path);
    err = esp_vfs_fat_spiflash_mount(tmp_path, flash_part, &mount_config, &free_part_stat->wl_handle);

    if (err != ESP_OK) {
        VS_LOG_ERROR("Failed to mount FATFS (%s)", esp_err_to_name(err));
    } else {
        free_part_stat->flash_part = VS_IOT_CALLOC(1, CONFIG_SPIFFS_OBJ_NAME_LEN);
        strncpy(free_part_stat->flash_part, flash_part, CONFIG_SPIFFS_OBJ_NAME_LEN);
    }

    return err;
}
