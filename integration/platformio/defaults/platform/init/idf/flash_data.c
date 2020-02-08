/* Wear levelling and FAT filesystem example.
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.

   This sample shows how to store files inside a FAT filesystem.
   FAT filesystem is stored in a partition inside SPI flash, using the 
   flash wear levelling library.
*/

#include <platform/init/idf/flash_data.h>

// Handle of the wear levelling library instance
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;

//*************************************************************************************************************
esp_err_t flash_data_umount(const char *partition_label)
{
    char tmp_path[32];
    esp_err_t err = ESP_FAIL;
    
    snprintf(tmp_path, 32, "/%s", partition_label);
    err = esp_vfs_fat_spiflash_unmount(tmp_path, s_wl_handle);
    if (err != ESP_OK)
    {
        VS_LOG_ERROR("Failed to unmount FATFS (%s)", esp_err_to_name(err));
    }
    return err;
}

//*************************************************************************************************************
esp_err_t flash_data_mount(const char *partition_label)
{
    char tmp_path[32];
    esp_err_t err = ESP_FAIL;
    const esp_vfs_fat_mount_config_t mount_config = {
        .max_files = 4, 
        .format_if_mount_failed = true, 
        .allocation_unit_size = 512
        };
    snprintf(tmp_path, 32, "/%s", partition_label);
    VS_LOG_DEBUG("Mounting %s -> %S", partition_label, tmp_path);
    err = esp_vfs_fat_spiflash_mount(tmp_path, partition_label, &mount_config, &s_wl_handle);
    if (err != ESP_OK)
    {
        VS_LOG_ERROR("Failed to mount FATFS (%s)", esp_err_to_name(err));
    }
    return err;
}

//*************************************************************************************************************
esp_err_t flash_data_deinit(void)
{
    return flash_data_umount(PART_HSM);
}

//*************************************************************************************************************
esp_err_t flash_data_init(void)
{
    return flash_data_mount(PART_HSM);
}
