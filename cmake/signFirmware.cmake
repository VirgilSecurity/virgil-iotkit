cmake_minimum_required (VERSION 3.11)

function(sign_firmware _target_name
        _path_to_config_file
        _path_to_firmware_image
        _app_size
        _app_version
        _manufacture_id
        _device_model
        _chunk_size
        _app_type)

    if(NOT VIRGIL_IOT_BINARY_DIRECTORY)
        message(FATAL_ERROR "[sign-firmware] VIRGIL_IOT_BINARY_DIRECTORY variable containing path to the Virgil IOT SDK binary is not specified")
    endif()

    set(_path_to_signer "${VIRGIL_IOT_BINARY_DIRECTORY}/tools/virgil-firmware-signer/virgil-firmware-signer")

    set(SIGN_FIRMWARE_PROCESSING ${_path_to_signer}
            --config ${_path_to_config_file}
            --input ${_path_to_firmware_image}
            --file-size ${_app_size}
            --fw-version ${_app_version}
            --manufacturer ${_manufacture_id}
            --model ${_device_model}
            --chunk-size ${_chunk_size})

    add_custom_target(${_target_name}
            COMMAND ${SIGN_FIRMWARE_PROCESSING}
            )

endfunction()