## Virgil Firmware Signer utility
Signs input file with firmware and creates two files: _Update and _Prog.
_Prog can be used directly on device. _Update file can be uploaded to cloud.

### Options
```
--config value, -c value        Path to config file
--input value, -i value         Input file
--file-size value, -s value     Output _Prog.bin file size in bytes (default: 0)
--fw-version value              Firmware version ([0-255].[0-255].[0-255].[0-4294967295])
--manufacturer value, -a value  Manufacturer
--model value, -d value         Model
--help, -h                      show help (default: false)
--version, -v                   print the version (default: false)
```

### Config example
Config is a json array with elements which represent signer keys. Example:
```json
[  
   {  
      "path":"/root/current-credentials/key_storage/private/auth_27254_auth2.key",
      "key_type":1
   },
   {  
      "path":"/root/current-credentials/key_storage/private/firmware_61777_firmware2.key",
      "key_type":3
   }
]
```
