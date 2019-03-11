Additional functional of registrar app.

1. It is support exel data file as source of card requests and visible serial numbers
2. It has capability to use as source of card requests txt file without visible serial (current functional in master branch).
3. It has new arguments:
   "--iot_priv_key" parameter with path to file with private key for signing serial (it can be current-credentials/virgil-app/iot-private.key file),
   "--base_url" parameter with base soraa services url (it can be found in current-credentials/virgil-app/base-url.txt file).
4. For activating new mode you should add flag "--xls_input" to run command line arguments of registrar and point exel file.
Also if you use register-devices.sh script you should use "xls" as 2nd arg and path to exel file as 3rd arg.
