import base64
import io
import os

import struct

from binascii import unhexlify
from pyasn1.codec.ber import decoder
from pyasn1.type import univ, namedtype
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.cryptography.hashes import HashAlgorithm
from virgilsign.libs.sign_processor import SignProcessor
from .ui import UI

from os.path import basename
from .atmel_device_manager import AtmelDeviceManager


class AtmelSignProcessor(SignProcessor):
    """
    Handling firmware sign operations
    """

    def __init__(self, atmel_util_path, firmware_path, prog_firmware_path, 
        update_firmware_path, prog_file_size, firmware_version, manufacturer, model, chunkSize, applicationType, buildtime):
        super().__init__(firmware_path, prog_firmware_path, 
        update_firmware_path, prog_file_size, firmware_version, manufacturer, model, chunkSize, applicationType, buildtime)

        self.crypto = VirgilCrypto()
        self.crypto.signature_hash_algorithm = HashAlgorithm.SHA256
        self.__atmel_device_manager = AtmelDeviceManager(atmel_util_path)
        self.__ui = UI()

        self.__load_private_keys()
        self.signatures_size = len(self.private_keys) * (64 + 2 + 1)  # key_count * (sign_size + key_id + key_type)

    def __load_private_keys(self):
        self.__ui.print_message("Please choose auth key for sign: ")
        auth_device = self.__atmel_device_manager.choose_atmel_device("auth")

        self.private_keys.append(self.__private_key(auth_device))

        self.__ui.print_message("Please choose firmware key for sign: ")
        firmware_device = self.__atmel_device_manager.choose_atmel_device("firmware")
        self.private_keys.append(self.__private_key(firmware_device))

    def __private_key(self, device):
        key = {}
        if (device["type"] not in self.KEY_TYPES):
            raise ValueError('[ERROR]: Wrong key type')
        key['type'] = self.KEY_TYPES[device["type"]]
        key['id'] = int(device["key_id"])
        key['data'] = device["device_serial"]

        return key


    def __signature(self, choosed_device_serial, bytes_to_sign):
        return self.__atmel_device_manager.sign_by_device(choosed_device_serial, bytes_to_sign)


    def get_full_signature(self, private_key_data, bytes_to_sign):
        signature = self.__signature(private_key_data, bytes_to_sign)
        return base64.b64decode(signature)




            
    



