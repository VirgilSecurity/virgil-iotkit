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

from os.path import basename

class HashedType(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('oid', univ.ObjectIdentifier()),
                                         namedtype.NamedType('null', univ.Null())
                                         )


class InnerSignatures(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('first_sign_part', univ.Integer()),
                                         namedtype.NamedType('second_sign_part', univ.Integer())
                                         )


class Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('hashed', HashedType()),
                                         namedtype.NamedType('sign', univ.OctetString())
                                         )


class VirgilSignProcessor(SignProcessor):
    """
    Handling firmware sign operations
    """
    KEY_TYPES = {'auth': 4, 'firmware': 1}

    def __init__(self, private_keys_paths, firmware_path, prog_firmware_path, 
        update_firmware_path, prog_file_size, firmware_version, manufacturer, model, chunkSize, applicationType, buildtime):
        super().__init__(firmware_path, prog_firmware_path, 
        update_firmware_path, prog_file_size, firmware_version, manufacturer, model, chunkSize, applicationType, buildtime)

        self.crypto = VirgilCrypto()
        self.crypto.signature_hash_algorithm = HashAlgorithm.SHA256
        self.private_keys_paths = private_keys_paths
        self.__load_private_keys()
        self.signatures_size = len(self.private_keys) * (64 + 2 + 1)  # key_count * (sign_size + key_id + key_type)

    def __load_private_keys(self):
        for private_key_path in self.private_keys_paths:
            self.private_keys.append(self.__private_key(private_key_path))


    def __private_key(self, private_key_path):
        key = {}
        # Get filename
        key_name = basename(private_key_path)

        # Get key type and key id from formatted filename "type_id"
        file_name = key_name.split(".")[0]

        key_info = file_name.split("_") 
        if (key_info[0] not in self.KEY_TYPES):
            raise ValueError('[ERROR]: Wrong key type')
        key['type'] = self.KEY_TYPES[key_info[0]]
        
        if "internal" in key_name:
            key['id'] = int(key_info[2])
        else:
            key['id'] = int(key_info[1])
	       
        with open(private_key_path, mode='rb') as file:
            key['data'] = self.crypto.import_private_key(bytearray(file.read()))

        return key



    def get_full_signature(self, private_key_data, bytes_to_sign):
        signature_no_compress = self.__virgil_sign_by_key(private_key_data, bytes_to_sign)

        asn_one_signature_no_compress = decoder.decode(base64.b64decode(signature_no_compress),
                                                       asn1Spec=Signature())
        asn_one_signature_no_compress = decoder.decode(asn_one_signature_no_compress[0]['sign'],
                                                       asn1Spec=InnerSignatures())
        full_signature = self.__long_to_bytes(asn_one_signature_no_compress[0]['first_sign_part'].__int__()) +\
        self.__long_to_bytes(asn_one_signature_no_compress[0]['second_sign_part'].__int__())
        return full_signature


    def __virgil_sign_by_key(self, private_key, bytes_to_sign):
        signature = self.crypto.sign(bytes_to_sign, private_key)
        return base64.b64encode(bytes(signature)).decode("utf-8")          

    def __long_to_bytes(self, val, endianness='big'):
        byte_buffer = io.BytesIO()
        byte_buffer.write(int(val).to_bytes(32, byteorder=endianness, signed=False))
        return bytearray(byte_buffer.getvalue())