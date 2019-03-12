from enum import IntEnum
from PyCRC.CRCCCITT import CRCCCITT
import base64

import io


class TrustList(object):

    class TrustListType(IntEnum):
        RELEASE = 0
        BETA = 1
        ALPHA = 2
        DEV = 3

    class KeyType(IntEnum):
        FIRMWARE_SERVICE_PUB_KEY = 1
        SAMS_PUB_KEY = 2
        FACTORY_PUB_KEY = 3
        FIRMWARE_INTERNAL_PUB_KEY = 8
        AUTH_INTERNAL_PUB_KEY = 9

    class Header(object):

        def __init__(self, whole_tl_size, version, pub_key_count):
            self.whole_tl_size = whole_tl_size  # type: int  # Bytes size of header+body+footer
            self.version = version  # type: int  # Incremented value stored at this machine
            self.pub_key_count = pub_key_count  # type: int
            self.reserved_place = bytearray(24)  # type: bytearray

        def __bytes__(self):
            # type: () -> bytes
            byte_buffer = io.BytesIO()
            byte_buffer.write(self.whole_tl_size.to_bytes(4, byteorder='little', signed=False))
            byte_buffer.write(self.version.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.pub_key_count.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.reserved_place)
            return bytes(byte_buffer.getvalue())

    class Footer(object):

        def __init__(self, auth_key_id, auth_signature, tl_service_id, tl_sevice_sign, tl_type):
            self.auth_key_id = int(auth_key_id)  # type: int
            self.auth_signature = bytearray(auth_signature)  # type: bytearray
            self.tl_service_id = int(tl_service_id)  # type: int
            self.tl_service_sign = bytearray(tl_sevice_sign)  # type: bytearray
            self.tl_type = tl_type  # type: TrustList.TrustListType
            self.reserved_place = bytearray(32)  # type: bytearray

        def __bytes__(self):
            # type: () -> bytes
            byte_buffer = io.BytesIO()
            byte_buffer.write(self.auth_key_id.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.auth_signature)
            byte_buffer.write(self.tl_service_id.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.tl_service_sign)
            byte_buffer.write(bytes([self.tl_type]))
            byte_buffer.write(self.reserved_place)
            return bytes(byte_buffer.getvalue())

    class PubKeyStructure(object):

        def __init__(self, pub_key, pub_key_type):
            self._key_id = None  # type: int
            self.__key_type = pub_key_type  # type: TrustList.PubKeyStructure.KeyType
            self.__pub_key = base64.b64decode(pub_key)  # type: bytearray
            self.__reserved_place = bytearray(28)  # type: bytearray

        def __bytes__(self):
            # type: () -> bytes
            byte_buffer = io.BytesIO()
            byte_buffer.write(self.__pub_key)
            byte_buffer.write(self.__key_id.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.__key_type.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self.__reserved_place)

            return bytes(byte_buffer.getvalue())

        @property
        def __key_id(self):
            return CRCCCITT().calculate(self.__pub_key)

    def __init__(self, pub_key_dict, tl_type, tl_version, custom_keys_structure_block=None):
        self.__pub_key_dict = pub_key_dict
        self.__tl_type = tl_type  # type: TrustList.TrustListType
        self.__tl_version = tl_version  # type: int
        self.__custom_keys_structure_block = custom_keys_structure_block

        self._auth_key_id = 0  # type: int  # unsigned 2 byte int
        self._auth_key_signature = bytearray(64)

        self._tl_service_key_id = 0  # type: int
        self._tl_service_key_signature = bytearray(64)

        self._header = None  # type: TrustList.Header
        self._footer = None  # type: TrustList.Footer
        self._body = None  # type: List(TrustList.PubKeyStructure)

    def __bytes__(self):
        # type: () -> bytes
        byte_buffer = io.BytesIO()
        byte_buffer.write(bytes(self.header))
        byte_buffer.write(bytes(self.__get_body_bytes()))
        byte_buffer.write(bytes(self.__footer))
        return bytes(byte_buffer.getvalue())

    def __get_body_bytes(self):
        byte_buffer = io.BytesIO()
        if self.__custom_keys_structure_block:
            byte_buffer.write(self.__custom_keys_structure_block)
        for pub_key in self.body:
            byte_buffer.write(bytes(pub_key))
        return bytes(byte_buffer.getvalue())

    def get_bytes_for_sign(self):
        byte_buffer = io.BytesIO()
        byte_buffer.write(bytes(self.header))
        byte_buffer.write(bytes(self.__get_body_bytes()))
        return bytes(byte_buffer.getvalue())

    @property
    def body(self):
        if not self._body:
            self._body = []
            for pub_key_id in self.__pub_key_dict.keys():
                key_type = 0

                if self.__pub_key_dict[pub_key_id]["type"] == "firmware":
                    key_type = TrustList.KeyType.FIRMWARE_SERVICE_PUB_KEY
                if self.__pub_key_dict[pub_key_id]["type"] == "cloud":
                    key_type = TrustList.KeyType.SAMS_PUB_KEY
                if self.__pub_key_dict[pub_key_id]["type"] == "factory":
                    key_type = TrustList.KeyType.FACTORY_PUB_KEY
                if self.__pub_key_dict[pub_key_id]["type"] == "auth_internal":
                    key_type = TrustList.KeyType.AUTH_INTERNAL_PUB_KEY
                if self.__pub_key_dict[pub_key_id]["type"] == "firmware_internal":
                    key_type = TrustList.KeyType.FIRMWARE_INTERNAL_PUB_KEY

                if key_type:
                    key_structure = TrustList.PubKeyStructure(self.__pub_key_dict[pub_key_id]["key"], key_type)
                    self._body.append(key_structure)

        return self._body

    @property
    def header(self):
        if not self._header:
            if self.__custom_keys_structure_block:
                whole_tl_size = len(self.body) * 96 + 32 + 165 + len(self.__custom_keys_structure_block) # KeyN * sizeofKey (96) + sizeofHeader (32) + sizeofFooter (165) + size of custom key structure block
            else:
                whole_tl_size = len(self.body) * 96 + 32 + 165  # KeyN * sizeofKey (96) + sizeofHeader (32) + sizeofFooter (165)
            if self.__custom_keys_structure_block:
                keys_count = int(len(self.body) + (len(self.__custom_keys_structure_block) / 96))
            else:
                keys_count = len(self.body)
            self._header = TrustList.Header(
                whole_tl_size,
                self.__tl_version,
                keys_count,
            )
        return self._header

    @property
    def auth_key_id(self):
        return self._auth_key_id

    @auth_key_id.setter
    def auth_key_id(self, key_id):
        self._auth_key_id = int(key_id)

    @property
    def auth_key_signature(self):
        return self._auth_key_signature

    @auth_key_signature.setter
    def auth_key_signature(self, signature):
        self._auth_key_signature = base64.b64decode(signature)

    @property
    def tl_service_key_signature(self):
        return self._tl_service_key_signature

    @tl_service_key_signature.setter
    def tl_service_key_signature(self, signature):
        self._tl_service_key_signature = base64.b64decode(signature)

    @property
    def tl_service_key_id(self):
        return self._tl_service_key_id

    @tl_service_key_id.setter
    def tl_service_key_id(self, key_id):
        self._tl_service_key_id = int(key_id)

    @property
    def __footer(self):
        if not self._footer:
            self._footer = TrustList.Footer(
                self.auth_key_id,
                self.auth_key_signature,
                self.tl_service_key_id,
                self.tl_service_key_signature,
                self.__tl_type
            )
        return self._footer
