import base64
import binascii
import json
import os
import sys
from io import BytesIO

from PyCRC.CRCCCITT import CRCCCITT

from virgil_trust_provisioner.storage.tinydb_storage_extensions import SignedByteStorage


class CryptoByteStorage(SignedByteStorage):
    def __init__(self, path, create_dirs=False, **kwargs):
        super(CryptoByteStorage, self).__init__(path, create_dirs, **kwargs)
        self._rec_pub_keys = None

    def _sign(self, data_bytes):
        self._plugged_dongles()
        upper_level_rows = self._upper_level_db.get_values(suppress_db_warning=self._suppress_db_warning)

        signature = None
        required_keys = self._check_required_keys(upper_level_rows)

        signer_id = 0
        if self._auth and required_keys:
            # signer id need to identify auth key used for sign dbs
            device_for_sign = None
            # get file signer id (crc16 from signer public key)
            if self._get_file_size():
                self._handle.seek(0)
                raw_signer_id = self._handle.read(2)
                signer_id = int.from_bytes(raw_signer_id, byteorder='big', signed=False)
            if signer_id != 0:
                for key in self._auth:
                    auth_pub_key = self._a_check(self._atmel.get_public_key(key))
                    auth_key_id = CRCCCITT().calculate(base64.b64decode(auth_pub_key))
                    if signer_id == auth_key_id:
                        device_for_sign = key
                        break
                if not device_for_sign:
                    self._ui.print_error("Can't sign by Auth Key")
                else:
                    signature = base64.b64decode(self._sign_on_dongle(data_bytes, device_for_sign))
            else:
                signer_device_serial = self._auth[0]
                auth_pub_key = self._a_check(self._atmel.get_public_key(signer_device_serial))
                signature = base64.b64decode(self._sign_on_dongle(data_bytes, signer_device_serial))
                signer_id = CRCCCITT().calculate(base64.b64decode(auth_pub_key))
        elif not required_keys:
            signature = bytearray(64)
        else:
            self._ui.print_error("Can't sign by Auth Key")
        signer_id = signer_id.to_bytes(2, byteorder='big', signed=False)
        return signature, signer_id

    def _verify(self, data, signer_id, signature_bytes):
        signer_id = int.from_bytes(signer_id, byteorder='big', signed=False)
        self._plugged_dongles()

        base64_data = base64.b64encode(bytes(data)).decode()

        upper_level_rows = None
        if self._upper_level_db:
            upper_level_rows = self._upper_level_db.get_values(suppress_db_warning=self._suppress_db_warning)

        if not all(b == 0 for b in signature_bytes):
            signature_base64 = base64.b64encode(signature_bytes).decode()
            signer_dongle_serial = 0
            for auth_key in self._auth:
                auth_pub_key = self._a_check(self._atmel.get_public_key(auth_key))
                auth_key_id = CRCCCITT().calculate(base64.b64decode(auth_pub_key))
                if auth_key_id == signer_id:
                    signer_dongle_serial = auth_key
                    break
            if not signer_dongle_serial:
                return False
            else:
                return self._verify_on_dongle(base64_data, signature_base64, signer_dongle_serial)
        else:
            if self._check_required_keys(upper_level_rows) and not self._suppress_db_warning:
                return False
            else:
                return True

    def _decrypt(self, encrypted_data, data_parts_count):
        # TODO need actualize byte addressing for new version of sign
        # self._plugged_dongles()
        #
        encrypted_data_buffer = BytesIO(encrypted_data)
        while data_parts_count > 0:
            part_size = int.from_bytes(encrypted_data_buffer.read(2), byteorder='big', signed=False)
            data_part = base64.b64encode(encrypted_data_buffer.read(part_size)).decode()
            return json.loads(base64.b64decode(data_part).decode())
        #     if self._auth:
        #         for auth in self._auth:
        #             try:
        #                 decrypted_data = self._decrypt_on_dongle(data_part, auth)
        #                 return json.loads(decrypted_data)
        #             except UnicodeDecodeError as e:
        #                 pass
        #     else:
        #         self._ui.print_error("Can't find Auth Key for decrypt")
        #     data_parts_count -= 1
        # sys.exit("[FATAL]: Can't decrypt db by inserted Auth Key")


    def _decrypt_on_dongle(self, encrypted_data, device_serial):
        ops_status = self._atmel.decrypt_by_device(encrypted_data, device_serial=device_serial)
        if not ops_status[0]:
            if "Error crypt file on chip!" in ops_status[1]:
                return
            else:
                sys.exit(ops_status[1])
        return base64.b64decode(ops_status[1]).decode()

    def _encrypt(self, serialized_data):
        # TODO need actualize byte addressing for new version of sign
        # if not any(self.__rec_pub_keys):
        #     sys.exit("[FATAL]: Not found Recovery Key for encrypt")
        #
        # data_parts = list()
        # if self._auth:
        #     auth_pub_key = self._a_check(self._atmel.get_public_key(self._auth[0]))
        #     if not auth_pub_key:
        #         sys.exit("Can't get Auth Public Key for db encryption")
        #     data_parts.append(self._encrypt_on_dongle(serialized_data, auth_pub_key, self._auth[0]))
        #     for rec_pub_key in self.__rec_pub_keys:
        #         data_parts.append(self._encrypt_on_dongle(serialized_data, rec_pub_key, self._auth[0]))
        #
        # byte_buffer = BytesIO()
        # for data_part in data_parts:
        #     byte_buffer.write(len(bytearray(data_part)).to_bytes(2, byteorder='big', signed=False))
        #     byte_buffer.write(data_part)
        # encrypted_data = byte_buffer.getvalue()
        # return len(data_parts), encrypted_data

        byte_buffer = BytesIO()
        byte_buffer.write(len(bytearray(serialized_data)).to_bytes(2, byteorder='big', signed=False))
        byte_buffer.write(serialized_data)
        return 1, byte_buffer.getvalue()

    def _encrypt_on_dongle(self, raw_data, recipient_pub_key, device_serial):
        data = self._a_check(self._atmel.crypt_by_device(
            base64.b64encode(raw_data).decode(),
            recipient_pub_key,
            device_serial=device_serial)
        )
        if data:
            return base64.b64decode(data)
        else:
            sys.exit()

    def read(self):
        # Get the file size
        self._handle.seek(0, os.SEEK_END)
        size = self._handle.tell()

        if not size:
            # File is empty
            return None

        try:
            self._handle.seek(0)
            signer_id = self._handle.read(2)
            signature_data = self._handle.read(64)
            data_parts_count = int.from_bytes(self._handle.read(2), byteorder='big', signed=False)
            encrypted_data = bytearray(binascii.unhexlify(self._handle.read().decode()))

            if not self._verify(encrypted_data, signer_id, signature_data):
                return
            return self._decrypt(encrypted_data, data_parts_count)
        except UnicodeDecodeError:
            sys.exit("[FATAL]: Wrong database format!")

    def write(self, data):
        self._plugged_dongles()
        serialized_data = json.dumps(data, **self.kwargs).encode()

        data_parts_count, encrypted_data = self._encrypt(serialized_data)
        signature, signer_id = self._sign(encrypted_data)

        if signature is None:
            return

        self._handle.seek(0)
        self._handle.write(signer_id)
        self._handle.seek(2)
        self._handle.write(signature)
        self._handle.seek(66)
        self._handle.write(data_parts_count.to_bytes(2, byteorder='big', signed=False))
        self._handle.seek(68)
        self._handle.write(bytearray(binascii.hexlify(encrypted_data)))
        self._handle.flush()
        self._handle.truncate()

    @property
    def __rec_pub_keys(self):
        if not self._rec_pub_keys:
            pub_keys = [None] * 2
            upper_keys = list(self._upper_level_db.get_values(suppress_db_warning=self._suppress_db_warning))
            for key in upper_keys:
                if key["type"] == "recovery":
                    if str(key["comment"]) == '1':
                        pub_keys[0] = key["key"]
                    if str(key["comment"]) == '2':
                        pub_keys[1] = key["key"]
            self._rec_pub_keys = pub_keys
        return self._rec_pub_keys
