import base64
import json
import os
import binascii

import sys

from PyCRC.CRCCCITT import CRCCCITT
from tinydb import Storage
from tinydb.storages import touch

from soraa_keymanager.data_types import DongleType


class SignedByteStorage(Storage):
    """
    Store the data in a hexlified pickled bytes file with signatures of Auth and TL Service keys.
    """

    def __init__(self, path, create_dirs=False, **kwargs):
        """
        Create a new instance.

        Also creates the storage file, if it doesn't exist.

        :param path: Where to store the JSON data.
        :type path: str
        """

        super(SignedByteStorage, self).__init__()
        touch(path, create_dirs=create_dirs)  # Create file if not exists
        self._path = path
        self.kwargs = kwargs
        self._atmel = self.kwargs.pop("atmel")
        self._ui = self.kwargs.pop("ui")
        self._upper_level_db = self.kwargs.pop("upper_level_keys_db")
        self._suppress_db_warning = self.kwargs.pop("suppress_db_warning") or False
        self._handle = open(path, 'r+b')
        self._required_key_type = DongleType.AUTH.value
        self._auth = list()

    def _a_check(self, atmel_ops_status):
        """
        Atmel operation checker. Check status of operation.

        Args:
            atmel_ops_status: atmel operation output
        Returns:
            In error case print error and return 0
            In success return, object of function return
        """
        if not atmel_ops_status[0]:
            self._ui.print_error(atmel_ops_status[1])
            return 0
        return atmel_ops_status[1]

    def _plugged_dongles(self):
        while True:
            device_list = self._a_check(self._atmel.list_devices())

            if device_list:
                for device_serial in device_list:
                    dev_info = self._a_check(self._atmel.info(device_serial=device_serial))
                    if "type" in dev_info.keys() \
                            and dev_info["type"] == DongleType.AUTH.value \
                            and device_serial not in self._auth:
                        self._auth.append(device_serial)

            if not self._auth and not self._suppress_db_warning:
                self._ui.print_warning("Not found Auth Keys")
                user_choice = str(
                    self._ui.get_user_input(
                        "Rescan dongles? [y/n]: ",
                        input_checker_callback=self._ui.InputCheckers.yes_no_checker,
                        input_checker_msg="Allowed answers [y/n]. Please try again: ",
                        empty_allow=False
                    )
                ).upper()
                if user_choice == "N":
                    sys.exit("Operation stopped by user")
                continue
            else:
                return

    def _sign(self, data):
        self._plugged_dongles()
        if self._upper_level_db:
            upper_level_rows = self._upper_level_db.get_values(suppress_db_warning=self._suppress_db_warning)
        else:
            upper_level_rows = self._get_values(data)

        serialized = json.dumps(data, **self.kwargs).encode()
        signature = None

        required_keys = self._check_required_keys(upper_level_rows)
        # signer id need to identify auth key used for sign dbs
        signer_id = 0
        if self._auth and required_keys:
            device_for_sign = None
            # get file signer id (crc16 from signer public key)
            if self._get_file_size():
                self._handle.seek(0)
                raw_signer_id = self._handle.read(2)
                signer_id = int.from_bytes(raw_signer_id, byteorder='little', signed=False)
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
                    signature = base64.b64decode(self._sign_on_dongle(serialized, device_for_sign))
            else:
                signer_device_serial = self._auth[0]
                auth_pub_key = self._a_check(self._atmel.get_public_key(signer_device_serial))
                signature = base64.b64decode(self._sign_on_dongle(serialized, signer_device_serial))
                signer_id = CRCCCITT().calculate(base64.b64decode(auth_pub_key))
        elif not required_keys:
            signature = bytearray(64)
        else:
            self._ui.print_error("Can't sign by Auth Key")
        signer_id = signer_id.to_bytes(2, byteorder='little', signed=False)
        return serialized, signer_id, signature

    def _sign_on_dongle(self, data, device_serial):
        if not device_serial:
            return None
        return self._a_check(self._atmel.sign_by_device(base64.b64encode(data).decode(), device_serial=device_serial))

    def _verify(self, data, signer_id, signature_bytes):
        signer_id = int.from_bytes(signer_id, byteorder='little', signed=False)
        self._plugged_dongles()

        base64_data = base64.b64encode(bytes(data)).decode()
        loaded_data = json.loads(data.decode())

        if self._upper_level_db:
            upper_level_rows = self._upper_level_db.get_values(suppress_db_warning=self._suppress_db_warning)
        else:
            upper_level_rows = self._get_values(loaded_data)

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
                auth_verify = False
            else:
                auth_verify = self._verify_on_dongle(base64_data, signature_base64, signer_dongle_serial)
        else:
            if self._check_required_keys(upper_level_rows) and not self._suppress_db_warning \
                    and len(loaded_data.values()) != 1 and not list(loaded_data.values())[0] == "{}":
                auth_verify = False
            else:
                auth_verify = True

        if auth_verify:
            return loaded_data
        else:
            sys.exit("[FATAL]: Db signature verification failed by ({}) Key!".format(DongleType.AUTH.value))

    def _verify_on_dongle(self, raw_data, signature, device_serial):
        signer_pub_key = self._a_check(self._atmel.get_public_key(device_serial))
        if not signer_pub_key:
            self._ui.print_error("Can't get Public Key for verify db signature")
            return
        return self._atmel.verify_by_device(
            raw_data,
            signature,
            signer_pub_key,
            device_serial=device_serial
        )

    def _check_required_keys(self, db_values):
        for db_row in db_values:
            if "type" in db_row.keys() and db_row["type"] == self._required_key_type:
                    return True

    def _get_file_size(self):
        self._handle.seek(0, os.SEEK_END)
        return self._handle.tell()

    @staticmethod
    def _get_values(data):
        db_data = list(data.values())
        if db_data:
            return list(db_data[0].values())

    def close(self):
        self._handle.close()

    def read(self):
        # Get the file size
        size = self._get_file_size()

        if not size:
            # File is empty
            return None

        try:
            self._handle.seek(0)
            signer_id = self._handle.read(2)
            signature_data = self._handle.read(64)
            self._handle.seek(66)
            data = binascii.unhexlify(self._handle.read().decode())
            return self._verify(data, signer_id, signature_data)
        except UnicodeDecodeError:
            sys.exit("[FATAL]: Wrong database format!")

    def write(self, data):
        serialized_data, signer_id, signature = self._sign(data)

        if signature is None:
            return

        self._handle.seek(0)
        self._handle.write(signer_id)
        self._handle.seek(2)
        self._handle.write(signature)
        self._handle.seek(66)
        self._handle.write(bytearray(binascii.hexlify(serialized_data)))
        self._handle.flush()
        self._handle.truncate()
