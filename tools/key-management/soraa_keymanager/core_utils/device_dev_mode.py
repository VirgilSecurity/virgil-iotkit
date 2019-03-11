import base64
from io import BytesIO

import os


class DeviceDevMode(object):

    def __init__(self, ui, upper_level_keys_db, dev_id_list=None, dev_id_list_path=None, dev_id_result_path=None):
        self.__ui = ui
        self.__upper_level_keys = upper_level_keys_db
        self.__dev_id_list = dev_id_list
        self.__dev_id_list_path = dev_id_list_path
        self.__dev_id_result_path = dev_id_result_path
        self.__recovery_keys = []
        self.__auth_keys = []
        self.__tl_svc_keys = []
        self.__firmware_keys = []

    def __export_signed_key(self, key_id, key, signer_key_id=None, signature=None):
        byte_buffer = BytesIO()
        byte_buffer.write(int(key_id).to_bytes(2, byteorder='little', signed=False))
        byte_buffer.write(base64.b64decode(key))
        if signer_key_id and signature:
            byte_buffer.write(int(signer_key_id).to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(base64.b64decode(signature))
        else:
            byte_buffer.write(bytes(66))
        return bytes(byte_buffer.getvalue())

    def __get_signed_keys(self, storage):
        for key_id in storage.get_keys():
            if storage.get_value(key_id)["type"] == "recovery":
                self.__recovery_keys.append(
                    self.__export_signed_key(
                        key_id,
                        storage.get_value(key_id)["key"]
                    )
                )
            elif storage.get_value(key_id)["type"] == "auth":
                self.__auth_keys.append(
                    self.__export_signed_key(
                        key_id,
                        storage.get_value(key_id)["key"],
                        signer_key_id=storage.get_value(key_id)["signer_key_id"],
                        signature=storage.get_value(key_id)["signature"]
                    )
                )
            elif storage.get_value(key_id)["type"] == "tl_service":
                self.__tl_svc_keys.append(
                    self.__export_signed_key(
                        key_id,
                        storage.get_value(key_id)["key"],
                        signer_key_id=storage.get_value(key_id)["signer_key_id"],
                        signature=storage.get_value(key_id)["signature"]
                    )
                )
            elif storage.get_value(key_id)["type"] == "firmware":
                self.__firmware_keys.append(
                    self.__export_signed_key(
                        key_id,
                        storage.get_value(key_id)["key"],
                        signer_key_id=storage.get_value(key_id)["signer_key_id"],
                        signature=storage.get_value(key_id)["signature"]
                    )
                )

    def __get_raw_keys(self, storage):
        for key_id in storage.get_keys():
            if storage.get_value(key_id)["type"] == "recovery":
                self.__recovery_keys.append(base64.b64decode(storage.get_value(key_id)["key"]))
            elif storage.get_value(key_id)["type"] == "auth":
                self.__auth_keys.append(base64.b64decode(storage.get_value(key_id)["key"]))
            elif storage.get_value(key_id)["type"] == "tl_service":
                self.__tl_svc_keys.append(base64.b64decode(storage.get_value(key_id)["key"]))
            elif storage.get_value(key_id)["type"] == "firmware":
                self.__firmware_keys.append(base64.b64decode(storage.get_value(key_id)["key"]))

    def enable(self):
        self.__get_raw_keys(self.__upper_level_keys)

        if self.__dev_id_result_path:
            if not os.path.exists(os.path.split(self.__dev_id_result_path)[0]):
                os.makedirs(os.path.split(self.__dev_id_list_path)[0])
            output_file = open(self.__dev_id_result_path, "wb")
        else:
            output_file = None

        if not self.__dev_id_list_path and self.__dev_id_list:
            device_ids = self.__dev_id_list
        else:
            if not os.path.exists(self.__dev_id_list_path):
                self.__ui.print_error("Can't find device_list at {}".format(self.__dev_id_list_path))
                return
            device_ids = open(self.__dev_id_list_path, "r").readlines()

        dev_mode_requests = list()
        for dev_id in device_ids:
            byte_buffer = BytesIO()

            byte_buffer.write(b"".join(self.__recovery_keys))
            byte_buffer.write(b"".join(self.__auth_keys))
            byte_buffer.write(b"".join(self.__tl_svc_keys))
            byte_buffer.write(b"".join(self.__firmware_keys))
            byte_buffer.write(base64.b64decode(dev_id))

            if output_file:
                output_file.write(base64.b64encode(byte_buffer.getvalue()) + b"\n")
            dev_mode_requests.append(base64.b64encode(byte_buffer.getvalue()).decode())
            byte_buffer.close()

        if output_file:
            output_file.close()
        return dev_mode_requests
