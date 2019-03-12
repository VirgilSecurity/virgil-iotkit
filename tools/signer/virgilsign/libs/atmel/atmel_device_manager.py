import base64
import sys

import io
import os
import shutil

from PyCRC.CRCCCITT import CRCCCITT
from .atmel_dongles_controller import AtmelDonglesController
from .db_storage import DBStorage


from .ui import UI



class AtmelDeviceManager(object):

    def __init__(self, atmel_util_path):
        self.__atmel_util_path = atmel_util_path
        self.__atmel = AtmelDonglesController(self.__atmel_util_path)
 
        self.__ui = UI()

    ################ Utility Functions #################

    def __list_devices_info(self, devices_serials):
        devices_info = []
        for device in devices_serials:
            ops_status = self.__atmel.get_public_key(device)
            if not ops_status[0]:
                if "Can't get own public key!" in ops_status[1]:
                    op_s = self.__atmel.info(device)
                    if op_s[0]:
                        if "lock_configuration" in op_s[1].keys() and "lock_data" in op_s[1].keys():
                            if op_s[1]["lock_configuration"] is False and op_s[1]["lock_configuration"] is False:
                                info = {
                                    "key_id": "Unknown",
                                    "device_serial": device,
                                    "type": "empty",
                                    "comment": "Unknown"
                                }
                                devices_info.append(info)
                else:
                    sys.exit(ops_status[1])
            else:
                public_key = ops_status[1]
                key_id = CRCCCITT().calculate(base64.b64decode(public_key))

                ops_status = self.__atmel.get_key_type(device)
                device_type = ops_status[1]
                if not ops_status[0]:
                    info = {"key_id": "Unknown", "device_serial": device, "type": "Unknown", "comment": "Unknown"}
                else:
                    info = {"key_id": key_id, "device_serial": device, "type": device_type, "comment": "Unknown"}

                devices_info.append(info)

        return devices_info



    def choose_atmel_device(self, key_type):
        ops_status = self.__atmel.list_devices()

        if not ops_status[0]:
            sys.exit(ops_status[1])

        device_list = self.__list_devices_info(ops_status[1])

        device_list = list(filter(lambda x: x if x["type"] == key_type else None, device_list))

        device_info_dict = {}
        device_map_key = {}
        if len(device_list) > 0:
            for number in range(0, len(device_list)):
                device_info_dict[number + 1] = [
                    "type: {key_type}, comment: {key_comment}, device serial: {device_serial}".format(
                        key_type=device_list[number]["type"],
                        key_comment=device_list[number]["comment"],
                        device_serial=device_list[number]["device_serial"]
                    ),
                    None
                ]
                device_map_key[number + 1] = device_list[number]
        else:
            sys.exit("[FATAL]: Key with type '{}' doesn't exist.".format(key_type))
            
        if len(device_list) > 1:
            user_choose = self.__ui.choose_from_list(
                device_info_dict,
                "Please choose number of device from list: ",
                "Device list:"
            )
        else:
            user_choose = 1

        return device_map_key[user_choose]


    def sign_by_device(self, choosed_device_serial, bytes_to_sign):
        ops_status = self.__atmel.sign_by_device(base64.b64encode(bytes(bytes_to_sign)).decode("utf-8"), 
            device_serial=choosed_device_serial)
        if not ops_status[0]:
            raise BaseException(ops_status[1])
        return ops_status[1]


