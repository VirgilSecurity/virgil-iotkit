import base64

import sys
from PyCRC.CRCCCITT import CRCCCITT


class DongleChooser(object):

    def __init__(
            self,
            ui,
            atmel,
            dongles_cache,
            upper_level_pub_keys=None,
            trust_list_pub_keys=None,
            logger=None
    ):
        self.__ui = ui
        self.__atmel = atmel
        self.__logger = logger
        self.__upper_level_pub_keys = upper_level_pub_keys
        self.__trust_list_pub_keys = trust_list_pub_keys
        self.__dongles_cache = dongles_cache

    def list_devices_info_db(self, devices_serials, suppress_db_warning=False):
        devices_info = []
        if self.__upper_level_pub_keys is None and self.__trust_list_pub_keys is None:
            return devices_info
        for device in devices_serials:
            cache_info = self.__dongles_cache.search_serial(device)
            if cache_info:
                devices_info.append(cache_info)
            else:
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
                        if self.__logger:
                            self.__logger.error("operation failed: {}".format(ops_status[1]))
                        sys.exit(ops_status[1])
                else:
                    public_key = ops_status[1]
                    del ops_status
                    key_id = str(CRCCCITT().calculate(base64.b64decode(public_key)))
                    if str(key_id) in self.__upper_level_pub_keys.get_keys(suppress_db_warning=suppress_db_warning):
                        info = {"key_id": key_id, "device_serial": device}
                        info.update(self.__upper_level_pub_keys.get_value(key_id,
                                                                          suppress_db_warning=suppress_db_warning))
                        self.__dongles_cache.add(info)
                        devices_info.append(info)
                    elif str(key_id) in self.__trust_list_pub_keys.get_keys(suppress_db_warning=suppress_db_warning):
                        info = {"key_id": key_id, "device_serial": device}
                        info.update(self.__trust_list_pub_keys.get_value(key_id,
                                                                         suppress_db_warning=suppress_db_warning))
                        self.__dongles_cache.add(info)
                        devices_info.append(info)
                    else:
                        info = {"key_id": "Unknown", "device_serial": device, "type": "Unknown", "comment": "Unknown"}
                        devices_info.append(info)
        if self.__logger:
            self.__logger.debug("Devices info from db: ")
            self.__logger.debug(devices_info)
        return devices_info

    def list_devices_info_hw(self, devices_serials):
        devices_info = []
        for device in devices_serials:
            cache_info = self.__dongles_cache.search_serial(device)
            if cache_info:
                devices_info.append(cache_info)
            else:
                ops_status = self.__atmel.info(device_serial=device)
                if not ops_status[0]:
                    if self.__logger:
                        self.__logger.error("operation failed: {}".format(ops_status[1]))
                    sys.exit(ops_status[1])
                dev_info_raw = ops_status[1]
                del ops_status

                if "public_key" in dev_info_raw.keys() and "type" in dev_info_raw.keys():
                    dev_info = dict()
                    dev_info["type"] = dev_info_raw["type"]
                    dev_info["public_key"] = dev_info_raw["public_key"]
                    dev_info["key_id"] = str(CRCCCITT().calculate(base64.b64decode(dev_info_raw["public_key"])))
                    dev_info["device_serial"] = device
                    dev_info["comment"] = "Unknown"
                elif dev_info_raw["lock_configuration"] == "false" and dev_info_raw["lock_data"] == "false":
                    dev_info = {"key_id": "Unknown", "device_serial": device, "type": "empty", "comment": "Unknown"}
                else:
                    dev_info = {"key_id": "Unknown", "device_serial": device, "type": "Unknown", "comment": "Unknown"}
                devices_info.append(dev_info)
        if self.__logger:
            self.__logger.debug("Devices info from hw: ")
            self.__logger.debug(devices_info)
        return devices_info

    def choose_atmel_device(self, key_type, greeting_msg="Please choose dongle: ",
                            suppress_db_warning=False, hw_info=False):
        while True:
            ops_status = self.__atmel.list_devices()
            if not ops_status[0]:
                if self.__logger:
                    self.__logger.error("operation failed: {}".format(ops_status[1]))
                sys.exit(ops_status[1])
            if hw_info or not any([self.__upper_level_pub_keys, self.__trust_list_pub_keys]):
                device_list = self.list_devices_info_hw(ops_status[1])
                db_device_list = self.list_devices_info_db(ops_status[1], suppress_db_warning=suppress_db_warning)
                for dev in device_list:
                    sieved_list = list(
                        filter(
                            lambda x: dev["device_serial"] in x.values() and dev["type"] == x["type"],
                            db_device_list
                        )
                    )
                    if len(sieved_list) == 1:
                        dev_list_ind = device_list.index(dev)
                        device_list[dev_list_ind] = sieved_list[0]
                    else:
                        continue
            else:
                device_list = self.list_devices_info_db(ops_status[1], suppress_db_warning=suppress_db_warning)
            del ops_status

            device_list = list(filter(lambda x: x if x["type"] == key_type else None, device_list))
            device_info_list = []
            device_map_key = []

            for number in range(len(device_list)):
                info_line = "type: {key_type}, comment: {key_comment}, device serial: {device_serial}".format(
                    key_type=device_list[number]["type"],
                    key_comment=device_list[number]["comment"],
                    device_serial=device_list[number]["device_serial"]
                )
                device_info_list.append([info_line])
                device_map_key.append(device_list[number]["device_serial"])
            if len(device_list):
                if len(device_list) > 1:
                    self.__ui.print_message(
                        greeting_msg
                    )
                    user_choose = self.__ui.choose_from_list(
                        device_info_list,
                        "Please enter option number: ",
                        "Device list:"
                    )
                else:
                    user_choose = 0
            else:
                self.__ui.print_message("Cannot find dongle with a type [{}]. Please insert it".format(key_type))
                user_choice = str(
                    self.__ui.get_user_input(
                        "Rescan dongles? [y/n]: ",
                        input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                        input_checker_msg="Allowed answers [y/n]. Please try again: ",
                        empty_allow=False
                    )
                ).upper()
                if user_choice == "N":
                    sys.exit("Operation stopped by user")
                continue
            return device_map_key[user_choose]
