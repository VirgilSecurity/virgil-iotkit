import io
import os
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from base64 import b64encode, b64decode

from PyCRC.CRCCCITT import CRCCCITT

from virgil_keymanager.external_utils.atmel_dongles_controller import AtmelDonglesController

from virgil_keymanager.ui import UI

from virgil_keymanager.core_utils import DongleChooser, DonglesCache
from virgil_keymanager.core_utils.config import Config


class KeySigner(object):

    # byte size
    KEY_FILE_SIZE = 132

    def __init__(self):
        self._args = None
        self.__config = self.__load_configs()
        self._emulator = None
        self._emulator_mode = None
        self._dongles_cache = None
        self._file_for_resign = None
        self._ui = None
        self._atmel_util_path = None
        self._atmel = None

    def run(self):
        if not os.path.exists(self.__file_for_resign):
            sys.exit("[FATAL]: Can't find {}".format(self.__file_for_resign))

        if os.stat(self.__file_for_resign).st_size > self.KEY_FILE_SIZE:
            sys.exit("[FATAL]: File: {0} larger then {1} bytes".format(self.__file_for_resign, self.KEY_FILE_SIZE))

        if os.stat(self.__file_for_resign).st_size < self.KEY_FILE_SIZE:
            sys.exit("[FATAL]: File: {0} smaller then {1} bytes".format(self.__file_for_resign, self.KEY_FILE_SIZE))

        dongle_chooser = DongleChooser(self.__ui, self.__atmel, self.__dongles_cache)
        dongle_for_sign = dongle_chooser.choose_atmel_device(
            "recovery",
            "Please choose Recovery dongle for sign: "
        )

        raw_bytes_for_sign = open(self.__file_for_resign, "rb").read()
        bytes_for_sign = raw_bytes_for_sign[2:66]
        key_id_bytes = raw_bytes_for_sign[:2]
        ok, signature = self.__atmel.sign_by_device(b64encode(bytes_for_sign).decode(), device_serial=dongle_for_sign)
        if not ok:
            sys.exit("[FATAL]: Can't sign key data, by atmel util error: {}".format(signature))
        ok, signer_pub_key = self.__atmel.get_public_key(dongle_for_sign)
        if not ok:
            sys.exit("[FATAL]: Can't sign key data, by atmel util error: {}".format(signer_pub_key))
        signer_key_id = str(CRCCCITT().calculate(b64decode(signer_pub_key)))

        byte_buffer = io.BytesIO()
        byte_buffer.write(key_id_bytes)
        byte_buffer.write(bytes_for_sign)
        byte_buffer.write(int(signer_key_id).to_bytes(2, byteorder='big', signed=False))
        byte_buffer.write(b64decode(signature))

        open(self.__file_for_resign, "wb").write(bytes(byte_buffer.getvalue()))

    def __load_configs(self):
        config_path = self.__args.get('config', None)
        config = Config(config_path)
        required_content = {
            "MAIN": [
                "dongles_cli_path", "dongles_cli_emulator_path"
            ]
        }
        config.check_content(required_content)
        return config

    @property
    def __args(self):
        if not self._args:
            arguments = ArgumentParser(
                description='Key signer utility',
                formatter_class=RawTextHelpFormatter
            )
            arguments.add_argument("key_file_path", type=str, help="path to Key for sign")
            arguments.add_argument('-c', "--config", metavar="CONFIG_PATH", type=str, help="custom configuration file")
            arguments.add_argument('-d', '--development', action='store_true', help="development mode")
            arguments.add_argument('-e', "--emulator", action="store_true", help="emulator usage")
            self._args = vars(arguments.parse_args())
        return self._args

    @property
    def __emulator(self):
        if not self._emulator:
            self._emulator = "emulator" in self.__args.keys() and self.__args["emulator"]
        return self._emulator

    @property
    def __emulator_mode(self):
        if not self._emulator_mode:
            if self.__emulator:
                self._emulator_mode = "dev" if "development" in self.__args and self.__args["development"] else "main"
        return self._emulator_mode

    @property
    def __file_for_resign(self):
        if not self._file_for_resign:
            self._file_for_resign = self.__args["key_file_path"]
        return self._file_for_resign

    @property
    def __ui(self):
        if not self._ui:
            self._ui = UI()
        return self._ui

    @property
    def __atmel_util_path(self):
        if not self._atmel_util_path:
            if self.__emulator_mode:
                if "dongles_cli_emulator_path" in self.__config["MAIN"].keys():
                    self._atmel_util_path = self.__config["MAIN"]["dongles_cli_emulator_path"]
            else:
                if "dongles_cli_path" in self.__config["MAIN"].keys():
                    self._atmel_util_path = self.__config["MAIN"]["dongles_cli_path"]

            if not self._atmel_util_path:
                self._atmel_util_path = os.path.join(
                    os.path.dirname(sys.modules["virgil_keymanager"].__file__),
                    "external_utils",
                    "util",
                    "emulator" if self.__emulator_mode else "origin",
                    "dongles-cli"
                )
        return self._atmel_util_path

    @property
    def __atmel(self):
        if not self._atmel:
            self._atmel = AtmelDonglesController(self.__atmel_util_path, self.__emulator_mode)
        return self._atmel

    @property
    def __dongles_cache(self):
        if not self._dongles_cache:
            self._dongles_cache = DonglesCache()
        return self._dongles_cache
