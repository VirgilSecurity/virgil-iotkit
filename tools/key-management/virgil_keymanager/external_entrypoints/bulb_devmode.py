import base64
import os
import shutil
import sys
from argparse import RawTextHelpFormatter, ArgumentParser
from io import BytesIO

from PyCRC.CRCCCITT import CRCCCITT
from virgil_sdk.cryptography import VirgilCrypto
from virgil_sdk.cryptography.hashes import HashAlgorithm

from virgil_keymanager.core_utils import VirgilSignExtractor, DeviceDevMode
from virgil_keymanager.core_utils.config import Config
from virgil_keymanager.storage.db_storage import DBStorage
from virgil_keymanager.ui import UI


class BulbDevMode(object):

    def __init__(self):
        self._args = None
        self.__config = self.__load_configs()
        self.__ui = UI()
        self._db_path = None
        self._upper_level_pub_keys = None
        self._cloud_private_key = None
        self._tl_private_key = None
        self._device_serials = None
        self._output_folder = None

    @staticmethod
    def __sign_by_crypto(priv_key, dev_id):
        crypto = VirgilCrypto()
        crypto.signature_hash_algorithm = HashAlgorithm.SHA256

        dev_id = dev_id.rstrip()
        sign_pyasn1 = crypto.sign(base64.b64decode(dev_id), crypto.import_private_key(priv_key))
        return VirgilSignExtractor.extract_sign(sign_pyasn1)

    @staticmethod
    def __get_signer_id(priv_key):
        crypto = VirgilCrypto()
        virgil_pub_key = crypto.extract_public_key(crypto.import_private_key(priv_key))
        tiny_pub_key = virgil_pub_key.value[-64:]
        return CRCCCITT().calculate(bytes(tiny_pub_key))

    def __sign_dev_credentials(self, dev_mode_request):
        self.__ui.print_message("Signing DevMode Enable requests...")
        dev_requests = dev_mode_request

        if not self.__cloud_private_key:
            self.__ui.print_error("Can't find any Cloud Keys!")
            sys.exit(1)

        if not self.__tl_private_key:
            self.__ui.print_warning("Operation stopped by user")
            sys.exit(1)

        signed_dev_ids = list()
        for dev_request in dev_requests:
            byte_buffer = BytesIO()

            # signing by cloud private key
            cloud_sign = self.__sign_by_crypto(self.__cloud_private_key, dev_request)

            # signing by tl private key
            tl_sign = self.__sign_by_crypto(self.__tl_private_key, dev_request)

            byte_buffer.write(base64.b64decode(dev_request))
            byte_buffer.write(int(self.__get_signer_id(self.__cloud_private_key)).to_bytes(
                2, byteorder='little', signed=False
            ))
            byte_buffer.write(bytes(cloud_sign))
            byte_buffer.write(int(self.__get_signer_id(self.__tl_private_key)).to_bytes(
                2, byteorder='little', signed=False
            ))
            byte_buffer.write(bytes(tl_sign))

            signed_dev_ids.append(
                base64.b64encode(byte_buffer.getvalue()).decode()
            )

        open(
            os.path.join(self.__output_folder, "dev_mode_requests"),
            "w"
        ).writelines("\n".join(signed_dev_ids))
        self.__ui.print_message("Signing finished")

    def __create_requests_dev_mode_enable(self):
        self.__ui.print_message("Create DevMode Enable requests...")
        ddm_enabler = DeviceDevMode(
            self.__ui,
            self.__upper_level_pub_keys,
            dev_id_list=self.__device_serials
        )
        dev_mode_request = ddm_enabler.enable()
        self.__ui.print_message("DevMode Enable requests created")
        return dev_mode_request

    def run(self):
        self.__ui.print_message("Initiate DevMode enabling")
        if os.path.exists(self.__output_folder):
            shutil.rmtree(self.__output_folder)
        os.makedirs(self.__output_folder)
        created_request = self.__create_requests_dev_mode_enable()
        self.__sign_dev_credentials(created_request)
        self.__ui.print_message("Request created")

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
                description='Database converter for keymanagement tools',
                formatter_class=RawTextHelpFormatter
            )
            arguments.add_argument("output_folder", nargs=1, type=str,
                                   help="folder to store DevMode request")
            arguments.add_argument("signing_keys", nargs=1, type=str,
                                   help="singing keys folder that contains, TL Service Key and Cloud Key")
            arguments.add_argument("device_serials", nargs="+", type=str,
                                   help="device serials numbers base64 encoded")
            arguments.add_argument(
                "-d",
                "--db_folder",
                metavar="DB_PATH",
                type=str,
                help="folder contains UpperLevelKeys db, override path from config file"
            )
            arguments.add_argument('-c', "--config", metavar="CONFIG_PATH", type=str, help="custom configuration file")
            self._args = vars(arguments.parse_args())
        return self._args

    @property
    def __device_serials(self):
        if not self._device_serials:
            self._device_serials = self.__args["device_serials"]
        return self._device_serials

    @property
    def __output_folder(self):
        if not self._output_folder:
            self._output_folder = self.__args["output_folder"][0]
        return self._output_folder

    @property
    def __db_path(self):
        if not self._db_path:
            if "db_folder" in self.__args.keys():
                self._db_path = self.__args["db_folder"]
            else:
                if self.__config["MAIN"]["storage_path"]:
                    self._db_path = os.path.join(self.__config["MAIN"]["storage_path"], "key_storage", "db")
        return self._db_path

    @property
    def __upper_level_pub_keys(self):
        if not self._upper_level_pub_keys:
            upper_levels_db_path = os.path.join(self.__db_path, "UpperLevelKeys")
            if os.path.exists(upper_levels_db_path + ".db"):
                self._upper_level_pub_keys = DBStorage(upper_levels_db_path)
            else:
                sys.exit("[ERROR]: Can't find Upper Level Public Keys at {}.db".format(upper_levels_db_path))
        return self._upper_level_pub_keys

    @property
    def __cloud_private_key(self):
        if not self._cloud_private_key:
            keys_folder = self.__args["signing_keys"][0]
            if os.path.exists(keys_folder):
                key_files = os.listdir(keys_folder)
                cloud_keys = list(filter(lambda x: x if "cloud_" in x else None, key_files))
                if len(cloud_keys) >= 1:
                    self._cloud_private_key = open(os.path.join(keys_folder, cloud_keys[0]), "rb").read()
                else:
                    self.__ui.print_error("Can't find Cloud Key at {}".format(keys_folder))
            else:
                self.__ui.print_error("Can't find signing keys folder at {}".format(keys_folder))
        return self._cloud_private_key

    @property
    def __tl_private_key(self):
        if not self._tl_private_key:
            keys_folder = self.__args["signing_keys"][0]
            if os.path.exists(keys_folder):
                key_files = os.listdir(keys_folder)
                tl_keys = list(filter(lambda x: "tl_service_" in x, key_files))
                if len(tl_keys) >= 1:
                    self._tl_private_key = open(os.path.join(keys_folder, tl_keys[0]), "rb").read()
                else:
                    self.__ui.print_error("Can't find TL Service Key at {}".format(self.__args["signing_keys"]))
            else:
                self.__ui.print_error("Can't find signing keys folder at {}".format(self.__args["signing_keys"]))
        return self._tl_private_key
