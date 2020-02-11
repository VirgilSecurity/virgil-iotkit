import collections
import json
import logging
import os
import sys
from pathlib import Path
from argparse import ArgumentParser, RawTextHelpFormatter

import psutil

from virgil_trust_provisioner import __version__
from virgil_trust_provisioner.core_utils.config import Config
from virgil_trust_provisioner.consts.modes import ProgramModes
from virgil_trust_provisioner.ui import UI
from virgil_trust_provisioner.utility_manager import UtilityManager


class UtilContext:
    def __init__(self):
        #
        # Currently only VIRGIL_CRYPTO_ONLY (keys are stored on disk) mode is available for user
        #

        self._cli_args = self.__get_cli_args()
        self.program_mode = ProgramModes.VIRGIL_CRYPTO_ONLY
        self._config = self.__load_config()
        self.logger = self.__prepare_logger()
        self.ui = UI(self.logger)

        self.skip_confirm = self._cli_args["skip_confirm"]

        self.storage_path = self.__prepare_storage_folder()
        self.provision_pack_path = os.path.expanduser(self._config["MAIN"]["provision_pack_path"])

        self.application_token = self._cli_args["app_token"]
        self.virgil_api_url = self._config["VIRGIL"]["iot_api_url"]

        # Load factory info from specified json file
        self.factory_info = self.__load_factory_info()

    @staticmethod
    def __get_cli_args():
        arguments = ArgumentParser(
            description='Key infrastructure management tool',
            formatter_class=RawTextHelpFormatter
        )
        arguments.add_argument('-y', '--skip-confirm', action='store_true', help='skip all confirmation requests')
        arguments.add_argument('-c', "--config", metavar="CONFIG_PATH", type=str, help="custom configuration file")
        arguments.add_argument('-t', "--app-token", required=True, type=str, help="Virgil application token")
        arguments.add_argument('-i', "--factory-info", required=True, type=str,
                               help="path to json with factory info (will be added to Factory key Virgil card)")
        arguments.add_argument('-v', "--version", action="version", version=__version__,
                               help="print application version and exit")
        return vars(arguments.parse_args())

    def __load_factory_info(self):
        factory_info_json_path = os.path.expanduser(self._cli_args["factory_info"])
        if not os.path.exists(factory_info_json_path):
            sys.exit("File with Factory info '%s' does not exist" % factory_info_json_path)
        with open(factory_info_json_path, 'r') as f:
            factory_info = json.load(f)
        if not factory_info:
            sys.exit("File with Factory info '%s' is empty" % factory_info)
        return factory_info

    def __prepare_storage_folder(self):
        # Create folder for storage if not exists and path specified for HOME
        storage = os.path.expanduser(self._config["MAIN"]["storage_path"])
        if not os.path.exists(storage):
            if storage.startswith(str(Path.home())):
                os.makedirs(storage)
            else:
                sys.exit("[FATAL]: Path for storage specified in config doesn't exist: %s" % storage)
        return storage

    def __prepare_logger(self):
        logger = logging.getLogger("virgil-trust-provisioner-logger")
        logger.setLevel(logging.INFO)

        # Create folder for logs if not exists and path specified for HOME
        log_path = os.path.expanduser(self._config["MAIN"]["log_path"])
        if not os.path.exists(log_path):
            if log_path.startswith(str(Path.home())):
                os.makedirs(log_path)
            else:
                sys.exit("[FATAL]: Path for logs specified in config doesn't exist: %s" % log_path)

        # Add file handler
        file_handler = logging.FileHandler(os.path.join(log_path, "virgil-trust-provisioner.log"))
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s][%(levelname)s]: %(message)s",
                datefmt="%d/%m/%Y %H:%M:%S"
            )
        )
        logger.addHandler(file_handler)
        return logger

    def __load_config(self):
        config_path = self._cli_args.get('config', None)
        config = Config(config_path)
        # Check required content
        required_content = {
            "MAIN": [
                "storage_path",
                "log_path",
                "provision_pack_path"
            ],
            "VIRGIL": [
                "iot_api_url"
            ]
        }

        config.check_content(required_content)
        return config


class Core:
    def __init__(self):
        self._util_context = UtilContext()
        self.pid_file_path = os.path.join(str(Path.home()), '.virgil_trust_provisioner', 'virgil_trust_provisioner.pid')
        self._ui = None
        self._util_manager = None

    def run(self):
        try:
            if self.__is_have_run_instance():
                sys.exit("[FATAL]: Running multiple instances is forbidden")
            while True:
                self.__util_manager.run_utility()
        except SystemExit:
            raise
        except KeyboardInterrupt:
            raise
        except:
            import traceback
            self._util_context.logger.critical(traceback.format_exc())
            sys.exit("[FATAL]: Application crashed. See log file for more info.")

    def __is_have_run_instance(self):
        if os.path.exists(self.pid_file_path) and os.stat(self.pid_file_path).st_size != 0:
            pid_file = open(self.pid_file_path, "r")
            proc_id = pid_file.read()
            pid_file.close()
            if proc_id:
                if psutil.pid_exists(int(proc_id)):
                    checked_processess = list()
                    process_list = [p.as_dict(["pid", "cmdline"]) for p in psutil.process_iter()]
                    for process in process_list:
                        if process["cmdline"]:
                            if "virgil-trust-provisioner" in process["cmdline"] and proc_id == process["pid"]:
                                checked_processess.append(process)
                        else:
                            continue
                    counter = collections.Counter(checked_processess)
                    if counter[True] <= 1:
                        return True
                    else:
                        return False
            os.remove(self.pid_file_path)
            return self.__is_have_run_instance()
        else:
            pid_file_dir = os.path.split(self.pid_file_path)[0]
            if not os.path.exists(pid_file_dir):
                os.makedirs(pid_file_dir, mode=0o755)
            pid_file = open(self.pid_file_path, "w")
            pid_file.write(str(psutil.Process().pid))
            pid_file.close()
            self._util_context.logger.debug("Run with pid {}".format(str(psutil.Process().pid)))
            return False

    @property
    def __util_manager(self):
        if not self._util_manager:
            self._util_manager = UtilityManager(self._util_context)
        return self._util_manager
