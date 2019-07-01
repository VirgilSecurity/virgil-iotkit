import collections
import functools
import logging
import os
import psutil
import sys
from pathlib import Path
from argparse import ArgumentParser, RawTextHelpFormatter

from virgil_keymanager import __version__
from virgil_keymanager.core_utils.config import Config
from virgil_keymanager.external_utils.atmel_dongles_controller import AtmelDonglesController
from .ui import UI
from .utility_manager import UtilityManager


class UtilContext:
    def __init__(self, config_, ui, logger, atmel_util, **cli_args):
        self.config = config_
        self.ui = ui
        self.logger = logger
        self.atmel = atmel_util

        self.dongles_mode = "emulator" if cli_args["emulator"] else "dongles"
        self.skip_confirm = cli_args["skip_confirm"]
        self.disable_cache = cli_args["no_cache"]
        self.printer_disable = cli_args["printer_disable"]
        self.debug_logging = cli_args["verbose_logging"]
        self.no_dongles = cli_args["no_dongles"]

        self.storage_path = config_["MAIN"]["storage_path"]
        self.secure_transfer_keys_path = config_["MAIN"]["secure_transfer_keys_path"]
        self.secure_transfer_password = config_["MAIN"]["secure_transfer_keys_passwd"]

        self.virgil_app_id = config_["CARDS"]["virgil_app_id"]
        self.factory_info_json = config_["CARDS"]["factory_info_json"]


class Core(object):

    def __init__(self):
        self._args = None
        self.__config = self.__load_configs()
        self.pid_file_path = os.path.join(str(Path.home()), '.keymanager', 'keymanager.pid')
        self._ui = None
        self.__dongles_mode = "emulator" if self.__args["emulator"] else "dongles"
        self.__skip_confirm = self.__args["skip_confirm"]
        self.__disable_cache = self.__args["no_cache"]
        self.__printer_disable = self.__args["printer_disable"]
        self.__debug_logging = self.__args["verbose_logging"]
        self._logger = None
        self._atmel_util_path = None
        self._atmel = None
        self._util_manager = None

    def __catch_exceptions(job_func):
        @functools.wraps(job_func)
        def wrapper(inst, *args, **kwargs):
            try:
                return job_func(inst, *args, **kwargs)
            except SystemExit:
                raise
            except KeyboardInterrupt:
                raise
            except:
                import traceback
                inst.logger.critical(traceback.format_exc())
                sys.exit("[FATAL]: Application crashed. See log file for more info.")
        return wrapper

    @__catch_exceptions
    def run(self):
        if self.__is_have_run_instance():
            sys.exit("[FATAL]: Running multiple instances is forbidden")
        while True:
            self.__util_manager.run_utility()

    def __load_configs(self):
        config_path = self.__args.get('config', None)
        config = Config(config_path)
        required_content = {
            "MAIN": [
                "storage_path",
                "log_path",
                "dongles_cli_path",
                "dongles_cli_emulator_path",
                "secure_transfer_keys_path",
                "secure_transfer_keys_passwd"
            ],
            "CARDS": [
                "virgil_app_id",
                "factory_info_json"
            ]
        }
        config.check_content(required_content)
        return config

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
                            if "keymanager" in process["cmdline"] and proc_id == process["pid"]:
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
            self.logger.debug("Run with pid {}".format(str(psutil.Process().pid)))
            return False

    @property
    def __args(self):
        if not self._args:
            arguments = ArgumentParser(
                description='Key infrastructure management tool',
                formatter_class=RawTextHelpFormatter
            )
            arguments.add_argument('-b', '--verbose-logging', action='store_true', help="enable debug logging")
            arguments.add_argument('-w', '--no-dongles', action='store_true',
                                   help="Virgil Crypto use only, all keys will be stored on the disk")
            arguments.add_argument('-e', '--emulator', action='store_true', help="enable dongles emulator mode")
            arguments.add_argument('-p', "--printer-disable", action="store_true",
                                   help="disable RestorePaper printing requests")
            arguments.add_argument('-y', '--skip-confirm', action='store_true', help='skip all confirmation requests')
            arguments.add_argument('-c', "--config", metavar="CONFIG_PATH", type=str, help="custom configuration file")
            arguments.add_argument('-n', "--no-cache", action="store_true", help="disable cache usage")
            arguments.add_argument('-v', "--version", action="version", version=__version__,
                                   help="print application version and exit")
            self._args = vars(arguments.parse_args())
        return self._args

    @property
    def __atmel_util_path(self):
        if not self._atmel_util_path:
            if self.__dongles_mode == "emulator":
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
                    "emulator" if self.__dongles_mode == "emulator" else "origin",
                    "dongles-cli"
                )
                self.logger.debug("atmel util path setted to {}".format(self._atmel_util_path))
        return self._atmel_util_path

    @property
    def __ui(self):
        if not self._ui:
            self._ui = UI(self.logger)
        return self._ui

    @property
    def __atmel(self):
        if not self._atmel:
            mode = "dev" if self.__dongles_mode == "emulator" else "main"
            self._atmel = AtmelDonglesController(self.__atmel_util_path, mode, logger=self.logger)
        return self._atmel

    @property
    def logger(self):
        if not self._logger:
            log_levels = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR
            }

            if "log_level" in self.__config["MAIN"].keys():
                if self.__config["MAIN"]["log_level"] in log_levels.keys():
                    log_level = self.__config["MAIN"]["log_level"]
                else:
                    sys.exit("[FATAL]: Logger miss configured please ensure you input correct log level ({})".format(
                        " ,".join(log_levels.keys())
                    ))
            else:
                log_level = log_levels["INFO"]

            self._logger = logging.getLogger("keymanager_logger")
            self._logger.setLevel(logging.DEBUG)

            # TODO enable when realize signed handler
            if not os.path.exists(self.__config["MAIN"]["log_path"]):
                os.makedirs(self.__config["MAIN"]["log_path"])
            # lc = SignedHandlerLogger(self.__config["MAIN"]["log_path"], atmel=self._atmel)
            access_log = logging.FileHandler(os.path.join(self.__config["MAIN"]["log_path"], "keymanager.log"))
            access_log.setLevel(log_level)
            access_log.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s",
                    datefmt="%d/%m/%Y %H:%M:%S"
                )
            )

            development_logger = logging.FileHandler(
                os.path.join(
                    self.__config["MAIN"]["log_path"],
                    "keymanager_dev.log"
                ),
                mode="w"
            )
            development_logger.setLevel(logging.DEBUG)
            development_logger.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s",
                    datefmt="%d/%m/%Y %H:%M:%S"
                )
            )

            self._logger.addHandler(access_log)
            if self.__debug_logging:
                self._logger.addHandler(development_logger)
        return self._logger

    @property
    def __util_manager(self):
        if not self._util_manager:
            util_context = UtilContext(
                self.__config,
                self.__ui,
                self.logger,
                self.__atmel,
                **self.__args
            )

            self._util_manager = UtilityManager(util_context)
        return self._util_manager
