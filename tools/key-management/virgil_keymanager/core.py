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
from virgil_keymanager.consts.modes import ProgramModes
from .ui import UI
from .utility_manager import UtilityManager


class UtilContext:
    def __init__(self):
        #
        # Currently only VIRGIL_CRYPTO_ONLY (keys are stored on disk) mode is available for user
        #

        self.__cli_args = None
        self.program_mode = ProgramModes.VIRGIL_CRYPTO_ONLY
        self._config = self.__load_config()
        self.logger = self.__prepare_logger()
        self.ui = UI(self.logger)
        self.atmel = self.__prepare_atmel_util()

        self.skip_confirm = self._cli_args["skip_confirm"]
        self.disable_cache = None
        self.printer_enable = False
        self.debug_logging = self._cli_args["verbose_logging"]

        self.storage_path = self._config["MAIN"]["storage_path"]
        self.secure_transfer_keys_path = self._config["MAIN"]["secure_transfer_keys_path"]
        self.secure_transfer_password = self._config["MAIN"]["secure_transfer_keys_passwd"]

        self.virgil_app_id = self._config["CARDS"]["virgil_app_id"]
        self.factory_info_json = self._config["CARDS"]["factory_info_json"]

    @property
    def _cli_args(self):
        if self.__cli_args is not None:
            return self.__cli_args
        arguments = ArgumentParser(
            description='Key infrastructure management tool',
            formatter_class=RawTextHelpFormatter
        )
        arguments.add_argument('-b', '--verbose-logging', action='store_true', help="enable debug logging")
        arguments.add_argument('-y', '--skip-confirm', action='store_true', help='skip all confirmation requests')
        arguments.add_argument('-c', "--config", metavar="CONFIG_PATH", type=str, help="custom configuration file")
        arguments.add_argument('-v', "--version", action="version", version=__version__,
                               help="print application version and exit")
        self.__cli_args = vars(arguments.parse_args())
        return self.__cli_args

    def __prepare_logger(self):
        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR
        }

        if "log_level" in self._config["MAIN"].keys():
            if self._config["MAIN"]["log_level"] in log_levels.keys():
                log_level = self._config["MAIN"]["log_level"]
            else:
                sys.exit("[FATAL]: Logger miss configured please ensure you input correct log level ({})".format(
                    " ,".join(log_levels.keys())
                ))
        else:
            log_level = log_levels["INFO"]

        logger = logging.getLogger("keymanager_logger")
        logger.setLevel(logging.DEBUG)

        # TODO enable when realize signed handler
        if not os.path.exists(self._config["MAIN"]["log_path"]):
            os.makedirs(self._config["MAIN"]["log_path"])
        # lc = SignedHandlerLogger(self.__config["MAIN"]["log_path"], atmel=self._atmel)
        access_log = logging.FileHandler(os.path.join(self._config["MAIN"]["log_path"], "keymanager.log"))
        access_log.setLevel(log_level)
        access_log.setFormatter(
            logging.Formatter(
                "[%(asctime)s][%(levelname)s]: %(message)s",
                datefmt="%d/%m/%Y %H:%M:%S"
            )
        )

        development_logger = logging.FileHandler(
            os.path.join(
                self._config["MAIN"]["log_path"],
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

        logger.addHandler(access_log)
        if self._cli_args["verbose_logging"]:
            logger.addHandler(development_logger)
        return logger

    def __load_config(self):
        config_path = self._cli_args.get('config', None)
        config = Config(config_path)
        # Check required content
        required_content = {
            "MAIN": [
                "storage_path",
                "log_path",
                "secure_transfer_keys_path",
                "secure_transfer_keys_passwd"
            ],
            "CARDS": [
                "virgil_app_id",
                "factory_info_json"
            ]
        }

        if self.program_mode == ProgramModes.ATMEL_DONGLES:
            required_content["MAIN"].append("dongles_cli_path")
        elif self.program_mode == ProgramModes.ATMEL_DONGLES_EMULATOR:
            required_content["MAIN"].append("dongles_cli_emulator_path")

        config.check_content(required_content)
        return config

    def __prepare_atmel_util(self):
        if self.program_mode not in (ProgramModes.ATMEL_DONGLES, ProgramModes.ATMEL_DONGLES_EMULATOR):
            return None

        if self.program_mode == ProgramModes.ATMEL_DONGLES_EMULATOR:
            atmel_util_path = self._config["MAIN"]["dongles_cli_emulator_path"]
        else:
            atmel_util_path = self._config["MAIN"]["dongles_cli_path"]

        if not atmel_util_path:
            atmel_util_path = os.path.join(
                os.path.dirname(sys.modules["virgil_keymanager"].__file__),
                "external_utils",
                "util",
                "emulator" if self.program_mode == ProgramModes.ATMEL_DONGLES_EMULATOR else "origin",
                "dongles-cli"
            )
            self.logger.debug("atmel util path set to {}".format(atmel_util_path))

        mode = "dev" if self.program_mode == ProgramModes.ATMEL_DONGLES_EMULATOR else "main"
        atmel = AtmelDonglesController(atmel_util_path, mode, logger=self.logger)
        return atmel


class Core:
    def __init__(self):
        self.__util_context = UtilContext()
        self.pid_file_path = os.path.join(str(Path.home()), '.keymanager', 'keymanager.pid')
        self._ui = None
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
                inst.__util_context.logger.critical(traceback.format_exc())
                sys.exit("[FATAL]: Application crashed. See log file for more info.")
        return wrapper

    @__catch_exceptions
    def run(self):
        if self.__is_have_run_instance():
            sys.exit("[FATAL]: Running multiple instances is forbidden")
        while True:
            self.__util_manager.run_utility()

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
            self.__util_context.logger.debug("Run with pid {}".format(str(psutil.Process().pid)))
            return False

    @property
    def __util_manager(self):
        if not self._util_manager:
            self._util_manager = UtilityManager(self.__util_context)
        return self._util_manager
