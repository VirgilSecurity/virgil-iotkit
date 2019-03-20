import os
from configparser import ConfigParser


class ConfigLoader:
    """
    Handling routine work with config files
    """

    def __init__(self, config_path=None):
        # Get main file name, strip from it extension, and add "conf" extension for default config file path search
        if config_path is None:
            raise IOError('[FATAL]: Config file missing at {}'.format(self.conf_path))
        else:
            self.conf_path = config_path
        self.__config = {}
        self.__handle()

    def __handle(self):
        # Try to get config file, and extract from it dict type config
        if not os.path.exists(self.conf_path):
            raise IOError('[FATAL]: Config file missing at {}'.format(self.conf_path))
        raw_config = ConfigParser()
        raw_config.read(self.conf_path)
        for section in raw_config.sections():
            self.__config[section] = dict(raw_config.items(section))

    def get_config(self):
        return self.__config
