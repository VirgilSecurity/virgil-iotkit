import os
import sys
from configparser import ConfigParser
from collections import Mapping


class Config(Mapping):

    def __init__(self, config_path=None):
        self._path = config_path if config_path is not None else _get_default_config_path()
        self._config_dict = self._load()

    def _load(self):
        if not os.path.exists(self._path):
            sys.exit('[FATAL]: Configuration file is missing at {}'.format(self._path))
        raw_config = ConfigParser()
        raw_config.read(self._path)
        config = {section: dict(raw_config.items(section)) for section in raw_config.sections()}
        if not config:
            sys.exit('[FATAL]: Configuration file is empty! Please setup config at {}'.format(self._path))
        return config

    def check_content(self, required):
        for section, required_keys in required.items():
            if section not in self._config_dict.keys():
                sys.exit('[FATAL]: Missing section {} in config'.format(section))
            section_content = self._config_dict[section]
            for key in required_keys:
                if key not in section_content:
                    sys.exit('[FATAL]: Missing config parameter {} in section {}'.format(key, section))

    def __len__(self):
        return len(self._config_dict)

    def __getitem__(self, k):
        return self._config_dict[k]

    def __iter__(self):
        return iter(self._config_dict)


def _get_default_config_path():
    return '/etc/virgil-trust-provisioner/provisioner.conf'
