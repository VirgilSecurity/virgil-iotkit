import os

import logging

from virgil_keymanager.core import Core
from virgil_keymanager.external_entrypoints.key_signer import KeySigner
from .external_entrypoints.db_converter import DbConverter


def main():
    app = Core()
    try:
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        if os.path.exists(app.pid_file_path):
            os.remove(app.pid_file_path)
        logging.shutdown()


def converter_main():
    db_converter = DbConverter()
    try:
        db_converter.run()
    except KeyboardInterrupt:
        pass


def key_signer_main():
    try:
        key_signer = KeySigner()
        key_signer.run()
    except KeyboardInterrupt:
        pass
