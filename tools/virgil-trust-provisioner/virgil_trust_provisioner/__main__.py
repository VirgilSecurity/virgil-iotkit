import os

import logging

from virgil_trust_provisioner.core import Core


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
