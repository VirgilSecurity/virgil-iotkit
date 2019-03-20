import os
import shutil
from collections import namedtuple

import pytest

from iot_integration_tests_framework.utils.processes import CmdSubProcess

# EMULATOR_MODE = 'emulator'
CRYPTO_ONLY_MODE = 'w'
DEFAULT_CONFIG_PATH = 'test_fs/keymanager.conf'


def pytest_addoption(parser):
    # parser.addoption('--mode', choices=[CRYPTO_ONLY_MODE],
    #                  type=str, help='Mode for key-manager: dongles emulator or crypto lib')
    parser.addoption('--print-output', action="store_true", default=False, help='Print to console during test run')


@pytest.fixture(scope='module')
def key_manager(request):

    mode = CRYPTO_ONLY_MODE
    config_path = DEFAULT_CONFIG_PATH
    print_output = request.config.getoption('--print-output')

    # prepare cmd
    cmd = 'keymanager -c {config_path} -{mode}yp'.format(**locals())

    # run and give process object
    process = CmdSubProcess(cmd, print_output=print_output)
    process.run_in_thread()

    yield process

    # kill process after tests execution
    process.kill()


@pytest.fixture(scope='session', autouse=True)
def clean_key_storage(test_paths):
    """Clean key storage before test execution"""
    if os.path.exists(test_paths.key_storage):
        shutil.rmtree(test_paths.key_storage)


@pytest.fixture(scope='session')
def test_paths():
    paths = namedtuple(
        'Paths', ['key_storage', 'virgil_requests', 'keys_db', 'dev_trust_lists', 'release_trust_lists']
    )

    this_file_path = os.path.dirname(os.path.abspath(__file__))
    key_storage_path = os.path.join(this_file_path, '..', 'test_fs', 'key_storage')
    key_storage_path = os.path.normpath(key_storage_path)

    p = paths(
        key_storage=key_storage_path,
        virgil_requests=os.path.join(key_storage_path, 'virgil_requests'),
        keys_db=os.path.join(key_storage_path, 'db'),
        dev_trust_lists=os.path.join(key_storage_path, 'trust_lists', 'dev'),
        release_trust_lists=os.path.join(key_storage_path, 'trust_lists', 'dev')
    )
    return p
