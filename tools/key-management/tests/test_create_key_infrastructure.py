import random
from collections import namedtuple
from os.path import exists, join

import pytest

from virgil_keymanager.data_types.trustlist_type import TrustList
from virgil_keymanager.storage.db_storage import DBStorage

from iot_integration_tests_framework.utils.trust_list import trust_list_to_dict
from iot_integration_tests_framework.utils.file_system import find_files


# KEYS GENERATION TESTS #

@pytest.mark.dependency()
def test_generate_upper_level_keys(key_manager):
    """
    Using key manager, generate upper-level keys
    """
    random_recovery = lambda: random.choice(['1', '2'])

    # Start generation
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin('1')

    # Generate 1 auth key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for Auth Key:')
    key_manager.send_to_stdin('auth_1')

    # Generate 2 auth key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for Auth Key:')
    key_manager.send_to_stdin('auth_2')

    # Generate 1 trust list key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for TrustList Service Key:')
    key_manager.send_to_stdin('tl_1')

    # Generate 2 trust list key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for TrustList Service Key:')
    key_manager.send_to_stdin('tl_2')

    # Generate 1 firmware key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for Firmware Key:')
    key_manager.send_to_stdin('firmware_1')

    # Generate 2 firmware key
    key_manager.wait_for_output('Please enter option number:')
    key_manager.send_to_stdin(random_recovery())

    key_manager.wait_for_output('Enter comment for Firmware Key:')
    key_manager.send_to_stdin('firmware_2')

    # Generate factory key
    key_manager.wait_for_output('Enter the signature limit number from 1 to 4294967295')
    signature_limit = str(random.choice(range(1, 4294967295)))
    key_manager.send_to_stdin(str(signature_limit))
    key_manager.wait_for_output('Enter factory name:')
    key_manager.send_to_stdin('factory')

    # Generate cloud key
    key_manager.wait_for_output('Enter comment for Cloud Key:')
    key_manager.send_to_stdin('cloud')


@pytest.fixture(params=[
    'UpperLevelKeys.db',
    'RecoveryPrivateKeys.db',
    'AuthPrivateKeys.db',
    'TLServicePrivateKeys.db',
    'TrustListPubKeys.db',
    'FirmwarePrivateKeys.db',
    'FactoryPrivateKeys.db',
    'CloudPrivateKeys.db'
])
def upper_level_db_path(request, test_paths):
    return join(test_paths.keys_db, request.param)


@pytest.mark.dependency(depends=['test_generate_upper_level_keys'])
def test_upper_level_dbs_created(upper_level_db_path):
    assert exists(upper_level_db_path), '%s was not created' % upper_level_db_path


@pytest.mark.dependency()
def test_generate_auth_internal_key(key_manager):
    key_manager.wait_for_output('Generate AuthInternal Key')
    key_manager.send_to_stdin('5')
    key_manager.wait_for_output('Enter comment for AuthInternal Key:')
    key_manager.send_to_stdin('auth_internal')
    key_manager.wait_for_output('Generation finished')


@pytest.mark.dependency()
def test_generate_firmware_internal_key(key_manager):
    key_manager.wait_for_output('Generate FirmwareInternal Key')
    key_manager.send_to_stdin('15')
    key_manager.wait_for_output('Enter comment for FirmwareInternal Key:')
    key_manager.send_to_stdin('firmware_internal')
    key_manager.wait_for_output('Generation finished')


@pytest.mark.dependency(depends=['test_generate_auth_internal_key', 'test_generate_firmware_internal_key'])
def test_internal_keys_db_created(test_paths):
    path = join(test_paths.keys_db, 'InternalPrivateKeys.db')
    assert exists(path), '%s was not created' % path


# TRUST LIST TESTS #

@pytest.fixture(scope='module')
def upper_level_keys_storage(test_paths):
    path = join(test_paths.keys_db, 'UpperLevelKeys')
    return DBStorage(path)


@pytest.fixture(scope='module')
def trust_list_signers(upper_level_keys_storage):
    # select random signers for tl from db and return ids
    db = upper_level_keys_storage.get_all_data()
    signer_keys = namedtuple('TLSigners', ['auth', 'tl_service'])
    auth_id = random.choice([k for k, v in db.items() if v['type'] == 'auth'])
    tl_service_id = random.choice([k for k, v in db.items() if v['type'] == 'tl_service'])
    return signer_keys(auth=auth_id, tl_service=tl_service_id)


def get_choice_number_by_output(km, pattern):
    # extract choice number from line by pattern. example line:
    # 2. db: AuthPrivateKeys, type: auth, comment: auth_2, key_id: 11913
    choice_line = [line for line in km.output[km.stdout_offset:] if pattern in line][0]
    return choice_line.strip()[0]


@pytest.mark.dependency(depends=['test_generate_upper_level_keys', 'test_generate_firmware_internal_key'])
def test_generate_dev_trust_list(key_manager, trust_list_signers):
    # Start trust list generation
    key_manager.send_to_stdin('17')

    # Select type
    key_manager.wait_for_output('Please choose TrustList type:')
    key_manager.send_to_stdin('1')

    # Select version
    key_manager.wait_for_output('Enter the TrustList version [1]:')
    key_manager.send_to_stdin('1')

    # Choose Auth key
    key_manager.wait_for_output('Please choose Auth Key for TrustList signing:')
    key_manager.wait_for_output('Please enter option number:')
    choice = get_choice_number_by_output(key_manager, trust_list_signers.auth)
    key_manager.send_to_stdin(choice)

    # Choose Trust List service key
    key_manager.wait_for_output('Please choose TrustList Service Key for TrustList signing:')
    key_manager.wait_for_output('Please enter option number:')
    choice = get_choice_number_by_output(key_manager, trust_list_signers.tl_service)
    key_manager.send_to_stdin(choice)

    key_manager.wait_for_output('TrustList generated and stored')


@pytest.fixture(scope='module')
def trust_list_keys_storage(test_paths):
    path = join(test_paths.keys_db, 'TrustListPubKeys')
    return DBStorage(path)


@pytest.mark.dependency(depends=['test_generate_dev_trust_list'])
def test_verify_dev_trust_list_structure(test_paths, trust_list_signers, trust_list_keys_storage):
    tl_db_keys = trust_list_keys_storage.get_all_data()

    trust_lists = list(find_files(test_paths.dev_trust_lists, 'TrustList.*\.tl', regex=True))
    assert len(trust_lists) == 1, 'Number of generated dev trust lists != 1'

    trust_list = trust_list_to_dict(trust_lists[0])

    # Verify Trust List header
    assert trust_list['header']['version'] == 1
    assert trust_list['header']['pub_keys_count'] == 4
    assert trust_list['header']['tl_size'] == 581

    # Verify Trust List body
    assert len(trust_list['body']) == 4, 'Body of dev Trust List does not contain 4 public keys'
    types_map = {
        TrustList.KeyType.AUTH_INTERNAL_PUB_KEY: 'auth_internal',
        TrustList.KeyType.FACTORY_PUB_KEY: 'factory',
        TrustList.KeyType.SAMS_PUB_KEY: 'cloud',
        TrustList.KeyType.FIRMWARE_INTERNAL_PUB_KEY: 'firmware_internal'
    }
    for tl_pub_key in trust_list['body']:
        db_value = tl_db_keys[str(tl_pub_key['key_id'])]
        assert db_value['type'] == types_map[tl_pub_key['key_type']], 'DB and TrustList body key types are not equal'
        assert db_value['key'] == tl_pub_key['pub_key'], 'DB and TrustList pub keys are not equal'

    # Verify Trust List footer
    assert str(trust_list['footer']['tl_key_id']) == str(trust_list_signers.tl_service),\
        'TL key id is not which has been chosen'
    assert trust_list['footer']['tl_signature'], 'TL key signature is empty'
    assert str(trust_list['footer']['auth_key_id']) == str(trust_list_signers.auth),\
        'Auth key id is not which has been chosen'
    assert trust_list['footer']['auth_signature'], 'Auth signature is empty'
    assert trust_list['footer']['tl_type'] == TrustList.TrustListType.DEV, 'TL type is not DEV'
