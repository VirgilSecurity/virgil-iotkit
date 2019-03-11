import base64
from random import randint

from soraa_keymanager.data_types import KeyPair
from virgil_crypto import VirgilKeyPair
from soraa_keymanager.generators.keys.abstract.trust_list_service_key import TrustListServiceKeyGenerator
from .atmel import Atmel


class AtmelTrustListServiceKeyGenerator(Atmel, TrustListServiceKeyGenerator):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelTrustListServiceKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, rec_pub_key1, rec_pub_key2, sign_device_serial, private_key_base64=None, dev_mode=False):
        # additional params
        signature_limit = None
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        if private_key_base64:
            private_key = base64.b64decode(private_key_base64)
            public_key = 0
        else:
            # generation virgil crypto key
            virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
            private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]
            private_key_base64 = base64.b64encode(bytes(private_key)).decode("utf-8")

        # setup pregenerated key to atmel device
        if self._a_check(self._atmel.set_private_key(private_key_base64, signature_limit, device_serial)) == 0:
            return 0

        # setup key type
        soraa_key_type = "tl_service"
        if self._a_check(self._atmel.set_soraa_key_type(soraa_key_type, device_serial)) == 0:
            return 0

        # setup recovery pub keys
        if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
            return 0
        if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
            return 0

        # getting pub key from device
        pub_key = self._a_check(self._atmel.get_public_key(device_serial))
        if public_key == 0:
            public_key = pub_key
        if pub_key == 0:
            return 0

        # setup sign to device
        sign_data = self._a_check(self._atmel.sign_by_device(pub_key, device_serial=sign_device_serial))
        if sign_data == 0:
            return 0
        if self._a_check(self._atmel.set_signature(sign_data, device_serial)) == 0:
            return 0

        # setup random number to device
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0

        # return device serial
        return self._a_check(self._atmel.lock_data(device_serial)), KeyPair(private_key=private_key, public_key=public_key)

    def sign(self, file_path_for_sign, device_serial):
        self._a_check(self._atmel.sign_by_device(file_path_for_sign, device_serial=device_serial))
