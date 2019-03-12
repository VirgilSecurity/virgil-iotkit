import base64
from random import randint

from virgil_crypto import VirgilKeyPair

from virgil_keymanager.data_types import KeyPair
from virgil_keymanager.generators.keys.abstract.recovery_key import RecoveryKeyGenerator
from .atmel import Atmel


class AtmelRecoveryKeyGenerator(Atmel, RecoveryKeyGenerator):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelRecoveryKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, private_key_base64=None):
        # additional params
        signature_limit = None
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        if private_key_base64:
            private_key = base64.b64decode(private_key_base64)
            public_key = 0
        else:
            # virgil key generation
            virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
            private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]
            private_key_base64 = base64.b64encode(bytes(private_key)).decode("utf-8")

        # setup pregenerated key to atmel device
        if self._a_check(self._atmel.set_private_key(private_key_base64, signature_limit, device_serial)) == 0:
            return 0

        # setup key type
        key_type = "recovery"
        if self._a_check(self._atmel.set_key_type(key_type, device_serial)) == 0:
            return 0

        # setup random number
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0

        return self._a_check(self._atmel.lock_data(device_serial)), KeyPair(private_key=private_key, public_key=public_key)

    def sign(self, data, device_serial):
        self._a_check(self._atmel.sign_by_device(data, device_serial=device_serial))
