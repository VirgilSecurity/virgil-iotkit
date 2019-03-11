import base64
from random import randint

from virgil_crypto import VirgilKeyPair

from soraa_keymanager.data_types import KeyPair

from soraa_keymanager.generators.keys.abstract.sdmpd_key import SDMPDKeyGenerator
from .atmel import Atmel


class AtmelSDMPDKeyGenerator(Atmel, SDMPDKeyGenerator):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelSDMPDKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, signature_limit, rec_pub_key1, rec_pub_key2, sign_device_serial):
        # additional params
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        # generation virgil crypto key
        virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
        private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
        public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]
        private_key_base64 = base64.b64encode(bytes(private_key)).decode("utf-8")

        # setup pregenerated key to atmel device
        if self._a_check(self._atmel.set_private_key(private_key_base64, signature_limit, device_serial)) == 0:
            return 0, 0

        # setup key type
        soraa_key_type = "sdmpd"
        if self._a_check(self._atmel.set_soraa_key_type(soraa_key_type, device_serial)) == 0:
            return 0, 0

        # setup recovery pub keys
        if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
            return 0, 0

        if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
            return 0, 0

        # getting pub key from device
        pub_key = self._a_check(self._atmel.get_public_key(device_serial))
        if pub_key == 0:
            return 0

        # setup sign to device
        sign_data = self._a_check(self._atmel.sign_by_device(pub_key, device_serial=sign_device_serial))
        if sign_data == 0:
            return 0
        if self._a_check(self._atmel.set_signature(sign_data, device_serial)) == 0:
            return 0

        # setup random number
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0, 0

        # return device serial
        return self._a_check(self._atmel.lock_data(device_serial)), KeyPair(private_key=private_key, public_key=public_key)

    def sign(self, data, device_serial):
        return self._a_check(self._atmel.sign_by_device(data, device_serial=device_serial))
