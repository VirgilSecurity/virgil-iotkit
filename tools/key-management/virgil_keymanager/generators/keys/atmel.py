import base64
from random import randint

from virgil_crypto import VirgilKeyPair
from virgil_keymanager.data_types import KeyPair


class Atmel(object):

    def __init__(self, ui, atmel):
        self._ui = ui
        self._atmel = atmel

    def _a_check(self, atmel_ops_status):
        """
        Atmel operation checker. Check status of operation.

        Args:
            atmel_ops_status:  atmel operation output
        Returns:
            In error case print error and return 0
            In success return, object of function return
        """
        if not atmel_ops_status[0]:
            self._ui.print_error(atmel_ops_status[1])
            return 0
        return atmel_ops_status[1]

    def sign(self, data, device_serial):
        return self._a_check(self._atmel.sign_by_device(data, device_serial=device_serial))


class AtmelCloudKeyGenerator(Atmel):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelCloudKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, rec_pub_key1, rec_pub_key2):

        # additional params
        signature_limit = None
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        # generate key on device
        if self._a_check(self._atmel.generate_private_key(signature_limit, device_serial)) == 0:
            return 0

        # setup key type
        key_type = "cloud"
        if self._a_check(self._atmel.set_key_type(key_type, device_serial)) == 0:
            return 0

        # setup recovery pub keys
        if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
            return 0
        if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
            return 0

        # setup random number
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0

        # return device serial
        return self._a_check(self._atmel.lock_data(device_serial))


class AtmelFactoryKeyGenerator(Atmel):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelFactoryKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, signature_limit, rec_pub_key1, rec_pub_key2, key_pair_base64=None):
        # additional params
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        # generation virgil crypto key
        if not key_pair_base64:
            virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
            private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]
            private_key_base64 = base64.b64encode(bytes(private_key)).decode("utf-8")
        else:
            private_key = base64.b64decode(key_pair_base64.private_key)
            public_key = base64.b64decode(key_pair_base64.public_key)
            private_key_base64 = key_pair_base64.private_key

        # setup pregenerated key to atmel device
        if self._a_check(self._atmel.set_private_key(private_key_base64, signature_limit, device_serial)) == 0:
            return 0, 0

        # setup key type
        key_type = "factory"
        if self._a_check(self._atmel.set_key_type(key_type, device_serial)) == 0:
            return 0, 0

        # setup recovery pub keys
        if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
            return 0, 0

        if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
            return 0, 0

        # setup random number
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0, 0

        # return device serial
        return self._a_check(self._atmel.lock_data(device_serial)), KeyPair(private_key=private_key, public_key=public_key)


class AtmelRecoveryKeyGenerator(Atmel):

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


class AtmelSignedKeyGenerator(Atmel):
    def __init__(self, key_type, ui, atmel):
        super(AtmelSignedKeyGenerator, self).__init__(ui, atmel)
        self._key_type = key_type

    def generate(self, device_serial, rec_pub_key1, rec_pub_key2, sign_device_serial, private_key_base64=None):
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
                return 0, 0

            # setup key type
            if self._a_check(self._atmel.set_key_type(self._key_type, device_serial)) == 0:
                return 0, 0

            # setup recovery pub keys
            if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
                return 0, 0
            if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
                return 0, 0

            # getting pub key from device
            pub_key = self._a_check(self._atmel.get_public_key(device_serial))
            if public_key == 0:
                public_key = pub_key
            if pub_key == 0:
                return 0, 0

            # setup sign to device
            sign_data = self._a_check(self._atmel.sign_by_device(pub_key, device_serial=sign_device_serial))
            if sign_data == 0:
                return 0, 0
            if self._a_check(self._atmel.set_signature(sign_data, device_serial)) == 0:
                return 0, 0

            # setup random number to device
            if random_number:
                if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                    return 0, 0

            # return device serial
            return self._a_check(self._atmel.lock_data(device_serial)), KeyPair(private_key=private_key,
                                                                                public_key=public_key)
