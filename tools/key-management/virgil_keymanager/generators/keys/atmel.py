import sys
from random import randint

from PyCRC.CRCCCITT import CRCCCITT
from virgil_crypto import VirgilKeyPair
from virgil_crypto.hashes import HashAlgorithm
from virgil_keymanager import consts

from virgil_keymanager.generators.keys.interface import KeyGeneratorInterface
from virgil_keymanager.core_utils.helpers import b64_to_bytes, to_b64


class AtmelKeyGenerator(KeyGeneratorInterface):
    """
    Represents key pair entity for atmel dongles/dongles emulator usage
    """

    def __init__(self, key_type,
                 device_serial,
                 util_context,
                 ec_type=VirgilKeyPair.Type_EC_SECP256R1,
                 hash_type=HashAlgorithm.SHA256):
        self._context = util_context
        self._ui = self._context.ui
        self._atmel = self._context.atmel
        self._key_type = key_type
        self._logger = self._context.logger
        self._ec_type = ec_type
        self._hash_type = consts.hash_type_vs_to_hsm_map[hash_type]

        self._private_key = None
        self.device_serial = device_serial

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

    def _lock_data_field(self):
        ops_status = self._atmel.lock_data(self.device_serial)
        if not ops_status[0]:
            self._logger.error("failed to lock data field: {}".format(ops_status[1]))
            sys.exit(ops_status[1])

    @property
    def ec_type(self):
        return self._ec_type

    @property
    def hash_type(self):
        return self._hash_type

    @property
    def public_key(self):
        ops_status = self._atmel.get_public_key(self.device_serial)
        if not ops_status[0]:
            self._logger.error("failed to get public key: {}".format(ops_status[1]))
            sys.exit(ops_status[1])
        return ops_status[1]

    @property
    def private_key(self):
        return self._private_key

    @property
    def signature(self):
        return self._a_check(self._atmel.get_signature(self.device_serial))

    @signature.setter
    def signature(self, sign_data):
        self._a_check(self._atmel.set_signature(sign_data, self.device_serial))

    @property
    def key_id(self):
        try:
            return CRCCCITT().calculate(b64_to_bytes(self.public_key))
        except Exception as e:
            self._logger.error("failed to calculate key id from public key: {}".format(e))
            sys.exit(e)

    @property
    def key_type(self):
        # return self._a_check(self._atmel.get_key_type(self.device_serial))
        return self._key_type

    def sign(self, data, long_sign=False):
        ops_status = self._atmel.sign_by_device(data, long_sign=long_sign, device_serial=self.device_serial)
        if not ops_status[0]:
            self._logger.error("signing failed: {}".format(ops_status[1]))
            sys.exit(ops_status[1])
        return ops_status[1]

    def verify(self, data, signature, long_sign=False):
        ops_status = self._atmel.verify_by_device(
            data,
            signature,
            self.public_key,
            device_serial=self.device_serial,
            long_sign=long_sign
        )
        if not ops_status[0]:
            self._logger.error("veryfing failed: {}".format(ops_status[1]))
            sys.exit(ops_status[1])
        return ops_status[1]

    def encrypt(self, data):
        ops_status = self._atmel.crypt_by_device(
            data,
            self.public_key,
            device_serial=self.device_serial)
        if not ops_status[0]:
            self._logger.error("encrypting failed: {}".format(ops_status[1]))
            sys.exit(ops_status[1])
        return ops_status[1]

    def decrypt(self, data):
        ops_status = self._atmel.decrypt_by_device(
            data,
            device_serial=self.device_serial)
        if not ops_status[0]:
            self._logger.error("decrypting failed: {}".format(ops_status[1]))
            sys.exit(ops_status[1])
        return ops_status[1]

    def generate(self, *, signature_limit=None, rec_pub_keys=None, signer_key=None, private_key_base64=None):
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = to_b64(bytearray(random_number_bytes))

        if not private_key_base64:
            # generation virgil crypto key
            virgil_key_pair = VirgilKeyPair.generate(self.ec_type)
            private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            private_key_base64 = to_b64(private_key)

        # setup pregenerated key to atmel device
        if self._a_check(self._atmel.set_private_key(private_key_base64, signature_limit, self.device_serial)) == 0:
            return

        # setup key type
        if self._a_check(self._atmel.set_key_type(self._key_type, self.device_serial)) == 0:
            return

        # setup recovery pub keys
        if rec_pub_keys:
            if self._atmel.set_recovery_pub_key(rec_pub_keys[0], 1, self.device_serial) == 0:
                return
            if self._atmel.set_recovery_pub_key(rec_pub_keys[1], 2, self.device_serial) == 0:
                return

        # setup sign to device
        if signer_key:
            pub_key = self._a_check(self._atmel.get_public_key(self.device_serial))
            if pub_key == 0:
                return

            sign_data = signer_key.sign(pub_key)
            if sign_data == 0:
                return

            if self._a_check(self._atmel.set_signature(sign_data, self.device_serial)) == 0:
                return

        # setup random number to device
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, self.device_serial)) == 0:
                return

        self._lock_data_field()
        self._private_key = private_key_base64
        return self
