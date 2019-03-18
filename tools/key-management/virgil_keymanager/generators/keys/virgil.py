from PyCRC.CRCCCITT import CRCCCITT

from virgil_crypto import VirgilCrypto, VirgilKeyPair
from virgil_crypto.hashes import HashAlgorithm

from virgil_keymanager.core_utils import VirgilSignExtractor
from virgil_keymanager.core_utils.helpers import to_b64, b64_to_bytes


class VirgilKeyGenerator:
    """
    Represents key pair entity for virgil_crypto lib usage only (without dongles/emulator)
    """
    def __init__(self, key_type, private_key=None, public_key=None):
        self._crypto = VirgilCrypto()
        self._crypto.signature_hash_algorithm = HashAlgorithm.SHA256
        self.__key_type = key_type
        self.__public_key = None if not private_key else b64_to_bytes(public_key)
        self.__private_key = None if not private_key else b64_to_bytes(private_key)
        self.__key_id = None
        self.__signature = None
        self.device_serial = None

    def generate(self, *, signature_limit=None, rec_pub_keys=None, signer_key=None, private_key_base64=None):
        # method signature is compatible with AtmelKeyGenerator
        if private_key_base64:
            self.__private_key = b64_to_bytes(private_key_base64)
            self.__public_key = self._crypto.extract_public_key(self.__private_key).value[-64:]

        if self.__private_key is None:
            virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
            self.__private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            self.__public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]

        if signer_key:
            self.__signature = signer_key.sign(self.public_key)

        return self

    @property
    def private_key(self):
        return to_b64(self.__private_key)

    @property
    def public_key(self):
        return to_b64(self.__public_key)

    @property
    def public_key_full(self):
        virgil_private_key = self._crypto.import_private_key(b64_to_bytes(self.private_key))
        return to_b64(self._crypto.extract_public_key(virgil_private_key))

    @property
    def signature(self):
        return self.__signature

    @property
    def key_id(self):
        return CRCCCITT().calculate(b64_to_bytes(self.public_key))

    @property
    def key_type(self):
        return self.__key_type

    def sign(self, data, long_sign=False):  # long_sign is for compatibility with dongle signer
        data = b64_to_bytes(data)
        private_key = b64_to_bytes(self.private_key)
        signature = self._crypto.sign(data, self._crypto.import_private_key(private_key))
        if not long_sign:
            signature = VirgilSignExtractor.extract_sign(signature)
        return to_b64(signature)

    def verify(self, data, signature, long_sign=False):
        data = b64_to_bytes(data)
        public_key = b64_to_bytes(self.public_key_full)  # verify  signature with full public key
        return self._crypto.verify(data, signature, self._crypto.import_public_key(public_key))

    def encrypt(self, data):
        data = b64_to_bytes(data)
        public_key = b64_to_bytes(self.public_key_full)  # encrypt with full public key
        encrypted = self._crypto.encrypt(data, self._crypto.import_public_key(public_key))
        return to_b64(encrypted)

    def decrypt(self, data):
        data = b64_to_bytes(data)
        private_key = b64_to_bytes(self.private_key)
        decrypted = self._crypto.decrypt(data, self._crypto.import_private_key(private_key))
        return to_b64(decrypted)
