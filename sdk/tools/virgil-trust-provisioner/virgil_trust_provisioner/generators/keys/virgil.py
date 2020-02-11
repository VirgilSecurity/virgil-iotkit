import io
from typing import Optional

from virgil_trust_provisioner.core_utils import CRCCCITT

from virgil_crypto import VirgilCrypto, VirgilKeyPair
from virgil_crypto.hashes import HashAlgorithm

from virgil_trust_provisioner.generators.keys.interface import KeyGeneratorInterface
from virgil_trust_provisioner.core_utils import VirgilSignExtractor
from virgil_trust_provisioner.core_utils.helpers import to_b64, b64_to_bytes


class VirgilKeyGenerator(KeyGeneratorInterface):
    """
    Represents key pair entity for virgil_crypto lib usage only
    """

    def __init__(self,
                 key_type: str,
                 private_key=None,
                 public_key=None,
                 ec_type=VirgilKeyPair.Type_EC_SECP256R1,
                 hash_type=HashAlgorithm.SHA256):
        self._crypto = VirgilCrypto()
        self._crypto.signature_hash_algorithm = hash_type
        self.__hash_type = hash_type
        self.__key_type = key_type
        self.__ec_type = ec_type
        self.__public_key = None if not public_key else b64_to_bytes(public_key)
        self.__private_key = None if not private_key else b64_to_bytes(private_key)
        self.__key_id = None
        self.__signature = None
        self.device_serial = None

    def generate(self,
                 *,
                 signature_limit=None,
                 rec_pub_keys=None,
                 signer_key: Optional[KeyGeneratorInterface]=None,
                 private_key_base64: Optional[str]=None,
                 start_date: Optional[int]=0,
                 expire_date: Optional[int]=0,
                 meta_data: Optional[bytes]=bytes()):
        def make_signature():
            byte_buffer = io.BytesIO()

            # vs_pubkey_dated_t
            byte_buffer.write(start_date.to_bytes(4, byteorder='big', signed=False))
            byte_buffer.write(expire_date.to_bytes(4, byteorder='big', signed=False))
            byte_buffer.write(self.key_type_secmodule.to_bytes(1, byteorder='big', signed=False))
            byte_buffer.write(self.ec_type_secmodule.to_bytes(1, byteorder='big', signed=False))
            byte_buffer.write(len(meta_data).to_bytes(2, byteorder='big', signed=False))
            byte_buffer.write(meta_data)
            byte_buffer.write(b64_to_bytes(self.public_key))

            bytes_to_sign = byte_buffer.getvalue()
            return signer_key.sign(to_b64(bytes_to_sign), long_sign=False)

        if private_key_base64:
            self.__private_key = b64_to_bytes(private_key_base64)
            virgil_priv_key = self._crypto.import_private_key(self.__private_key)
            virgil_pubkey = self._crypto.extract_public_key(virgil_priv_key)
            self.__public_key = VirgilKeyPair.publicKeyToDER(virgil_pubkey.raw_key)[-65:]

        if self.__private_key is None:
            virgil_key_pair = VirgilKeyPair.generate(self.ec_type)
            self.__private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
            self.__public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-65:]

        if signer_key:
            self.__signature = make_signature()

        return self

    @property
    def ec_type(self):
        return self.__ec_type

    @property
    def hash_type(self):
        return self.__hash_type

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

    def sign(self, data, long_sign=False):
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
