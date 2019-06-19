from abc import ABC, abstractmethod


class KeyGeneratorInterface(ABC):

    @abstractmethod
    def generate(self, *, signature_limit, rec_pub_keys, signer_key, private_key_base64):
        pass

    @property
    @abstractmethod
    def ec_type(self):
        pass

    @property
    @abstractmethod
    def hash_type(self):
        pass

    @property
    @abstractmethod
    def private_key(self):
        pass

    @property
    @abstractmethod
    def public_key(self):
        pass

    @property
    @abstractmethod
    def signature(self):
        pass

    @property
    @abstractmethod
    def key_id(self):
        pass

    @property
    @abstractmethod
    def key_type(self):
        pass

    @abstractmethod
    def sign(self, data, long_sign):
        pass

    @abstractmethod
    def verify(self, data, signature, long_sign):
        pass

    @abstractmethod
    def encrypt(self, data):
        pass

    @abstractmethod
    def decrypt(self, data):
        pass
