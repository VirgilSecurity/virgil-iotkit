from abc import ABC, abstractmethod

from virgil_trust_provisioner import consts


class KeyGeneratorInterface(ABC):

    @abstractmethod
    def generate(self, *,
                 signature_limit,
                 rec_pub_keys,
                 signer_key,
                 private_key_base64,
                 start_date,
                 expire_date,
                 meta_data):
        pass

    @property
    @abstractmethod
    def ec_type(self):
        pass

    @property
    def ec_type_secmodule(self) -> int:
        t = consts.ec_type_vs_to_secmodule_map.get(self.ec_type, None)
        if t is None:
            raise ValueError("Can`t find SECMODULE EC key type for %s Virgil type" % self.ec_type)
        return t.value

    @property
    @abstractmethod
    def hash_type(self):
        pass

    @property
    def hash_type_secmodule(self):
        t = consts.hash_type_vs_to_secmodule_map.get(self.hash_type, None)
        if t is None:
            raise ValueError("Can`t find SECMODULE hash type for %s Virgil hash type" % self.hash_type)
        return t

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

    @property
    def key_type_secmodule(self) -> int:
        vs_type = consts.VSKeyTypeS(self.key_type)
        t = consts.key_type_str_to_num_map.get(vs_type, None)
        if t is None:
            raise ValueError("Can`t find SECMODULE key type for %s Virgil key type" % self.key_type)
        return t.value

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
