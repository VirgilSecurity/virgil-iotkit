from virgil_keymanager.data_types import KeyPair
from virgil_crypto import VirgilKeyPair


class VirgilKeyGenerator(object):

    def generate(self):
        virgil_key_pair = VirgilKeyPair.generate(VirgilKeyPair.Type_EC_SECP256R1)
        private_key = VirgilKeyPair.privateKeyToDER(virgil_key_pair.privateKey())
        public_key = VirgilKeyPair.publicKeyToDER(virgil_key_pair.publicKey())[-64:]
        return KeyPair(private_key=private_key, public_key=public_key)
