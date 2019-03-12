from virgil_crypto import VirgilSigner
from virgil_keymanager.generators.keys.abstract.sdmpd_key import SDMPDKeyGenerator
from .virgil import Virgil


class VirgilSDMPDKeyGenerator(Virgil, SDMPDKeyGenerator):

    def __init__(self):
        super(VirgilSDMPDKeyGenerator, self).__init__()
        self.public_key = None

    def sign(self, private_key):
        if not self.public_key:
            return None
        signer = VirgilSigner(3)  # SHA256
        return signer.sign(self.public_key, private_key)
