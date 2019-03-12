from virgil_keymanager.generators.keys.abstract.recovery_key import RecoveryKeyGenerator
from .virgil import Virgil


class VirgilRecoveryKeyGenerator(Virgil, RecoveryKeyGenerator):

    def __init__(self):
        super(VirgilRecoveryKeyGenerator, self).__init__()
