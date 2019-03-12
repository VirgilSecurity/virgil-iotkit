from virgil_keymanager.generators.keys.abstract.firmaware_internal_key import FirmwareInternalKeyGenerator
from .virgil import Virgil


class VirgilFirmwareInternalKeyGenerator(Virgil, FirmwareInternalKeyGenerator):

    def __init__(self):
        super(VirgilFirmwareInternalKeyGenerator, self).__init__()
