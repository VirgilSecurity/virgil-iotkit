from virgil_keymanager.generators.keys.abstract.factory_key import FactoryKeyGenerator
from .virgil import Virgil


class VirgilCloudKeyGenerator(Virgil, FactoryKeyGenerator):

    def __init__(self):
        super(VirgilCloudKeyGenerator, self).__init__()
