from virgil_keymanager.generators.keys.abstract.factory_key import FactoryKeyGenerator
from .virgil import Virgil


class VirgilFactoryKeyGenerator(Virgil, FactoryKeyGenerator):

    def __init__(self):
        super(VirgilFactoryKeyGenerator, self).__init__()
