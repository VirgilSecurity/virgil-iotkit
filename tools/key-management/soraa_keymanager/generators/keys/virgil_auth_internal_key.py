from soraa_keymanager.generators.keys.abstract.auth_internal_key import AuthInternalKeyGenerator
from .virgil import Virgil


class VirgilAuthInternalKeyGenerator(Virgil, AuthInternalKeyGenerator):

    def __init__(self):
        super(VirgilAuthInternalKeyGenerator, self).__init__()
