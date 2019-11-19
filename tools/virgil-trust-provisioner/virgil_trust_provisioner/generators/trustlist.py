from virgil_trust_provisioner import consts
from virgil_trust_provisioner.data_types.trustlist_type import TrustList


class TrustListGenerator:

    def __init__(self, ui, storage):
        self.__tl = None  # type: TrustList
        self.__ui = ui
        self.__storage = storage

    def generate(self, signer_keys, tl_version):
        keys_dict = self.__storage.get_all_data()
        tl_type = consts.TrustListType.RELEASE

        self.__tl = TrustList(
            pub_keys_dict=keys_dict,
            signer_keys=signer_keys,
            tl_type=tl_type,
            tl_version=tl_version)

        return self.__tl
