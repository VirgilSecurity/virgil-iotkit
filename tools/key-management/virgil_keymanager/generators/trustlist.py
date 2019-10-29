from virgil_keymanager import consts
from virgil_keymanager.data_types.trustlist_type import TrustList


class TrustListGenerator(object):

    def __init__(self, ui, storage):
        self.__tl = None  # type: TrustList
        self.__ui = ui
        self.__storage = storage

    def generate(
        self,
        signer_keys,
        tl_version,
        generate_dev_tl=False
    ):
        raw_keys_dict = self.__storage.get_all_data()

        if generate_dev_tl:
            keys_dict = raw_keys_dict
        else:
            keys_dict = self.__sieve_internal_keys(raw_keys_dict)

        if generate_dev_tl:
            tl_type = consts.TrustListType.DEV
        else:
            tl_type = consts.TrustListType.RELEASE

        self.__tl = TrustList(
            pub_keys_dict=keys_dict,
            signer_keys=signer_keys,
            tl_type=tl_type,
            tl_version=tl_version)

        return self.__tl

    @staticmethod
    def __sieve_internal_keys(keys_dict):
        sieved_keys_dict = dict()
        for key_id in keys_dict.keys():
            if "_internal" not in keys_dict[key_id]["type"]:
                sieved_keys_dict[key_id] = keys_dict[key_id]
        return sieved_keys_dict
