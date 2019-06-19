from virgil_keymanager import consts
from virgil_keymanager.data_types.trustlist_type import TrustList


class TrustListGenerator(object):

    def __init__(self, ui, storage, atmel):
        self.__tl = None  # type: TrustList
        self.__ui = ui
        self.__storage = storage
        self.__atmel = atmel

    def __a_check(self, atmel_ops_status):
        """
        Atmel operation checker. Check status of operation.

        Args:
            atmel_ops_status:  atmel operation output
        Returns:
            In error case print error and return 0
            In success return, object of function return
        """
        if not atmel_ops_status[0]:
            self.__ui.print_error(atmel_ops_status[1])
            return 0
        return atmel_ops_status[1]

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

        # choose_dict = [
        #     ["Release", TrustList.TrustListType.RELEASE],
        #     ["Dev", TrustList.TrustListType.DEV],
        #     ["Alpha", TrustList.TrustListType.ALPHA],
        #     ["Beta", TrustList.TrustListType.BETA]
        # ]
        # choice = self._ui.choose_from_list(choose_dict, "Please input number of type: ", "Trust List Types: ")
        # tl_type = choose_dict[choice][1]

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
