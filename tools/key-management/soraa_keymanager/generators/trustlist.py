import base64

from PyCRC.CRCCCITT import CRCCCITT

from soraa_keymanager.data_types import TrustList


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
        auth_key_serial,
        tl_svc_key_serial,
        tl_version,
        release_tl_keys_structure=None,
        dev_mode=False,
        include_internal_keys=False
    ):
        raw_keys_dict = self.__storage.get_all_data()

        if include_internal_keys:
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

        if dev_mode:
            tl_type = TrustList.TrustListType.DEV
        else:
            tl_type = TrustList.TrustListType.RELEASE

        self.__tl = TrustList(keys_dict, tl_type, tl_version, release_tl_keys_structure)

        # get data for sign
        data_for_sign = base64.b64encode(bytes(self.__tl.get_bytes_for_sign())).decode("utf-8")

        # get public tl_svc_key
        tl_svc_pub_key = self.__a_check(self.__atmel.get_public_key(tl_svc_key_serial))
        if tl_svc_pub_key == 0:
            return

        # calculate tl_svc_key_id
        tl_svc_pub_key_id = CRCCCITT().calculate(base64.b64decode(tl_svc_pub_key))
        if tl_svc_pub_key_id == 0:
            return

        # sign tl by tl_svc_key
        tl_svc_key_signature = self.__a_check(
            self.__atmel.sign_by_device(data_for_sign, device_serial=tl_svc_key_serial))
        if tl_svc_key_signature == 0:
            return

        # setup tl_svc_key signature to tl
        self.__tl.tl_service_key_signature = tl_svc_key_signature

        # setup tl_svc_key id
        self.__tl.tl_service_key_id = tl_svc_pub_key_id

        # get public auth key
        auth_pub_key = self.__a_check(self.__atmel.get_public_key(auth_key_serial))
        if auth_pub_key == 0:
            return

        # calculate auth_key_id
        auth_pub_key_id = CRCCCITT().calculate(base64.b64decode(auth_pub_key))
        if auth_pub_key_id == 0:
            return

        # sign tl by auth key
        auth_key_signature = self.__a_check(self.__atmel.sign_by_device(data_for_sign, device_serial=auth_key_serial))
        if auth_key_signature == 0:
            return

        # setup auth_key signature to tl
        self.__tl.auth_key_signature = auth_key_signature

        # setup auth_key id
        self.__tl.auth_key_id = auth_pub_key_id

        return self.__tl

    @staticmethod
    def __sieve_internal_keys(keys_dict):
        sieved_keys_dict = dict()
        for key_id in keys_dict.keys():
            if "_internal" not in keys_dict[key_id]["type"]:
                sieved_keys_dict[key_id] = keys_dict[key_id]
        return sieved_keys_dict
