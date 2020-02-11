import os

from virgil_trust_provisioner.core_utils import CRCCCITT

from virgil_trust_provisioner.data_types import TrustList


class FileKeyStorage:

    def __init__(self, storage_path):
        super(FileKeyStorage, self).__init__()
        self.storage_path = storage_path

    def __save_key_pair(self, file_name, key_pair):
        file_prefix = CRCCCITT().calculate(bytes(key_pair.public_key))
        file_path_public = os.path.join(self.storage_path, file_name + '_pub_' + str(file_prefix))
        file_path_private = os.path.join(self.storage_path, file_name + '_priv_' + str(file_prefix))
        open(file_path_public, 'wb').write(bytearray(key_pair.public_key))
        open(file_path_private, 'wb').write(bytearray(key_pair.private_key))

    def __save_trust_list(self, file_name, trust_list):
        file_prefix = CRCCCITT().calculate(bytes(trust_list))
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)
        file_path = os.path.join(
            self.storage_path,
            file_name + '_' + str(file_prefix) + '.tl'
        )
        open(file_path, 'wb').write(bytes(trust_list))

    def __save_blob(self, file_name, data):
        file_path = os.path.join(self.storage_path, file_name)
        open(file_path, 'wb').write(data)

    def save(self, data, place):
        """
        Store data to file in hardcoded place.
        Args:
            data: Data for storing.
            place: File name for storing data.
        """
        if isinstance(data, TrustList):
            self.__save_trust_list(place, data)

        if isinstance(data, (bytes, bytearray)):
            self.__save_blob(place, data)
