

class DonglesCache(object):

    def __init__(self, disable=False):
        self.__disable = disable
        self.__serial_index = dict()
        self.__key_id_index = dict()
        self.__type_index = dict()

    def add(self, key_data):
        if not self.__disable:
            self.__serial_index[key_data["device_serial"]] = key_data
            self.__key_id_index[key_data["key_id"]] = key_data
            if key_data["type"] not in self.__type_index.keys():
                self.__type_index[key_data["type"]] = list()
            self.__type_index[key_data["type"]].append(key_data)

    def drop(self):
        self.__serial_index = dict()
        self.__key_id_index = dict()
        self.__type_index = dict()

    def search_serial(self, device_serial):
        if device_serial in self.__serial_index.keys():
            return self.__serial_index[device_serial]

    def search_id(self, key_id):
        if key_id in self.__key_id_index.keys():
            return self.__key_id_index[key_id]

    def search_type(self, key_type):
        if key_type in self.__type_index.keys():
            return self.__type_index[key_type]
