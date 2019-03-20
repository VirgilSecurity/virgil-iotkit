import shelve

import os


class DBStorage(object):

    def __init__(self, storage_path):
        self.__storage_path = storage_path
        if not os.path.exists(os.path.split(self.__storage_path)[0]):
            os.makedirs(os.path.split(self.__storage_path)[0])

    def get_keys(self):
        db = shelve.open(self.__storage_path)
        keys = list(db.keys())
        db.close()
        return keys

    def get_all_data(self):
        db = shelve.open(self.__storage_path)
        result = {}
        for key in list(db.keys()):
            result[key] = db[key]
        db.close()
        return result

    def get_value(self, key):
        db = shelve.open(self.__storage_path)
        key = db[str(key)]
        db.close()
        return key

