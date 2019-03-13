import os
from tinydb import TinyDB, where

from .tinydb_storage_extensions import ByteStorage, CryptoByteStorage, SignedByteStorage


class KeysTinyDBStorage(object):

    def __init__(self, storage_path, storage_type=ByteStorage, storage_kwargs=None):
        self.storage_path = storage_path + ".db"
        self.__storage_type = storage_type
        self.__storage_kwargs = storage_kwargs or {}
        self.__table_name = os.path.split(self.storage_path)[1]

    @staticmethod
    def __compatibility(db_obj):
        return {str(db_obj.pop("key_id")): db_obj}

    def _get_db(self, suppress_db_warning=False):
        return TinyDB(
            self.storage_path,
            create_dirs=True,
            storage=self.__storage_type,
            default_table=self.__table_name,
            suppress_db_warning=suppress_db_warning,
            **self.__storage_kwargs
        )

    def save(self, key, value, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        db.table(self.__table_name).insert({"key_id": key, **value})
        db.close()

    def get_keys(self, suppress_db_warning=False):
        def get_keys_id(element_list, curr_eid):
            return element_list[curr_eid]["key_id"]
        db = self._get_db(suppress_db_warning)
        keys = db.table(self.__table_name).search(where("key_id").exists())
        db.close()
        return list(map(lambda x: x["key_id"], keys))

    def get_values(self, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        values = db.table(self.__table_name).search(where("key_id").exists())
        db.close()
        for value in values:
            del value["key_id"]
        return values

    def get_all_data(self, suppress_db_warning=False):
        data = dict()
        db = self._get_db(suppress_db_warning)
        new_data = db.table(self.__table_name).all()
        for d in new_data:
            data.update(self.__compatibility(d))
        db.close()
        return data

    def get_value(self, key, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        data = db.table(self.__table_name).get(where("key_id") == str(key))
        if data:
            del data["key_id"]
        db.close()
        return data

    def delete_key(self, key, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        db.table(self.__table_name).remove(where("key_id") == str(key))
        db.close()

    def resign(self, suppress_db_warning=False):
        if self.__storage_type is SignedByteStorage or self.__storage_type is CryptoByteStorage:
            db = self._get_db(suppress_db_warning)
            db.table("resign")
            db.close()

            db = self._get_db(suppress_db_warning)
            db.purge_table("resign")
            db.close()
