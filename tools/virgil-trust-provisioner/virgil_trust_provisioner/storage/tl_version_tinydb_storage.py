import os
from tinydb import TinyDB, where

from .tinydb_storage_extensions import ByteStorage


class TLVersionTinyDBStorage:

    def __init__(self, storage_path, storage_type=ByteStorage, storage_kwargs=None):
        self.storage_path = storage_path + ".db"
        self.__storage_type = storage_type
        self.__storage_kwargs = storage_kwargs or {}
        self.__table_name = os.path.split(self.storage_path)[1]

    def _get_db(self, suppress_db_warning=False):
        return TinyDB(
            self.storage_path,
            storage=self.__storage_type,
            default_table=self.__table_name,
            suppress_db_warning=suppress_db_warning,
            **self.__storage_kwargs
        )

    def save(self, key, value, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        db.table(self.__table_name).upsert({key: value}, where(key).exists())
        db.close()

    def get_value(self, key, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        data = db.table(self.__table_name).get(where(key))
        del data["key_id"]
        db.close()
        return data

    def get_keys(self, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        keys = db.table(self.__table_name).search(where("*_version").exists())
        db.close()
        return list(map(lambda x: x.keys(), keys))

    def get_release_version(self, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        version = db.table(self.__table_name).get(where("release_version").exists())
        db.close()
        return version["release_version"] if version else "0.0.0.0"

    def get_dev_version(self, suppress_db_warning=False):
        db = self._get_db(suppress_db_warning)
        version = db.table(self.__table_name).get(where("dev_version").exists())
        db.close()
        return version["dev_version"] if version else "0.0.0.0"
