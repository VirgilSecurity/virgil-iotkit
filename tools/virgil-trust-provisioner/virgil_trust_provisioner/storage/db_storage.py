import shelve
import os

import _dbm

import sys


class DBStorage:

    def __init__(self, storage_path):
        self.storage_path = storage_path
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])

    def save(self, key, value, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        try:
            db = shelve.open(self.storage_path, writeback=True)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        db[str(key)] = value
        db.close()

    def get_keys(self, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])
        try:
            db = shelve.open(self.storage_path)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        keys = list(db.keys())
        db.close()
        return keys

    def get_values(self, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])
        try:
            db = shelve.open(self.storage_path)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        values = list(db.values())
        db.close()
        return values

    def get_all_data(self, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])
        try:
            db = shelve.open(self.storage_path)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        result = {}
        for key in list(db.keys()):
            result[key] = db[key]
        db.close()
        return result

    def get_value(self, key, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])
        try:
            db = shelve.open(self.storage_path)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        if str(key) in db.keys():
            key = db[str(key)]
            db.close()
            return key
        else:
            return

    def delete_key(self, key, suppress_db_warning=False):
        # suppress_db_warning added for compatibility with tinydb storage
        if not os.path.exists(os.path.split(self.storage_path)[0]):
            os.makedirs(os.path.split(self.storage_path)[0])
        try:
            db = shelve.open(self.storage_path)
        except _dbm.error:
            sys.exit("[FATAL]: Wrong database format!")
        del db[key]
        db.close()

    def resign(self, suppress_db_warning=False):
        pass

