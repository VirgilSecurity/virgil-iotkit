import json
import os
import binascii

from tinydb import Storage
from tinydb.storages import touch


class ByteStorage(Storage):
    """
    Store the data in a hexlified pickled bytes file.
    """

    def __init__(self, path, create_dirs=False, **kwargs):
        """
        Create a new instance.

        Also creates the storage file, if it doesn't exist.

        :param path: Where to store the JSON data.
        :type path: str
        """

        super(ByteStorage, self).__init__()
        self._suppress_db_warning = kwargs.pop("suppress_db_warning") or False
        touch(path, create_dirs=create_dirs)  # Create file if not exists
        self.kwargs = kwargs
        self._handle = open(path, 'r+b')

    def close(self):
        self._handle.close()

    def read(self):
        # Get the file size
        self._handle.seek(0, os.SEEK_END)
        size = self._handle.tell()

        if not size:
            # File is empty
            return None
        else:
            self._handle.seek(0)
            data = self._handle.read()
            return json.loads(binascii.unhexlify(data).decode())

    def write(self, data):
        self._handle.seek(0)
        serialized = json.dumps(data, **self.kwargs).encode()
        self._handle.write(binascii.hexlify(serialized))
        self._handle.flush()
        self._handle.truncate()
