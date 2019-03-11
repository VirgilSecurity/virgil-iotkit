from abc import ABCMeta, abstractmethod


class KeyStorage(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def save(self, data, place):
        """
        Abstract save method for different type storage.
        Args:
            data: Data to write to storage
            place: Place for storing data
        """
        raise NotImplementedError()
