from abc import ABCMeta
from abc import abstractmethod


class FirmwareKeyGenerator(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def generate(self, *args, **kwargs):
        raise NotImplementedError()
