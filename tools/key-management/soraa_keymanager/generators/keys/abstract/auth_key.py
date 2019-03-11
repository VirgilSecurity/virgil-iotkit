from abc import ABCMeta
from abc import abstractmethod


class AuthKeyGenerator(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def generate(self, *args, **kwargs):
        raise NotImplementedError()

    @abstractmethod
    def sign(self, *args, **kwargs):
        raise NotImplementedError()
