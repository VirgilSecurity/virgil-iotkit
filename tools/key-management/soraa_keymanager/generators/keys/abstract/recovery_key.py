from abc import ABCMeta
from abc import abstractmethod


class RecoveryKeyGenerator(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def generate(self, *args, **kwargs):
        raise NotImplementedError()

    def sign(self, *args, **kwargs):
        raise NotImplementedError()
