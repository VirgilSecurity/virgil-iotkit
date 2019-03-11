from abc import ABCMeta, abstractmethod


class SDMPDKeyGenerator(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def generate(self, *args, **kwargs):
        raise NotImplementedError()
