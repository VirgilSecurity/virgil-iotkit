import base64
from random import randint
from soraa_keymanager.generators.keys.abstract.cloud_key import CloudKeyGenerator
from .atmel import Atmel


class AtmelCloudKeyGenerator(Atmel, CloudKeyGenerator):

    def __init__(self, ui, atmel):
        Atmel.__init__(self, ui, atmel)
        super(AtmelCloudKeyGenerator, self).__init__(ui, atmel)

    def generate(self, device_serial, rec_pub_key1, rec_pub_key2):

        # additional params
        signature_limit = None
        random_number_bytes = list(randint(0, 255) for _ in range(32))
        random_number = base64.b64encode(bytearray(random_number_bytes)).decode("utf-8")

        # generate key on device
        if self._a_check(self._atmel.generate_private_key(signature_limit, device_serial)) == 0:
            return 0

        # setup key type
        soraa_key_type = "cloud"
        if self._a_check(self._atmel.set_soraa_key_type(soraa_key_type, device_serial)) == 0:
            return 0

        # setup recovery pub keys
        if self._atmel.set_recovery_pub_key(rec_pub_key1, 1, device_serial) == 0:
            return 0
        if self._atmel.set_recovery_pub_key(rec_pub_key2, 2, device_serial) == 0:
            return 0

        # setup random number
        if random_number:
            if self._a_check(self._atmel.set_random_number(random_number, device_serial)) == 0:
                return 0

        # return device serial
        return self._a_check(self._atmel.lock_data(device_serial))

    def sign(self, data, device_serial):
        return self._a_check(self._atmel.sign_by_device(data, device_serial=device_serial))
