import base64
from datetime import datetime

from PyCRC.CRCCCITT import CRCCCITT
from virgil_sdk.api import VirgilContext, VirgilCard
from virgil_sdk.client import Card
from virgil_sdk.client.requests import CreateCardRequest


class VirgilBridge(object):

    def __init__(self, atmel, exporter_keys, ui):
        self.__virgil_context = VirgilContext()
        self.__atmel = atmel
        self.__exporter_keys = exporter_keys
        self.__ui = ui

    def __a_check(self, atmel_ops_status):
        """
        Atmel operation checker. Check status of operation.

        Args:
            atmel_ops_status:  atmel operation output
        Returns:
            In error case print error and return 0
            In success return, object of function return
        """
        if not atmel_ops_status[0]:
            self.__ui.print_error(atmel_ops_status[1])
            return 0
        return atmel_ops_status[1]

    def __tiny_key_to_virgil(self, tiny_key):
        asn_1_prefix = bytearray(
            [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
                0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00, 0x04
            ]
        )

        key_data = asn_1_prefix + bytearray(base64.b64decode(tiny_key))

        return key_data

    def __create_virgil_card_model(self, key_type, key_id, public_key, device_serial=None, private_key=None):
        timestamp = base64.b64encode(str(datetime.now().timestamp()).encode()).decode()
        card_config = {
            "identity": "soraa_{key_type}".format(key_type=key_type),
            "identity_type": key_type,
            "public_key": base64.b64decode(public_key),
            "data": {"timestamp": timestamp, "key_id": str(key_id)},
        }
        card_model = Card(**card_config, version="4.0")
        card_request = CreateCardRequest(**card_config)
        card_model.snapshot = card_request.snapshot
        snapshot_fingerprint = self.__virgil_context.crypto.calculate_fingerprint(card_model.snapshot)
        card_model.scope = Card.Scope.APPLICATION
        card_model.id = snapshot_fingerprint.to_hex
        self_signature = None
        if device_serial:
            self_signature = self.__a_check(
                self.__atmel.sign_by_device(
                    base64.b64encode(bytes(snapshot_fingerprint.value)).decode("utf-8"),
                    long_sign=True,
                    device_serial=device_serial
                )
            )
            if self_signature == 0:
                return
        if private_key:
            self_signature = self.__virgil_context.crypto.sign(
                tuple(snapshot_fingerprint.value),
                self.__virgil_context.crypto.import_private_key(private_key)
            )
            self_signature = base64.b64encode(bytes(self_signature)).decode("utf-8")
        if not self_signature:
            self.__ui.print_error("[ERROR]: Virgil Card creation request signing failed")
            return
        card_model.signatures = {card_model.id: self_signature}
        virgil_card = VirgilCard(self.__virgil_context, card_model)
        return virgil_card.export()

    def __export_virgil_card_model(self, key_type, key_id, public_key, device_serial=None, private_key=None):

        public_key = self.__tiny_key_to_virgil(public_key)
        public_key = base64.b64encode(bytes(public_key)).decode("utf-8")

        exported_virgil_card = self.__create_virgil_card_model(key_type, key_id, public_key, device_serial, private_key)
        if not exported_virgil_card:
            return

        imported_private_key = self.__virgil_context.crypto.import_private_key(
            tuple(self.__exporter_keys["private"]),
            self.__exporter_keys["password"]
        )
        imported_public_key = self.__virgil_context.crypto.import_public_key(
            self.__exporter_keys["public"]
        )

        crypted_signed_exported_request = self.__virgil_context.crypto.sign_then_encrypt(
            bytearray(exported_virgil_card.encode()),
            imported_private_key,
            imported_public_key
        )
        return base64.b64encode(bytes(crypted_signed_exported_request)).decode("utf-8")

    def prepare_virgil_card(self, device_serial):
        public_key = self.__a_check(self.__atmel.get_public_key(device_serial))
        if public_key == 0:
            return

        key_type = self.__a_check(self.__atmel.get_key_type(device_serial))
        if key_type == 0:
            return

        key_id = CRCCCITT().calculate(base64.b64decode(public_key))

        return self.__export_virgil_card_model(key_type, key_id, public_key, device_serial=device_serial)

    def prepare_virgil_card_from_data(self, key_type, key_id, public_key, private_key):
        return self.__export_virgil_card_model(key_type, key_id, public_key, private_key=private_key)
