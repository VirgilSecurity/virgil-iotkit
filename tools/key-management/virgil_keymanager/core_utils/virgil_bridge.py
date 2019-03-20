import base64
from datetime import datetime

from virgil_sdk.api import VirgilContext, VirgilCard
from virgil_sdk.client import Card
from virgil_sdk.client.requests import CreateCardRequest

from virgil_keymanager.core_utils.helpers import to_b64, b64_to_bytes


class VirgilBridge(object):

    def __init__(self, key, exporter_keys, ui):
        self.__virgil_context = VirgilContext()
        self.__key = key
        self.__exporter_keys = exporter_keys
        self.__ui = ui

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

    def __create_virgil_card_model(self, key_type, key_id, public_key):
        timestamp = to_b64(str(datetime.now().timestamp()).encode())
        card_config = {
            "identity": "{key_type}".format(key_type=key_type),
            "identity_type": key_type,
            "public_key": b64_to_bytes(public_key),
            "data": {"timestamp": timestamp, "key_id": str(key_id)},
        }
        card_model = Card(**card_config, version="4.0")
        card_request = CreateCardRequest(**card_config)
        card_model.snapshot = card_request.snapshot
        snapshot_fingerprint = self.__virgil_context.crypto.calculate_fingerprint(card_model.snapshot)
        card_model.scope = Card.Scope.APPLICATION
        card_model.id = snapshot_fingerprint.to_hex

        self_signature = self.__key.sign(to_b64(bytes(snapshot_fingerprint.value)), long_sign=True)

        if not self_signature:
            self.__ui.print_error("[ERROR]: Virgil Card creation request signing failed")
            return
        card_model.signatures = {card_model.id: self_signature}
        virgil_card = VirgilCard(self.__virgil_context, card_model)
        return virgil_card.export()

    def export_virgil_card_model(self):

        key_type = self.__key.key_type
        key_id = self.__key.key_id

        public_key = self.__key.public_key
        public_key = self.__tiny_key_to_virgil(public_key)
        public_key = to_b64(public_key)

        exported_virgil_card = self.__create_virgil_card_model(key_type, key_id, public_key)
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
        return to_b64(crypted_signed_exported_request)
