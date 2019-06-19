import base64
import json
import string
import random
from datetime import datetime

from virgil_crypto import VirgilCrypto
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel, RawSignature

from virgil_keymanager.core_utils.helpers import to_b64, b64_to_bytes

crypto = VirgilCrypto()


class VirgilBridge:

    def __init__(self, key, key_info: dict, exporter_keys, ui):
        self.__key = key
        self.__key_info = key_info
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

    def __create_virgil_card_model(self, public_key):
        # Get card identity
        identity = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(64))

        # Prepare card content snapshot
        created_at = int(datetime.utcnow().timestamp())
        card_content = RawCardContent(
            identity=identity,
            public_key=public_key,
            created_at=created_at
        )
        card_content_snapshot = card_content.content_snapshot

        # Create raw card
        raw_card = RawSignedModel(card_content_snapshot)

        # Sign combined snapshot (with key_info)
        key_info_b = json.dumps(self.__key_info).encode("utf-8")
        key_info_b64 = to_b64(key_info_b)
        combined_snapshot = to_b64(b64_to_bytes(card_content_snapshot) + b64_to_bytes(key_info_b64))

        signature = self.__key.sign(combined_snapshot, long_sign=True)
        if not signature:
            self.__ui.print_error("[ERROR]: Virgil Card creation request: signing failed")
            return

        raw_signature = RawSignature(
            signer="self",
            signature=b64_to_bytes(signature),
            signature_snapshot=b64_to_bytes(key_info_b64)
        )

        # Append signature to card
        raw_card.signatures.append(raw_signature)

        # Return bas64 encoded string
        return raw_card.to_string()

    def export_virgil_card_model(self):
        public_key = self.__key.public_key
        public_key = self.__tiny_key_to_virgil(public_key)
        public_key = crypto.import_public_key(public_key)

        exported_virgil_card_b64 = self.__create_virgil_card_model(public_key)
        if not exported_virgil_card_b64:
            return

        imported_private_key = crypto.import_private_key(
            tuple(self.__exporter_keys["private"]),
            self.__exporter_keys["password"]
        )
        imported_public_key = crypto.import_public_key(
            self.__exporter_keys["public"]
        )

        crypted_signed_exported_request = crypto.sign_then_encrypt(
            exported_virgil_card_b64.encode('utf-8'),
            imported_private_key,
            imported_public_key
        )
        return to_b64(crypted_signed_exported_request)
