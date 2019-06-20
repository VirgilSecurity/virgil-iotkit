import json
import os
import string
import random
import sys
from datetime import datetime

from virgil_crypto import VirgilCrypto
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel, RawSignature

from virgil_keymanager.core_utils.helpers import tiny_key_to_virgil
from virgil_keymanager.generators.keys.interface import KeyGeneratorInterface
from virgil_keymanager.core_utils.helpers import to_b64, b64_to_bytes


class CardRequestsHandler:
    def __init__(self, ui, logger, exporter_keys, path_to_requests_file):
        self._ui = ui
        self._logger = logger
        self._crypto = VirgilCrypto()
        self._path_to_requests_file = path_to_requests_file

        # Prepare keys for requests encryption
        self._request_encrypt_private_key = self._crypto.import_private_key(
            tuple(exporter_keys["private"]),
            exporter_keys["password"]
        )
        self._recipient_public_key = self._crypto.import_public_key(
            exporter_keys["public"]
        )

    def _create_raw_card(self, key_pair: KeyGeneratorInterface, key_info: dict) -> str:
        # Prepare public key in virgil format
        public_key = key_pair.public_key
        public_key = tiny_key_to_virgil(public_key)
        public_key = self._crypto.import_public_key(public_key)

        # Generate card identity
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
        key_info_b = json.dumps(key_info).encode("utf-8")
        key_info_b64 = to_b64(key_info_b)
        combined_snapshot = to_b64(b64_to_bytes(card_content_snapshot) + b64_to_bytes(key_info_b64))

        signature = key_pair.sign(combined_snapshot, long_sign=True)
        if not signature:
            err_msg = "[ERROR]: Virgil Card creation request: signing failed"
            self._ui.print_error(err_msg)
            self._logger.error(err_msg)
            sys.exit(1)

        raw_signature = RawSignature(
            signer="self",
            signature=b64_to_bytes(signature),
            signature_snapshot=b64_to_bytes(key_info_b64)
        )

        # Append signature to card
        raw_card.signatures.append(raw_signature)

        # Return card request as base64 encoded string
        return raw_card.to_string()

    def _create_encrypted_card_request(self, key: KeyGeneratorInterface, key_info: dict) -> str:
        exported_virgil_card_b64 = self._create_raw_card(key, key_info)

        encrypted_card_request = self._crypto.sign_then_encrypt(
            exported_virgil_card_b64.encode('utf-8'),
            self._request_encrypt_private_key,
            self._recipient_public_key
        )
        return to_b64(encrypted_card_request)

    def _save_card_request_to_file(self, encrypted_request: str):
        folder_path = os.path.dirname(self._path_to_requests_file)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        with open(self._path_to_requests_file, "a") as f:
            f.write(encrypted_request + "\n")

    def create_and_save_request_for_key(self, key: KeyGeneratorInterface, key_info: dict):
        encrypted_request = self._create_encrypted_card_request(key, key_info)
        if not encrypted_request:
            err_msg = "[ERROR]: Failed to create encrypted card request"
            self._ui.print_error(err_msg)
            self._logger.error(err_msg)
            sys.exit(1)

        self._save_card_request_to_file(encrypted_request)
