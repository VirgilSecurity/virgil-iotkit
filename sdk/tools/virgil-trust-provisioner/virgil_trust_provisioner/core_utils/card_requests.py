import json
import sys
import http.client
from datetime import datetime
from urllib.parse import urlparse

from virgil_crypto import VirgilCrypto
from virgil_sdk.cards import RawCardContent
from virgil_sdk.client import RawSignedModel, RawSignature

from virgil_trust_provisioner.consts import CARD_REGISTRATION_ENDPOINT, VSKeyTypeS
from virgil_trust_provisioner.core_utils.helpers import tiny_key_to_virgil
from virgil_trust_provisioner.generators.keys.interface import KeyGeneratorInterface
from virgil_trust_provisioner.core_utils.helpers import to_b64, b64_to_bytes


class CardRequestsHandler:
    def __init__(self, ui, logger, api_url, app_token):
        self._ui = ui
        self._logger = logger
        self._crypto = VirgilCrypto()
        self._api_host = urlparse(api_url).netloc
        self._app_token = app_token

        self._keys_counter = {}  # used for identities calculation: auth_1, auth_2

    def _create_raw_card(self, key_pair: KeyGeneratorInterface, key_info: dict) -> str:
        # Prepare public key in virgil format
        public_key = key_pair.public_key
        public_key = tiny_key_to_virgil(public_key)
        public_key = self._crypto.import_public_key(public_key)

        # Calculate identity.
        identity = key_pair.key_type
        # For keys which amount is 2 there should be identities like auth_1, auth_2
        if key_pair.key_type in (VSKeyTypeS.RECOVERY.value,
                                 VSKeyTypeS.AUTH.value,
                                 VSKeyTypeS.TRUSTLIST.value,
                                 VSKeyTypeS.FIRMWARE.value):
            if key_pair.key_type not in self._keys_counter or self._keys_counter[key_pair.key_type] == 2:
                key_number = 1
            else:
                key_number = 2
            identity = "%s_%s" % (identity, key_number)
            self._keys_counter[key_pair.key_type] = key_number

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

        # Return card request as json string
        return raw_card.to_json()

    def _register_card(self, card_b64):
        """
        Send card request to Things service
        """
        conn = http.client.HTTPSConnection(host=self._api_host)
        conn.request(method="POST",
                     url=CARD_REGISTRATION_ENDPOINT,
                     body=card_b64,
                     headers={"AppToken": self._app_token})
        response = conn.getresponse()
        resp_body = response.read()
        if response.status != 200:
            err_msg = ("[ERROR]: Failed to register Virgil card at {host}{endpoint}\n"
                       "Card: {card_b64}\n"
                       "Response status code: {status}\n"
                       "Response body: {body}".format(card_b64=card_b64,
                                                      host=self._api_host,
                                                      endpoint=CARD_REGISTRATION_ENDPOINT,
                                                      status=response.status,
                                                      body=resp_body))
            self._ui.print_error(err_msg)
            self._logger.error(err_msg)
            sys.exit(1)
        self._ui.print_message("Virgil Card for key successfully registered")
        self._logger.info("Card registered. Response: %s" % resp_body)

    def create_and_register_card(self, key: KeyGeneratorInterface, key_info: dict):
        card = self._create_raw_card(key, key_info)
        self._logger.info("Card request prepared: %s" % card)
        self._register_card(card)
