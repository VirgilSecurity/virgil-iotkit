import io
from typing import List

from virgil_keymanager import consts
from virgil_keymanager.core_utils.helpers import b64_to_bytes, to_b64
from virgil_keymanager.generators.keys.interface import KeyGeneratorInterface


class Header:
    """
    type Header struct {
        WholeTLSize      uint32
        Version          uint16
        PubKeysCount     uint16
        SignaturesCount  uint8
    }
    """
    SIZE = 4 + 2 + 2 + 1  # see structure in class doc-string

    def __init__(self, whole_tl_size: int, version: int, pub_keys_count: int, signatures_count: int):
        self._whole_tl_size = whole_tl_size
        self._version = version
        self._pub_keys_count = pub_keys_count
        self._signatures_count = signatures_count

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._whole_tl_size.to_bytes(4, byteorder='little', signed=False))
            byte_buffer.write(self._version.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self._pub_keys_count.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self._signatures_count.to_bytes(1, byteorder='little', signed=False))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class Signature:
    """
    type Signature struct {
        SignerType       uint8
        ECType           uint8
        Hash_type        uint8
        Sign             [SignSize]byte
        SignerPublicKey  []byte
    }
    """
    def __init__(self, signer_type: int, ec_type: int, hash_type: int, sign: bytearray, signer_pub_key: bytearray):
        self._signer_type = signer_type
        self._ec_type = ec_type
        self._hash_type = hash_type
        self._sign = sign
        self._signer_pub_key = signer_pub_key

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._signer_type.to_bytes(1, byteorder='little', signed=False))
            byte_buffer.write(self._ec_type.to_bytes(1, byteorder='little', signed=False))
            byte_buffer.write(self._hash_type.to_bytes(1, byteorder='little', signed=False))
            byte_buffer.write(self._sign)
            byte_buffer.write(self._signer_pub_key)
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class Footer:
    """
    type Footer struct {
        TLType        uint8
        Signatures    [SignaturesCount]Signature
    }
    """
    def __init__(self, tl_type: int, signatures: List[Signature]):
        self.tl_type = tl_type
        self.signatures = signatures

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self.tl_type.to_bytes(1, byteorder='little', signed=False))
            for signature in self.signatures:
                byte_buffer.write(bytes(signature))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class PubKeyStructure:
    """
    type PubKeyStructure struct {
        StartDate       uint32
        ExpirationDate  uint32
        KeyType         uint16
        ECType          uint16
        PubKey          [PublicKeySize]byte
    }
    """
    def __init__(self, start_date: int, expiration_date: int, key_type: int, ec_type: int, pub_key: bytearray):
        self._start_date = start_date
        self._expiration_date = expiration_date
        self._key_type = key_type
        self._ec_type = ec_type
        self._pub_key = pub_key

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._start_date.to_bytes(4, byteorder='little', signed=False))
            byte_buffer.write(self._expiration_date.to_bytes(4, byteorder='little', signed=False))
            byte_buffer.write(self._key_type.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self._ec_type.to_bytes(2, byteorder='little', signed=False))
            byte_buffer.write(self._pub_key)
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return 2 + 2 + 4 + 4 + len(self._pub_key)  # see structure in class doc-string


class Body:
    def __init__(self, pub_keys: List[PubKeyStructure]):
        self.pub_keys = pub_keys

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            for pub_key in self.pub_keys:
                byte_buffer.write(bytes(pub_key))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class TrustList:
    def __init__(self,
                 pub_keys_dict: dict,
                 signer_keys: List[KeyGeneratorInterface],
                 tl_type: consts.TrustListType,
                 tl_version: int
                 ):
        self._pub_keys_dict = pub_keys_dict
        self._signer_keys = signer_keys
        self._tl_type = tl_type
        self._tl_version = tl_version

        self._header = None  # type: Header
        self._body = None    # type: Body
        self._footer = None  # type: Footer

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(bytes(self.header))
            byte_buffer.write(bytes(self.body))
            byte_buffer.write(bytes(self.footer))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(self.header) + len(self.body) + len(self.footer)

    @property
    def header(self) -> Header:
        if self._header is None:
            # Calculate expected footer size
            tl_type_sz = 1  # TLType field size
            # Size of all signatures (only) inside Signatures[]
            signatures_only_sz = sum(consts.signature_sizes[signer_key.ec_type] for signer_key in self._signer_keys)
            # Size of all signer pub keys inside Signatures[]
            signatures_pub_keys_sz = sum(consts.pub_keys_sizes[signer_key.ec_type] for signer_key in self._signer_keys)
            # Size of all other info inside Signatures[] = (SignerType + ECType + Hash_type) * keys count
            signatures_meta_sz = (1 + 1 + 1) * len(self._signer_keys)

            footer_size = tl_type_sz + signatures_only_sz + signatures_pub_keys_sz + signatures_meta_sz

            # Prepare header
            self._header = Header(
                whole_tl_size=Header.SIZE + len(self.body) + footer_size,
                version=self._tl_version,
                pub_keys_count=len(self._pub_keys_dict),
                signatures_count=len(self._signer_keys)
            )
        return self._header

    @property
    def body(self) -> Body:
        if self._body is None:
            keys = []
            for pub_key_id, key_data in self._pub_keys_dict.items():
                key_type_str = consts.VSKeyTypeS(key_data["type"])
                start_date = int(key_data["start_date"])
                expiration_date = int(key_data["expiration_date"])
                ec_type = int(key_data["ec_type"])
                key = PubKeyStructure(
                    start_date=start_date,
                    expiration_date=expiration_date,
                    key_type=consts.key_type_str_to_num_map[key_type_str],
                    ec_type=ec_type,
                    pub_key=b64_to_bytes(key_data["key"])
                )
                keys.append(key)
            self._body = Body(keys)
        return self._body

    @property
    def footer(self) -> Footer:
        if self._footer is None:
            # Get signatures
            signatures = []
            data_to_sign = to_b64(bytes(self.header) + bytes(self.body))

            for key in self._signer_keys:
                # Sign data
                signature = key.sign(data_to_sign, long_sign=False)

                # Add signature to signatures list
                signer_type_str = consts.VSKeyTypeS(key.key_type)
                s = Signature(
                    signer_type=consts.key_type_str_to_num_map[signer_type_str],
                    ec_type=key.ec_type,
                    hash_type=key.hash_type,
                    sign=b64_to_bytes(signature),
                    signer_pub_key=b64_to_bytes(key.public_key)
                )
                signatures.append(s)

            # Finalize footer
            self._footer = Footer(
                tl_type=self._tl_type,
                signatures=signatures
            )
        return self._footer
