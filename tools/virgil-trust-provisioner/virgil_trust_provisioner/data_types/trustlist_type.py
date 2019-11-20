import io
from typing import List

from virgil_trust_provisioner import consts
from virgil_trust_provisioner.core_utils import virgil_time
from virgil_trust_provisioner.core_utils.helpers import b64_to_bytes, to_b64
from virgil_trust_provisioner.generators.keys.interface import KeyGeneratorInterface

TL_BYTE_ORDER = 'big'


class FileVersion:
    """
    type FileVersion struct {
        Major           uint8
        Minor           uint8
        Patch           uint8
        Build           uint32
        Timestamp       uint32
    }
    """
    SIZE = 1 + 1 + 1 + 4 + 4  # see structure in class doc-string

    def __init__(self, major: int, minor: int, patch: int, build: int, timestamp: int):
        self._major = major
        self._minor = minor
        self._patch = patch
        self._build = build
        self._timestamp = timestamp

        self.__bytes = None

    @classmethod
    def from_string(cls, ver: str):
        ts = virgil_time.ts_now()
        major, minor, patch, build = ver.split('.')
        major, minor, patch, build = int(major), int(minor), int(patch), int(build)
        return cls(major, minor, patch, build, ts)

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._major.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._minor.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._patch.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._build.to_bytes(4, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._timestamp.to_bytes(4, byteorder=TL_BYTE_ORDER, signed=False))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class Header:
    """
    type Header struct {
        WholeTLSize      uint32
        Version          FileVersion
        PubKeysCount     uint16
        SignaturesCount  uint8
    }
    """
    SIZE = 4 + FileVersion.SIZE + 2 + 1  # see structure in class doc-string

    def __init__(self, whole_tl_size: int, version: FileVersion, pub_keys_count: int, signatures_count: int):
        self._whole_tl_size = whole_tl_size
        self._version = version
        self._pub_keys_count = pub_keys_count
        self._signatures_count = signatures_count

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._whole_tl_size.to_bytes(4, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(bytes(self._version))
            byte_buffer.write(self._pub_keys_count.to_bytes(2, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._signatures_count.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return self.SIZE


class Signature:
    """
    type Signature struct {
        SignerType               uint8
        ECType                   uint8
        Hash_type                uint8
        SignAndSignerPublicKey   [SignSize+PublicKeySize]byte
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
            byte_buffer.write(self._signer_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._ec_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._hash_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
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
            byte_buffer.write(self.tl_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            for signature in self.signatures:
                byte_buffer.write(bytes(signature))
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return len(bytes(self))


class PubKeyStructure:
    """
    type PubKeyStructure struct {
        StartDate           uint32
        ExpirationDate      uint32
        KeyType             uint8
        ECType              uint8
        MetadataSize        uint16
        MetadataAndPubKey   [MetadataSize+PublicKeySize]byte
    }
    """
    def __init__(self,
                 start_date: int,
                 expiration_date: int,
                 key_type: int,
                 ec_type: int,
                 meta_data: bytearray,
                 pub_key: bytearray):
        self._start_date = start_date
        self._expiration_date = expiration_date
        self._key_type = key_type
        self._ec_type = ec_type
        self._meta_data_sz = len(meta_data)
        self._meta_data = meta_data
        self._pub_key = pub_key

        self.__bytes = None

    def __bytes__(self) -> bytes:
        if self.__bytes is None:
            byte_buffer = io.BytesIO()
            byte_buffer.write(self._start_date.to_bytes(4, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._expiration_date.to_bytes(4, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._key_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._ec_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._meta_data_sz.to_bytes(2, byteorder=TL_BYTE_ORDER, signed=False))
            byte_buffer.write(self._meta_data)
            byte_buffer.write(self._pub_key)
            self.__bytes = byte_buffer.getvalue()
        return self.__bytes

    def __len__(self):
        return 4 + 4 + 1 + 1 + 2 + self._meta_data_sz + len(self._pub_key)  # see structure in class doc-string


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
                 tl_version: str
                 ):
        self._pub_keys_dict = pub_keys_dict
        self._signer_keys = signer_keys
        self._tl_type = tl_type
        self._tl_version = FileVersion.from_string(tl_version)

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
            for _, key_data in self._pub_keys_dict.items():
                key_type_str = consts.VSKeyTypeS(key_data["type"])
                start_date = int(key_data["start_date"])
                expiration_date = int(key_data["expiration_date"])
                ec_type = int(key_data["ec_type"])
                meta_data = key_data["meta_data"]
                key = PubKeyStructure(
                    start_date=start_date,
                    expiration_date=expiration_date,
                    key_type=consts.key_type_str_to_num_map[key_type_str],
                    ec_type=consts.VsEcTypeE(ec_type),
                    meta_data=bytearray(meta_data, 'utf-8'),
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

            # Data to sign: header + body + tl_type from footer
            tl_type_bytes = self._tl_type.to_bytes(1, byteorder=TL_BYTE_ORDER, signed=False)
            data_to_sign = to_b64(bytes(self.header) + bytes(self.body) + tl_type_bytes)

            for key in self._signer_keys:
                # Sign data
                signature = key.sign(data_to_sign, long_sign=False)

                # Add signature to signatures list
                s = Signature(
                    signer_type=key.key_type_secmodule,
                    ec_type=key.ec_type_secmodule,
                    hash_type=key.hash_type_secmodule,
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
