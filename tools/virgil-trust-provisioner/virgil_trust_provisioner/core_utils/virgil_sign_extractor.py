import io

from pyasn1.codec.ber import decoder
from pyasn1.type import univ, namedtype


class HashedType(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('oid', univ.ObjectIdentifier()),
                                         namedtype.NamedType('null', univ.Null())
                                         )


class InnerSignatures(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('first_sign_part', univ.Integer()),
                                         namedtype.NamedType('second_sign_part', univ.Integer())
                                         )


class Signature(univ.Sequence):
    componentType = namedtype.NamedTypes(namedtype.NamedType('hashed', HashedType()),
                                         namedtype.NamedType('sign', univ.OctetString())
                                     )


class VirgilSignExtractor:

    @classmethod
    def extract_sign(cls, signature_data):
        """
        Extract signature bytes from virgil crypto pyasn1 structure
        Args:
            signature_data: signature bytes
        Returns:

        """
        asn_one_signature_no_compress = decoder.decode(
            signature_data,
            asn1Spec=Signature()
        )
        asn_one_signature_no_compress = decoder.decode(
            asn_one_signature_no_compress[0]['sign'],
            asn1Spec=InnerSignatures()
        )
        return cls.__long_to_bytes(int(asn_one_signature_no_compress[0]['first_sign_part'])) + \
            cls.__long_to_bytes(int(asn_one_signature_no_compress[0]['second_sign_part']))

    @classmethod
    def __long_to_bytes(cls, val, endianness='big'):
        byte_buffer = io.BytesIO()
        byte_buffer.write(int(val).to_bytes(32, byteorder=endianness, signed=False))
        return bytearray(byte_buffer.getvalue())
