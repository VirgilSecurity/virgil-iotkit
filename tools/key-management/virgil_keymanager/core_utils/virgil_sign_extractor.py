from binascii import unhexlify

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


class VirgilSignExtractor(object):

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
        width = val.bit_length()
        width += 8 - ((width % 8) or 8)
        fmt = '%%0%dx' % (width // 4)
        s = unhexlify(fmt % val)
        if endianness == 'little':
            s = s[::-1]
        return s