from enum import IntEnum, Enum

from virgil_crypto import VirgilKeyPair
from virgil_crypto.hashes import HashAlgorithm


TIME_OFFSET = 1420070400  # 01/01/2015 @ 12:00am (UTC)
CARD_REGISTRATION_ENDPOINT = "/things/card/key"
CLOUD_KEY_INIT_ENDPOINT = "/things/init"
CLOUD_KEY_RECEIVE_ENDPOINT = "/things/cloudkey"


class TrustListType(IntEnum):
    RELEASE = 0
    BETA = 1
    ALPHA = 2
    DEV = 3


class VsEcTypeE(IntEnum):
    VS_KEYPAIR_EC_SECP192R1 = 1
    VS_KEYPAIR_EC_SECP224R1 = 2
    VS_KEYPAIR_EC_SECP256R1 = 3
    VS_KEYPAIR_EC_SECP384R1 = 4
    VS_KEYPAIR_EC_SECP521R1 = 5
    VS_KEYPAIR_EC_SECP192K1 = 6
    VS_KEYPAIR_EC_SECP224K1 = 7
    VS_KEYPAIR_EC_SECP256K1 = 8
    VS_KEYPAIR_EC_CURVE25519 = 9
    VS_KEYPAIR_EC_ED25519 = 10
    VS_KEYPAIR_RSA_2048 = 11


class VSKeyTypeE(IntEnum):
    RECOVERY = 0
    AUTH = 1
    TRUSTLIST = 2
    FIRMWARE = 3
    FACTORY = 4
    IOT_DEVICE = 5
    USER_DEVICE = 6
    FIRMWARE_INTERNAL = 7
    AUTH_INTERNAL = 8
    CLOUD = 9


class VSKeyTypeS(Enum):
    RECOVERY = "recovery"
    AUTH = "auth"
    TRUSTLIST = "tl"
    FIRMWARE = "firmware"
    FACTORY = "factory"
    IOT_DEVICE = "iot_device"
    USER_DEVICE = "user_device"
    FIRMWARE_INTERNAL = "firmware_internal"
    AUTH_INTERNAL = "auth_internal"
    CLOUD = "cloud"


hash_type_vs_to_secmodule_map = {
    HashAlgorithm.SHA256: 0,
    HashAlgorithm.SHA384: 1,
    HashAlgorithm.SHA512: 2
}

ec_type_vs_to_secmodule_map = {
    VirgilKeyPair.Type_RSA_2048:        VsEcTypeE.VS_KEYPAIR_RSA_2048,
    VirgilKeyPair.Type_EC_SECP192R1:    VsEcTypeE.VS_KEYPAIR_EC_SECP192R1,
    VirgilKeyPair.Type_EC_SECP192K1:    VsEcTypeE.VS_KEYPAIR_EC_SECP192K1,
    VirgilKeyPair.Type_EC_SECP224R1:    VsEcTypeE.VS_KEYPAIR_EC_SECP224R1,
    VirgilKeyPair.Type_EC_SECP224K1:    VsEcTypeE.VS_KEYPAIR_EC_SECP224K1,
    VirgilKeyPair.Type_EC_SECP256R1:    VsEcTypeE.VS_KEYPAIR_EC_SECP256R1,
    VirgilKeyPair.Type_EC_SECP256K1:    VsEcTypeE.VS_KEYPAIR_EC_SECP256K1,
    VirgilKeyPair.Type_EC_SECP384R1:    VsEcTypeE.VS_KEYPAIR_EC_SECP384R1,
    VirgilKeyPair.Type_EC_SECP521R1:    VsEcTypeE.VS_KEYPAIR_EC_SECP521R1,
    VirgilKeyPair.Type_FAST_EC_ED25519: VsEcTypeE.VS_KEYPAIR_EC_ED25519
}

key_type_str_to_num_map = {
    VSKeyTypeS.RECOVERY:          VSKeyTypeE.RECOVERY,
    VSKeyTypeS.AUTH:              VSKeyTypeE.AUTH,
    VSKeyTypeS.TRUSTLIST:         VSKeyTypeE.TRUSTLIST,
    VSKeyTypeS.FIRMWARE:          VSKeyTypeE.FIRMWARE,
    VSKeyTypeS.FACTORY:           VSKeyTypeE.FACTORY,
    VSKeyTypeS.IOT_DEVICE:        VSKeyTypeE.IOT_DEVICE,
    VSKeyTypeS.USER_DEVICE:       VSKeyTypeE.USER_DEVICE,
    VSKeyTypeS.FIRMWARE_INTERNAL: VSKeyTypeE.FIRMWARE_INTERNAL,
    VSKeyTypeS.AUTH_INTERNAL:     VSKeyTypeE.AUTH_INTERNAL,
    VSKeyTypeS.CLOUD:             VSKeyTypeE.CLOUD
}

signature_sizes = {
    VirgilKeyPair.Type_RSA_2048: 256,
    VirgilKeyPair.Type_EC_SECP192R1: 48,
    VirgilKeyPair.Type_EC_SECP192K1: 48,
    VirgilKeyPair.Type_EC_SECP224R1: 56,
    VirgilKeyPair.Type_EC_SECP224K1: 56,
    VirgilKeyPair.Type_EC_SECP256R1: 64,
    VirgilKeyPair.Type_EC_SECP256K1: 64,
    VirgilKeyPair.Type_EC_SECP384R1: 96,
    VirgilKeyPair.Type_EC_SECP521R1: 132,
    VirgilKeyPair.Type_FAST_EC_ED25519: 64
}

pub_keys_sizes = {
    # VirgilKeyPair.Type_RSA_2048: 256,
    # VirgilKeyPair.Type_EC_SECP192R1: 49,
    # VirgilKeyPair.Type_EC_SECP192K1: 49,
    # VirgilKeyPair.Type_EC_SECP224R1: 57,
    # VirgilKeyPair.Type_EC_SECP224K1: 57,
    # VirgilKeyPair.Type_EC_SECP256R1: 65,
    # VirgilKeyPair.Type_EC_SECP256K1: 65,
    # VirgilKeyPair.Type_EC_SECP384R1: 97,
    # VirgilKeyPair.Type_EC_SECP521R1: 133,
    # VirgilKeyPair.Type_EC_CURVE25519: 32,
    # VirgilKeyPair.Type_FAST_EC_ED25519: 32
    # TODO: Use values above after converters implementation
    VirgilKeyPair.Type_EC_SECP256R1: 65
}
