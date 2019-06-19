from enum import IntEnum, Enum

from virgil_crypto import VirgilKeyPair

TIME_OFFSET = 1420070400  # 01/01/2015 @ 12:00am (UTC)


class TrustListType(IntEnum):
    RELEASE = 0
    BETA = 1
    ALPHA = 2
    DEV = 3


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


class VSKeyTypeS(Enum):
    RECOVERY = "recovery"
    AUTH = "auth"
    TRUSTLIST = "tl_service"
    FIRMWARE = "firmware"
    FACTORY = "factory"
    IOT_DEVICE = "iot_device"
    USER_DEVICE = "user_device"
    FIRMWARE_INTERNAL = "firmware_internal"
    AUTH_INTERNAL = "auth_internal"


key_type_str_to_num_map = {
    VSKeyTypeS.RECOVERY:          VSKeyTypeE.RECOVERY,
    VSKeyTypeS.AUTH:              VSKeyTypeE.AUTH,
    VSKeyTypeS.TRUSTLIST:         VSKeyTypeE.TRUSTLIST,
    VSKeyTypeS.FIRMWARE:          VSKeyTypeE.FIRMWARE,
    VSKeyTypeS.FACTORY:           VSKeyTypeE.FACTORY,
    VSKeyTypeS.IOT_DEVICE:        VSKeyTypeE.IOT_DEVICE,
    VSKeyTypeS.USER_DEVICE:       VSKeyTypeE.USER_DEVICE,
    VSKeyTypeS.FIRMWARE_INTERNAL: VSKeyTypeE.FIRMWARE_INTERNAL,
    VSKeyTypeS.AUTH_INTERNAL:     VSKeyTypeE.AUTH_INTERNAL
}

# TODO: find sizes in crypto?
signature_sizes = {
    VirgilKeyPair.Type_EC_SECP256R1: 64
}

pub_keys_sizes = {
    VirgilKeyPair.Type_EC_SECP256R1: 64
}
