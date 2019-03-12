from enum import Enum


class DongleType(Enum):
    RECOVERY = "recovery"
    AUTH = "auth"
    AUTH_INTERNAL = "auth_internal"
    TL = "tl_service"
    FIRMWARE = "firmware"
    FIRMWARE_INTERNAL = "firmware_internal"
    FACTORY = "factory"
    CLOUD = "cloud"
