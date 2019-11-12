from datetime import datetime, timezone

from virgil_trust_provisioner.consts import TIME_OFFSET


def date_to_timestamp(year: int, month: int, day: int) -> int:
    """
    Get timestamp with offset (to be stored in uint32)
    """
    ts = datetime(year, month, day, tzinfo=timezone.utc).timestamp()
    return int(ts - TIME_OFFSET)


def ts_now() -> int:
    ts = datetime.now().timestamp()
    return int(ts - TIME_OFFSET)


def timestamp_to_date(ts: int) -> (int, int, int):
    timestamp = TIME_OFFSET + ts
    dt = datetime.utcfromtimestamp(timestamp)
    return dt.year, dt.month, dt.day
