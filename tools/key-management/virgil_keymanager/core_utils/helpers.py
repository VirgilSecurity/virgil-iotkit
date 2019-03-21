import base64


def b64_to_bytes(data):
    return base64.b64decode(data)


def to_b64(data):
    return base64.b64encode(bytes(data)).decode("utf-8")
