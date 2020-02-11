import base64
import os
import re
import shutil


def b64_to_bytes(data):
    return base64.b64decode(data)


def to_b64(data):
    return base64.b64encode(bytes(data)).decode("utf-8")


def tiny_key_to_virgil(tiny_key):
    asn_1_prefix = bytearray(
        [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
            0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
            0x42, 0x00
        ]
    )

    key_data = asn_1_prefix + bytearray(base64.b64decode(tiny_key))

    return key_data


def clean_folder_content(path):
    if not os.path.exists(path):
        return
    for content in os.listdir(path):
        to_clean = os.path.join(path, content)
        if os.path.isdir(to_clean):
            shutil.rmtree(to_clean)
        else:
            os.remove(to_clean)


def find_files(path, pattern, regex=False):
    result = []
    for root, _, files in os.walk(path):
        for f_name in files:
            full_path = os.path.join(root, f_name)
            search_in = full_path.split(path)[-1]
            if regex:
                match = re.search(pattern, search_in)
            else:
                match = pattern in search_in
            if match:
                result.append(full_path)
    return result
