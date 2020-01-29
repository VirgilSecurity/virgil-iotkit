import os
from optparse import OptionParser

TEMPLATE = """#!/bin/bash

#
#   PATH TO VIRGIL DEVICE INITIALIZER
#
INITIALIZER_APP="virgil-device-initializer"

#
#   Run Virgil Device Initializer
#
{INITIALIZER_CMD}

#
#   Check exit code
#
exit_code=$?
if [[ $exit_code != 0 ]]; then
    res="FAILED"
else
    res="SUCCESS"
fi

echo "============================================"
echo "${{res}}: Perform devices provision"
echo "============================================"
exit $exit_code"""


def _find_files(path, pattern):
    result = []
    for root, dirs, files in os.walk(path):
        for f_name in files:
            full_path = os.path.join(root, f_name)
            search_in = full_path.split(path)[-1]
            if pattern in search_in:
                result.append(full_path)
    return result


def _prepare_cmd(pp_pack_path, output_file, info_output_file):
    private = os.path.join(pp_pack_path, "private")
    pubkeys = os.path.join(pp_pack_path, "pubkeys")

    # Public keys
    auth_pub_key_1, auth_pub_key_2 = _find_files(pubkeys, "auth_")
    rec_pub_key_1, rec_pub_key_2 = _find_files(pubkeys, "recovery_")
    tl_pub_key_1, tl_pub_key_2 = _find_files(pubkeys, "tl_")
    fw_pub_key_1, fw_pub_key_2 = _find_files(pubkeys, "firmware_")

    # Private key
    factory_key, *_ = _find_files(private, "factory_")

    # Trust List
    trust_list, *_ = _find_files(provision_pack_path, "TrustList_")

    cmd = (
        '"${{INITIALIZER_APP}}" \\\n'
        '\t--output "{output_file}" \\\n'
        '\t--device_info_output "{info_output_file}" \\\n'
        '\t--auth_pub_key_1 "{auth_pub_key_1}" \\\n'
        '\t--auth_pub_key_2 "{auth_pub_key_2}" \\\n'
        '\t--rec_pub_key_1 "{rec_pub_key_1}" \\\n'
        '\t--rec_pub_key_2 "{rec_pub_key_2}" \\\n'
        '\t--tl_pub_key_1 "{tl_pub_key_1}" \\\n'
        '\t--tl_pub_key_2 "{tl_pub_key_2}" \\\n'
        '\t--fw_pub_key_1 "{fw_pub_key_1}" \\\n'
        '\t--fw_pub_key_2 "{fw_pub_key_2}" \\\n'
        '\t--trust_list "{trust_list}" \\\n'
        '\t--factory_key "{factory_key}"'
    ).format(**locals())

    return cmd


if __name__ == "__main__":
    # Parse arguments
    parser = OptionParser()
    parser.add_option("-o", "--output-folder",
                      dest="output_folder",
                      help="path to folder with utilities output")
    (options, args) = parser.parse_args()

    # Prepare paths
    output_folder = options.output_folder
    provision_pack_path = os.path.join(output_folder, "provision-pack")
    output_file = os.path.join(output_folder, "initializer-output.txt")
    info_output_file = os.path.join(output_folder, "initializer-info-output.txt")

    # Print script
    cmd = _prepare_cmd(provision_pack_path, output_file, info_output_file)
    print(TEMPLATE.format(INITIALIZER_CMD=cmd))
