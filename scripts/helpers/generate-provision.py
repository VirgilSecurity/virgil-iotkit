import os
import sys
from pathlib import Path
from optparse import OptionParser
from shutil import rmtree
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))

from tools import trust_provisioner as tp
from utils.processes import CmdSubProcess


if __name__ == "__main__":
    # Parse arguments
    parser = OptionParser()
    parser.add_option("-t", "--virgil-app-token",
                      dest="virgil_app_token",
                      help="Virgil Application token")
    parser.add_option("-u", "--iot-api-url",
                      dest="iot_api_url",
                      help="Virgil IoT api URL")
    parser.add_option("-o", "--output-folder",
                      dest="output_folder",
                      help="path to folder to store utilities output")
    (options, args) = parser.parse_args()

    # Prepare paths
    output_folder = options.output_folder
    tp_cfg = os.path.join(output_folder, "trust-provisioner.conf")
    provision_pack_folder = os.path.join(output_folder, "provision-pack")
    factory_info_json = os.path.join(output_folder, "factory-info.json")

    # Cleanup previous provision package and utilities output
    if os.path.exists(output_folder):
        rmtree(output_folder)
    os.makedirs(output_folder)

    # Create config for Trust Provisioner
    tp.create_config(config_path=tp_cfg,
                     storage_path=output_folder,
                     log_path=output_folder,
                     provision_pack_path=provision_pack_folder,
                     iot_api_url=options.iot_api_url)

    # Create sample json with factory info
    tp.create_factory_info_json(factory_info_json)

    # Prepare Trust Provisioner process
    cmd = "virgil-trust-provisioner -c {0} -t {1} -i {2} -y".format(tp_cfg,
                                                                    options.virgil_app_token,
                                                                    factory_info_json)
    process = CmdSubProcess(cmd, print_output=True)
    process.run_in_thread()

    # Generate provision
    try:
        p = tp.TrustProvisioner(process)
        p.generate_upper_level_keys()
        p.generate_release_trust_list()
        p.export_provision_package()
        p.exit()
    finally:
        process.kill()
