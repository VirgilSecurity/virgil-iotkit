import argparse
import os
import sys

from virgilsign.libs.config_loader import ConfigLoader
from virgilsign.libs.virgil_sign_processor import VirgilSignProcessor
from virgilsign.libs.atmel.atmel_sign_processor import AtmelSignProcessor


class MainHandler:
    """
    Handle all types of preparation and common functional
    """
    def __init__(self):
        # Get args and configs
        self.args = self.__get_cli_args()
        self.config = self.__load_configs()


        # Setup main variables from config file
        if self.args['mode'] == 'virgil':
            self.private_keys_paths = [self.__fix_path(i) for i in self.config['MAIN']['private_keys_paths'].split('\n')]
        else:
            self.atmel_util_path = self.__fix_path(self.config['HSM']['atmel_util_path'])

                        
        # Set input file
        self.firmware_path = self.args['input']

        # Set buildtimestamp
        self.buildtime = self.args['buildtime']
        
        firmware_path_without_ext = '.'.join(self.firmware_path.split(".")[:-1])

        self.prog_firmware_path = firmware_path_without_ext + "_Prog.bin"

        # output file size in bytes
        self.prog_file_size = self.args['filesize']

        self.manufacturer = self.args['manufacturer']
        self.model = self.args['model']
        self.chunkSize = self.args['chunkSize']
        self.applicationType = self.args['applicationType']

        self.firmware_version = self.args['version'].split(".")

        self.update_firmware_path = firmware_path_without_ext + "_Update.bin"
        # Check existence of main components
        self.__components_check()

        if self.args['mode'] == 'virgil':
            self.sign_maker = VirgilSignProcessor(self.private_keys_paths, 
                                            self.firmware_path,
                                            self.prog_firmware_path, 
                                            self.update_firmware_path, 
                                            self.prog_file_size, 
                                            self.firmware_version,
                                            self.manufacturer,
                                            self.model,
                                            self.chunkSize,
                                            self.applicationType,
                                            self.buildtime)
        else:
            self.sign_maker = AtmelSignProcessor(
                                self.atmel_util_path, 
                                self.firmware_path,
                                self.prog_firmware_path, 
                                self.update_firmware_path, 
                                self.prog_file_size, 
                                self.firmware_version,
								self.manufacturer,
								self.model,
								self.chunkSize,
								self.applicationType,
								self.buildtime)

    @staticmethod
    def __get_cli_args():
        args = argparse.ArgumentParser(prog='virgilsign', description='Virgil Security util for signing'
                                                                      'soraa bulb firmware',
                                       formatter_class=argparse.RawTextHelpFormatter)
        args.add_argument('-c', '--config', type=str, help='Use config file from custom path')
        args.add_argument('-i', '--input', type=str, help='Input file')
        args.add_argument('-b', '--buildtime', type=str, help='Build time')
        args.add_argument('-s', '--filesize', type=str, help='Output _Prog.bin file size in bytes')
        args.add_argument('-v', '--version', type=str, help='Firmware version')
        args.add_argument('-a', '--manufacturer', type=str, help='Manufacturer')
        args.add_argument('-d', '--model', type=str, help='Model')
        args.add_argument('-k', '--chunkSize', type=str, help='chunkSize')
        args.add_argument('-t', '--applicationType', type=str, help='Application Type')
        args.add_argument('-m', '--mode', choices=['hsm', 'virgil'],
                          help='hsm - Use hardware security module to generate signs\n'
                               'virgil - Use virgil crypto to generate signs', default='virgil')


        return vars(args.parse_args())

    def __fix_path(self, path):
        if path[0] == '.':
            return os.path.join(os.path.dirname(self.config_path), path)
        else:
            return path

    def __load_configs(self):
        # Try load config from argument variable, if arg not set try from default path
        try:
            if self.args['config']:
                self.config_path = os.path.abspath(self.args['config'])
            else:
                if sys.platform == "win32":
                    self.config_path = os.path.join(os.environ(os.getenv('LOCALAPPDATA'), "virgilsign\\virgilsign.conf"))
                else:
                    self.config_path = "/etc/virgilsign/virgilsign.conf"

            config = ConfigLoader(self.config_path).get_config()

            if config:
                return config
            else:
                sys.exit("[FATAL]: Config files is empty! please setup config at {}".format(config_path))
        except Exception as error:
            sys.exit(error)

    def __components_check(self):
        # Check existence of main components described in config file
        if not os.path.exists(self.firmware_path):
            sys.exit('[FATAL]: Cannot find key file at {}'.format(self.firmware_path))

        if self.args['mode'] == 'virgil':
            for private_key_path in self.private_keys_paths:    
                if not os.path.exists(private_key_path):
                    sys.exit('[FATAL]: Cannot find key file at {}'.format(private_key_path))
        else:
            if not os.path.exists(self.atmel_util_path):
                sys.exit('[FATAL]: Atmel util doesn\'t exist' + self.atmel_util_path)              

    def run(self):
        try:
            self.sign_maker.create_firmware()
        except Exception as error:
            sys.exit(error)

