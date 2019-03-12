import json
from queue import Queue
from json import JSONDecodeError
import sys
from typing import Union, Optional, Tuple

from virgil_keymanager.core_utils.cmd_subprocess import CmdSubProcess


class AtmelDonglesController(object):
    """
    Controller for work with atmel dongles utility
    """

    def __init__(
            self,
            util_path,  # type: str
            emulator_mode=None,  # type: str
            logger=None
    ):
        # type: (...) -> None
        self.__util_path = util_path
        self.__emul_mode = emulator_mode
        self.__logger = logger

    def __use_cmd(self, cmd_line):
        # type: (str) -> Union[list, dict]
        """
        Utility function for running outer cmd utils.
        Args:
            cmd_line: command line for run in terminal

        Returns:
            External utility output, handled for predefined dict or list of errors.
        """

        def check_error(dict_check, err_list):
            for key in dict_check.keys():
                if isinstance(dict_check[key], dict):
                    check_error(dict_check[key], err_list)
                if key == "status":
                    if dict_check["status"].upper() == "ERROR" and "msg" in dict_check.keys():
                        err_list.append(dict_check["msg"])
            return err_list

        output_pipe = Queue()
        cmd = CmdSubProcess(cmd_line, output_pipe=output_pipe)
        cmd.run()
        output_list = []
        if output_pipe.empty():
            sys.exit("[ERROR]: dongle utility output is empty")
        while not output_pipe.empty():
            output_list.append(output_pipe.get())
        try:
            if output_list[0] == '':
                output_line = ""
                output_list.remove('')
                for line in output_list:
                    output_line += line
                output_dict = json.loads(output_line)
                if output_dict["status"].upper() == "ERROR":
                    error_list = []
                    check_error(output_dict, error_list)
                    return error_list
                return output_dict
            else:
                raise ValueError
        except JSONDecodeError and ValueError:
            try:
                json_start = output_list.index("{")
            except ValueError:
                return output_list
            error_list = output_list[:json_start]
            output_line = ""
            for line in output_list[json_start:]:
                output_line += line
            output_dict = json.loads(output_line)
            if output_dict["status"].upper() == "ERROR":
                check_error(output_dict, error_list)
            return error_list

    def generate_private_key(self, signature_limit=None, device_serial=None):
        # type: (Optional[int], Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Generate private key on Atmel device
        Args:
            signature_limit: Optional, signature limit number.
            device_serial: Optional, Atmel device serial number.
        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if signature_limit:
            if device_serial:
                cmd_line = "{util_path} -i -d {device_serial} --sl {signature_limit} --cl".format(
                    util_path=self.__util_path,
                    device_serial=device_serial,
                    signature_limit=signature_limit
                )
            else:
                cmd_line = "{util_path} -i --sl {signature_limit} --cl".format(
                    util_path=self.__util_path,
                    signature_limit=signature_limit
                )
        else:
            if device_serial:
                cmd_line = "{util_path} -d {device_serial} -i".format(
                    util_path=self.__util_path,
                    device_serial=device_serial
                )
            else:
                cmd_line = "{util_path} -i".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def set_private_key(self, private_key, signature_limit=None, device_serial=None):
        # type: (str, Optional[Union[str, int]], Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Set pre-generated private key to atmel device.
        Args:
            private_key: base64 representation of private key
            signature_limit: Optional, signature limit number.
            device_serial: Optional, Atmel device serial number.
        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if signature_limit:
            if device_serial:
                cmd_line = "{util_path} -d {device_serial} -i {private_key} --sl {signature_limit} --cl".format(
                    util_path=self.__util_path,
                    device_serial=device_serial,
                    signature_limit=signature_limit,
                    private_key=private_key
                )
            else:
                cmd_line = "{util_path} -i {private_key} --sl {signature_limit} --cl".format(
                    util_path=self.__util_path,
                    signature_limit=signature_limit,
                    private_key=private_key
                )
        else:
            if device_serial:
                cmd_line = "{util_path} -d {device_serial} -i {private_key} --cl".format(
                    util_path=self.__util_path,
                    device_serial=device_serial,
                    private_key=private_key
                )
            else:
                cmd_line = "{util_path} -i {private_key} --cl".format(
                    util_path=self.__util_path,
                    private_key=private_key
                )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def get_key_type(self, device_serial=None):
        # type: (Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Get type of key wrote to atmel device.
        Args:
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation.
            If False second item is string of errors.
            In success string contains key type.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -t".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} -t".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["type"]

    def set_key_type(self, key_type, device_serial=None):
        # type: (str, Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Sets string of key type string to atmel device
        Args:
            key_type: Key type name.
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -t {key_type}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                key_type=key_type
            )
        else:
            cmd_line = "{util_path} -t {key_type}".format(
                util_path=self.__util_path,
                key_type=key_type
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def get_public_key(self, device_serial=None):
        # type: (Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Get public part of key stored on atmel device.
        Args:
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is base64 string representation of public key.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -p".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} -p".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["public_key"]["key"]

    def set_signature(self, signature_path, device_serial=None):
        # type: (str, Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Setup signature for key stored at atmel device.
        Args:
            signature_path: Path to signature file.
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -s {signature_path}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                signature_path=signature_path
            )
        else:
            cmd_line = "{util_path} -s {signature_path}".format(
                util_path=self.__util_path,
                signature_path=signature_path
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def get_signature(self, device_serial=None):
        # type: (Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Get signature of key stored at atmel device.
        Args:
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is signature representation.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -s".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} -s".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["signature"]

    def get_random_number(self, device_serial=None):
        # type: (Optional[Union[int, str]]) -> Tuple(bool, Union[str, int])
        """
        Get random number stored in atmel device.
        Args:
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is random number stored in atmel device.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -r".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} -r".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["random_num"]

    def set_random_number(self, random_number, device_serial=None):
        # type: (str, Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Store random number to atmel device.
        Args:
            random_number: Random number for store in atmel device
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -r {random_number}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                random_number=random_number
            )
        else:
            cmd_line = "{util_path} -r {random_number}".format(
                util_path=self.__util_path,
                random_number=random_number
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def list_devices(self):
        # type: () -> Tuple(bool, Union[str, list])
        """
        List plugged atmel devices.
        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is a list of devices serials.
        """
        cmd_line = "{util_path} -l".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return True, list()
        if cmd_output and type(cmd_output) is dict:
            return True, list(cmd_output["devices"].values())

    def info(self, device_serial=None):
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --info".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} --info".format(
                util_path=self.__util_path
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["info"]

    def set_recovery_pub_key(self, key_path, key_num, device_serial=None):  # type1, type2
        # type: (str, int, Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Set RecoveryKeys public part for authorize of properly this atmel devices.
        Args:
            key_path: Path to Recovery key public part
            key_num: Number of one of Recovery key, must be 1 or 2
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --key{key_num} {key_path}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                key_num=key_num,
                key_path=key_path
            )
        else:
            cmd_line = "{util_path} --key{key_num} {key_path}".format(
                util_path=self.__util_path,
                key_num=key_num,
                key_path=key_path
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def get_recovery_pub_key(self, key_num, device_serial=None):
        # type: (Union[str, int], Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Get from atmel device, Recovery public key, for authority this device.
        Args:
            key_num: Number of one of Recovery key, must be 1 or 2
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is a recovery public key
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --key{key_num}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                key_num=key_num
            )
        else:
            cmd_line = "{util_path} --key{key_num}".format(
                util_path=self.__util_path,
                key_num=key_num
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["public_key_{}".format(key_num)]

    def lock_data(self, device_serial=None):
        # type: (Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Lock data field in atmel device.
        WARNING! It irreversible operation. Make only after all changes.
        Args:
            device_serial: Serial of plugged atmel device.
        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --dl".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} --dl".format(util_path=self.__util_path)
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        return True, device_serial

    def sign_by_device(self, data, long_sign=False, device_serial=None):
        # type: (str, bool, Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Sing data by atmel device.
        Args:
            long_sign:
            data: base64 representation of data for sign
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is a sing.
        """
        if long_sign:
            sign_type = "vsign"
        else:
            sign_type = "sign"

        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --{sign} {data}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                sign=sign_type,
                data=data
            )
        else:
            cmd_line = "{util_path} --{sign} {data}".format(
                util_path=self.__util_path,
                sign=sign_type,
                data=data
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            if long_sign:
                return True, cmd_output["vsignature"]["vsign"]
            else:
                return True, cmd_output["signature"]["sign"]

    def verify_by_device(self, data, sign, signer_pub_key, long_sign=False, device_serial=None):
        # type: (str, str, str, bool, Union[int, str]) -> Tuple(bool, bool)
        """
        Verify signed data by atmel device
        Args:
            data: Original data in base64.
            sign: Signature in base64.
            signer_pub_key: Signer public key in base64.
            long_sign:  Vigil signature usage.
            device_serial: Device serial number, points which device need use

        Returns:

        """
        if long_sign:
            verify_type = "vverify"
            sign_type = "vverify_sign"
            signer_key_type = "vverify_key"
        else:
            verify_type = "verify"
            sign_type = "verify_sign"
            signer_key_type = "verify_key"

        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --{verify} {data} --{sign} {sign_data} --{signer_key} {signer_pub_key}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                verify=verify_type,
                data=data,
                sign=sign_type,
                sign_data=sign,
                signer_key=signer_key_type,
                signer_pub_key=signer_pub_key
            )
        else:
            cmd_line = "{util_path} --{verify} {data} --{sign} {sign_data} --{signer_key} {signer_pub_key}".format(
                util_path=self.__util_path,
                verify=verify_type,
                data=data,
                sign=sign_type,
                sign_data=sign,
                signer_key=signer_key_type,
                signer_pub_key=signer_pub_key
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            if long_sign:
                return True, True if cmd_output["vverify"]["vverify"] == "ok" else False
            else:
                return True, True if cmd_output["verify"]["verify"] == "ok" else False

    def crypt_by_device(self, data, pub_key, device_serial=None):
        # type: (str, str, Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Crypt data by atmel device.
        Args:
            data: base64 data representation string
            pub_key: Recipient public key 64 bytes in base64 encode.
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is base64 string representaiotn of encrypted data.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --crypt {data} --key {pub_key}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                data=data,
                pub_key=pub_key
            )
        else:
            cmd_line = "{util_path} --crypt {data}".format(
                util_path=self.__util_path,
                data=data
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["crypto"]["crypt"]

    def decrypt_by_device(self, encrypted_data, device_serial=None):
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --decrypt {encrypted_data}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                encrypted_data=encrypted_data,
            )
        else:
            cmd_line = "{util_path} --decrypt {encrypted_data}".format(
                util_path=self.__util_path,
                encrypted_data=encrypted_data
            )
        if self.__emul_mode:
            cmd_line += " --mode {}".format(self.__emul_mode)
        cmd_output = self.__use_cmd(cmd_line)
        if self.__logger:
            self.__logger.debug(cmd_line)
            self.__logger.debug("Dongle utility output: ")
            self.__logger.debug(cmd_output)
        if cmd_output and type(cmd_output) is list:
            return False, "Dongle utility exits with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["decrypt"]["decrypt"]
