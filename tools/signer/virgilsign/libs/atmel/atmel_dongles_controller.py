import json
from queue import Queue
from json import JSONDecodeError
import sys
import os
import tempfile
from typing import Union, Optional, Tuple

from .cmd_subprocess import CmdSubProcess


class AtmelDonglesController(object):
    """
    Controller for work with atmel dongles utility
    """

    def __init__(
            self,
            util_path  # type: str
    ):
        # type: (...) -> AtmelDonglesController
        self.__util_path = util_path

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
            sys.exit("[ERROR]: utility doesnt response any output")
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



    def get_key_type(self, device_serial=None):
        # type: (Optional[Union[int, str]]) -> Tuple(bool, str)
        """
        Get type of soraa key wrote to atmel device.
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
        cmd_output = self.__use_cmd(cmd_line)
        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["type"]

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
        cmd_output = self.__use_cmd(cmd_line)
        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["public_key"]["key"]

    def get_key_type(self, device_serial=None):
        # type: (Optional[Union[str, int]]) -> Tuple(bool, str)
        """
        Get type of key stored on atmel device.
        Args:
            device_serial: Serial of plugged atmel device.

        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is string representation of key type.
        """
        if device_serial:
            cmd_line = "{util_path} -d {device_serial} -t".format(
                util_path=self.__util_path,
                device_serial=device_serial
            )
        else:
            cmd_line = "{util_path} -t".format(util_path=self.__util_path)
        cmd_output = self.__use_cmd(cmd_line)
        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["type"]

            
    def list_devices(self):
        # type: () -> Tuple(bool, Union[str, list])
        """
        List plugged atmel devices.
        Returns:
            Status of operation in tuple representation, if False second item is string of errors.
            In success second item is a list of devices serials.
        """
        cmd_line = "{util_path} -l".format(util_path=self.__util_path)
        cmd_output = self.__use_cmd(cmd_line)
        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["devices"].values()

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
        cmd_output = self.__use_cmd(cmd_line)
        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            return True, cmd_output["info"]



    def sign_by_device(self, data, long_sign=False, device_serial=None):
        # type: (str, Optional[Union[str, int]]) -> Tuple(bool, str)
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
            sign_type = "fvsign"
        else:
            sign_type = "fsign"

        temp = tempfile.NamedTemporaryFile(mode='w+', encoding='utf-8', delete=False)
        temp.write(data)
        file_name = temp.name
        temp.close()

        if device_serial:
            cmd_line = "{util_path} -d {device_serial} --{sign} {data}".format(
                util_path=self.__util_path,
                device_serial=device_serial,
                sign=sign_type,
                data=file_name
            )
        else:
            cmd_line = "{util_path} --{sign} {data}".format(
                util_path=self.__util_path,
                sign=sign_type,
                data=file_name
            )

        cmd_output = self.__use_cmd(cmd_line)

        os.remove(file_name)

        if cmd_output and type(cmd_output) is list:
            return False, "Atmel utility exit with error(s): {}".format(", ".join(cmd_output))
        if cmd_output and type(cmd_output) is dict:
            if long_sign:
                return True, cmd_output["vsignature"]["vsign"]
            else:
                return True, cmd_output["signature"]["sign"]


