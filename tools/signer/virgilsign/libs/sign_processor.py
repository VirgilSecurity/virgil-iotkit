import base64
import io
import os
import sys

import struct

from binascii import unhexlify
from pyasn1.codec.ber import decoder
from pyasn1.type import univ, namedtype


class SignProcessor:
    """
    Handling firmware sign operations
    """
    KEY_TYPES = {'auth': 4, 'firmware': 1}

    def __init__(self, firmware_path, prog_firmware_path, 
        update_firmware_path, prog_file_size, firmware_version, 
        manufacturer, model, chunkSize, applicationType, buildtime):
        self.firmware_path = firmware_path
        self.prog_firmware_path = prog_firmware_path
        self.prog_file_size = int(prog_file_size)
        self.update_firmware_path = update_firmware_path
        self.buildtime = buildtime
        self.firmware_version = [int(element) for element in firmware_version]
        self.firmware_bytes = bytearray(self.__load_file_bytes(self.firmware_path))
        self.version_size = 21

        self.manufacturer = bytes(manufacturer[:4],'ascii')
        self.model = bytes(model[:4],'ascii')
        self.chunkSize = int(chunkSize)
        self.applicationType = bytes(applicationType[:4],'ascii')

        self.private_keys = []
        self.signatures_size = 0


    def __load_file_bytes(self, file_name):
        # Load bytes of firmware file
        if os.path.exists(file_name):
            return bytearray(open(file_name, 'rb').read())
        else:
            raise IOError('[FATAL]: Cannot find file: {}'.format(file_name))



    def create_firmware(self):
        self.create_prog_file()
        self.create_update_file()



    def create_prog_file(self):
        # Get raw Data bytes
        firmware_bytes_without_sign = self.firmware_bytes

        # append FF-filler
        filler_size = self.prog_file_size - len(firmware_bytes_without_sign) - self.version_size - self.signatures_size

        filler = bytearray([255] * filler_size)
        prog_body = firmware_bytes_without_sign + filler

        # append applicationType and version
        prog_body += self.applicationType
        prog_body += bytearray(self.firmware_version)
        bt_bytes = self.buildtime.encode()
        prog_body += bytearray(bt_bytes)

        # create signatures with meta: key type and key id
        signatures = self.signatures(prog_body)

        # append signatures
        prog_body += signatures
        try:
            open(self.prog_firmware_path, 'wb').write(prog_body)
        except Exception as error:
            raise IOError('[FATAL]: Cannot write Prog firmware file at {} with error: {}'.format(
                          self.prog_firmware_path, error))


    def create_update_file(self):
        byte_buffer = io.BytesIO()

        # Get raw Data bytes
        firmware_bytes_without_sign = self.firmware_bytes

        # Fill header
        header_size = 56
        byte_buffer.write(int(header_size).to_bytes(4, byteorder='big', signed=False))

        code_len = len(firmware_bytes_without_sign)
        byte_buffer.write(int(code_len).to_bytes(4, byteorder='big', signed=False))

        footer_offset = header_size + code_len
        byte_buffer.write(int(footer_offset).to_bytes(4, byteorder='big', signed=False))

        footer_length = self.version_size + self.signatures_size
        byte_buffer.write(int(footer_length).to_bytes(4, byteorder='big', signed=False))

        manufacturer = self.manufacturer
        byte_buffer.write(manufacturer)

        model = self.model
        byte_buffer.write(model)

        applicationType = self.applicationType
        byte_buffer.write(applicationType)
        
        byte_buffer.write(bytearray(self.firmware_version))
        bt_bytes = self.buildtime.encode()
        byte_buffer.write(bytearray(bt_bytes))

        padByte = 0x00
        byte_buffer.write(int(padByte).to_bytes(1, byteorder='big', signed=False))

        chunkSize = self.chunkSize
        byte_buffer.write(int(chunkSize).to_bytes(2, byteorder='big', signed=False))

        byte_buffer.write(len(firmware_bytes_without_sign).to_bytes(4, byteorder='big', signed=False))

        app_size = self.prog_file_size
        byte_buffer.write(int(app_size).to_bytes(4, byteorder='big', signed=False))

        # Fill code
        byte_buffer.write(self.firmware_bytes)

        # Fill footer
        prog_file_data = bytearray(self.__load_file_bytes(self.prog_firmware_path))
        re = len(prog_file_data)
        rb = re - footer_length
        footer_data = prog_file_data[rb:re]
        byte_buffer.write(footer_data)

        update_body = bytearray(byte_buffer.getvalue())

        try:
            open(self.update_firmware_path, 'wb').write(update_body)
        except Exception as error:
            raise IOError('[FATAL]: Cannot write Update firmware file at {} with error: {}'.format(
                          self.update_firmware_path, error))




    def signatures(self, firmware):

        signed_firmware = bytearray(firmware)
        signatures = bytearray()
        for private_key in self.private_keys:

            # Create signature for data and fast signature using current private key
            full_signature = self.get_full_signature(private_key['data'], firmware)
        
            byte_buffer = io.BytesIO()
            byte_buffer.write(int(private_key['id']).to_bytes(2, byteorder='little', signed=False))
            key_id_bytes = bytearray(byte_buffer.getvalue())

            # Appends 1 byte for key type, 2 bytes for key id and 64 bytes for signature
            signature_with_meta = bytearray([private_key['type']]) +\
            key_id_bytes +\
            bytearray(full_signature)
            signatures = signatures + signature_with_meta

        return signatures


    def get_full_signature(self, private_key_data, firmware):
        raise Exception("Full signature method isn't implemented")
            
            
    



