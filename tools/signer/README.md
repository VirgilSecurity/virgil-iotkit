Virgil Security util for signing soraa bulb firmware

## Requirments:
* Python 3.x - 3.5
* pip
* wheel

## Installation:
* pip install .

## Usage:
* virgilsign -h - for help

## Config:
* Default config path /etc/virgilsign/virgilsign.conf
* Config file content example:
[MAIN]
firmware_path = ./firmware/nxp_lamp_base.bin.orig
signed_firmware_path = ./firmware/nxp_lamp_base.bin
chunk_size = 512
root_private_key_path = ./firmware/keys/root-private.key
