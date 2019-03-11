#!/bin/bash

# Use as ./initialize-static-nmk.sh 195D1F7BDDCE778AC00759A7F89F7AC7

set_nmk_cmd='{ "sdmp": {"header": {"dst": 65535, "src": 0, "address": "0.0.0.0", "encrypted": 0, "service": "DIAG", "message": "iSET", "flags": ["COMMAND", "BROADCAST"]}, "content": { "char_set": {"char": "sNMK", "message_data": { "hex": "'"$1"'" } } } } }'

(echo "$set_nmk_cmd"; sleep 5) | nc -U /tmp/sdmpd.sock
