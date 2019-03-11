#!/bin/bash

erase_command='{ "sdmp": {"header": {"dst": 65535, "src": 0, "address": "0.0.0.0", "encrypted": 0, "service": "DIAG", "message": "iGET", "flags": ["COMMAND", "BROADCAST"] }, "content": { "char_get": {"char": "ERAS"} } } }'
(echo "$erase_command"; sleep 20) | nc -U /tmp/sdmpd.sock
