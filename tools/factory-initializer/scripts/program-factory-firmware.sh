#!/bin/bash

program_factory='factory-firmware '${1}
(echo "$program_factory"; sleep 60) | nc -U /tmp/sdmpd.sock
