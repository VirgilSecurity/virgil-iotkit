#!/bin/bash

IMAGE="virgilsecurity-docker-iotl-demo.bintray.io/testing/iot-sdk-demo:0.1.3.69"

if [ "${1}" = "vagrant" ]; then
    sleep 5s
    ifconfig -a
    SUBNET_BCAST=$(ifconfig eth1 | grep -Eo 'broadcast (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
    echo "SUBNET_BCAST = ${SUBNET_BCAST}"
    sleep 3s
    exec docker run -it --rm -p 8080:8080 -p 8081:8081 --net=host -e VS_BCAST_SUBNET_ADDR="${SUBNET_BCAST}" ${IMAGE}
else
    echo "SUBNET_BCAST = 255.255.255.255"
    exec docker run -it --rm -p 8080:8080 -p 8081:8081 --net=host ${IMAGE}
fi
