#!/bin/bash

IMAGE="virgilsecurity-docker-iotl-demo.bintray.io/testing/iot-sdk-demo:0.1.4.13"

#
#   Ask for Application token
#
read -p 'Please enter Virgil Application Token: ' APP_TOKEN

#
#   Start Sandbox
#
if [ "${1}" = "vagrant" ]; then
    sleep 5s
    ifconfig -a
    SUBNET_BCAST=$(ifconfig eth1 | grep -Eo 'broadcast (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
    echo "SUBNET_BCAST = ${SUBNET_BCAST}"
    EXTRA_OPTIONS="-e VS_BCAST_SUBNET_ADDR=${SUBNET_BCAST}"
else
    echo "SUBNET_BCAST = 255.255.255.255"
fi

exec docker run -it --rm \
    -e LOCAL_MODE=true \
    -e APP_TOKEN=${APP_TOKEN} \
    -p 8000:8000 \
    -p 8080:8080 \
    -p 8081:8081 \
    ${EXTRA_OPTIONS} \
    --net=host ${IMAGE}
