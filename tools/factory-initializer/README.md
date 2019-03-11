# virgil-demo-soraa-lamp-initializer
The application to create a signed content snapshot for a Virgil Card creation inside the Soraa Bulb

## Factory Install

0) Due to the changing nature of keys and scripts, it is important to isolate these archive
   deliveries from previous versions.  You may wish to expand this and sdmpd archive in its own directory
   so it can be completely wiped out upon next upgrade.  That will make step 1 below much easier.
1) Delete old versions of soraa-device-initializer, data/ scripts/ current-credentials/ soraa-production
2) Expand tar file.

## Credentials

The tools point to a symlink, current-credentials, which points to a directory of credentials.
In the factory, this should be soraa-production.

## Steps to provision

(PATH TO SCRIPT) (PATH TO BINARY)

*Example*
./scripts/initialize-release.sh ~/soraa-device-initializer

This script will work for all device types, and will provision every provisionable device on the network.

## Building 

### Raspberry Pi

As performed by Soraa_Common/archive-factory-tools.sh
```
# from the root of Soraa_Common
docker build -t raspbian-dev tools/docker/raspbian-dev/
docker run --rm -v ${PWD}:/src raspbian-dev /bin/bash -c "cd /src/tools/factory-initializer && ./archive.sh soraa-production;"
```
