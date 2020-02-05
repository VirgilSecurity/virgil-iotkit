#!/bin/bash

SCRIPT_FOLDER="$( cd "$( dirname "$0" )" && pwd )"

VM_NAME="sandbox_f29"
START_SCRIPT="/vagrant/run.sh vagrant"

trap ctrlc_int INT

ctrlc_int() {
    echo "####### Found CTRL + C... Exiting"
    halt_vm
    exit 1
}

print_info_header() {
  echo "###########################################"
  echo "$1"
  echo "###########################################"
}

run_vm() {
    print_info_header "Starting VM using Vagrant"
    vagrant up ${VM_NAME}
    local res=$?
    if [[ $res != 0 ]]; then
        print_info_header "Failed to start VM. Exiting..."
        exit $res
    fi
}

run_sandbox() {
    print_info_header "Running IoT Sandbox inside VM"
    vagrant ssh ${VM_NAME} -c "${START_SCRIPT}"
}

halt_vm() {
    print_info_header "Halting VM"
    vagrant halt ${VM_NAME}
}

pushd "${SCRIPT_FOLDER}"
    halt_vm
    run_vm
    run_sandbox
    halt_vm
popd
