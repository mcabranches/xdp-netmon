# xdp-netmon

## Installation

    git submodule init
    git submodule update

    sudo apt-get install build-essential clang gcc-multilib libelf-dev llvm

## Compilation

    make

## Directory description

* src/bpf -> kernel space code.
* src/user -> user space code. Main controller and app specific controllers.

Code in the main branch implement the system with SmartNIC offloads.

If a Netronome SmartNIC is not available, please use the code located on the branch: "no\_offload\_code".
