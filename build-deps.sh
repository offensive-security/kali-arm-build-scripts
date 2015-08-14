#!/bin/bash
apt-get install -y git-core gnupg flex bison gperf libesd0-dev build-essential \
zip curl zlib1g-dev libncurses5-dev gcc-4.9 g++-4.9 \
parted kpartx debootstrap abootimg /
u-boot-tools bc automake autoconf m4 dosfstools pixz rsync \
schedtool git dosfstools e2fsprogs device-tree-compiler libssl-dev
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    dpkg --add-architecture i386
    apt-get update
    apt-get install -y ia32-libs
    # Required for kernel cross compiles
    apt-get install -y libncurses5:i386
else
    apt-get install -y libncurses5
fi
