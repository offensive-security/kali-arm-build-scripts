#!/bin/bash
apt-get update
apt-get install -y git-core gnupg flex bison gperf build-essential \
zip curl libncurses5-dev zlib1g-dev libncurses5-dev gcc-multilib g++-multilib \
parted kpartx debootstrap pixz qemu-user-static abootimg cgpt vboot-kernel-utils \
vboot-utils u-boot-tools bc lzma lzop automake autoconf m4 dosfstools rsync \
schedtool git dosfstools e2fsprogs device-tree-compiler libssl-dev qemu-user-static \
btrfs-tools 

apt-get install -y crossbuild-essential-armhf

MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    dpkg --add-architecture i386
    apt-get install -y libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386
else
    apt-get install -y libncurses5
fi
