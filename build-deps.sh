#!/bin/bash
apt-get install -y git-core gnupg flex bison gperf libesd0-dev build-essential \
zip curl libncurses5-dev zlib1g-dev libncurses5-dev gcc-multilib g++-multilib \
parted kpartx debootstrap qemu-user-static abootimg cgpt vboot-kernel-utils \
vboot-utils uboot-mkimage bc lzma lzop build-essential automake autoconf m4 \
schedtool
dpkg --add-architecture i386
apt-get update
apt-get install -y ia32-libs
# Required for kernel cross compiles
apt-get install -y libncurses5:i386
