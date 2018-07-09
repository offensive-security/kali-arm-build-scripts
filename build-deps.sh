#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

while fuser /var/lib/dpkg/lock >/dev/null ; do
    sleep 5
done

apt-get update

# We can get a race when building 2 images around the same time.
while fuser /var/lib/dpkg/lock >/dev/null ; do
    sleep 5
done

apt-get install -y git-core gnupg flex bison gperf build-essential \
zip curl libncurses5-dev zlib1g-dev libncurses5-dev kali-archive-keyring \
parted kpartx debootstrap pixz qemu-user-static abootimg cgpt vboot-kernel-utils \
vboot-utils u-boot-tools bc lzma lzop automake autoconf m4 dosfstools rsync \
schedtool git dosfstools e2fsprogs device-tree-compiler libssl-dev qemu-user-static \
crossbuild-essential-armhf crossbuild-essential-armel crossbuild-essential-arm64 \
systemd-container libgmp3-dev gawk qpdf bison flex make git


echo "Waiting for other software manager to finish..."
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
    while fuser /var/lib/dpkg/lock >/dev/null ; do
        sleep 5
    done
    dpkg --add-architecture i386
    # apt-get update to make sure we have a list of the i386 packages
    apt-get update
    while fuser /var/lib/dpkg/lock >/dev/null ; do
        sleep 5
    done
    apt-get install -y libstdc++6:i386 libgcc1:i386 zlib1g:i386 libncurses5:i386
else
    while fuser /var/lib/dpkg/lock >/dev/null ; do
        sleep 5
    done
    apt-get install -y libncurses5
fi
