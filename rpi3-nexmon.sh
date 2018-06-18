#!/bin/bash
set -e

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0, and (if you want) a hostname, default is kali"
    exit 0
fi

basedir=`pwd`/rpi3-nexmon-$1
workfile=$1

kaliname=kali

if [ $2 ]; then
    kalname=$2
fi

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="e2fsprogs initramfs-tools parted sudo usbutils firmware-linux firmware-linux-nonfree firmware-atheros firmware-libertas net-tools"
desktop="fonts-croscore kali-defaults kali-menu fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev xserver-xorg-input-evdev xserver-xorg-input-synaptics"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark net-tools"
services="apache2 openssh-server"
extras="iceweasel xfce4-terminal wpasupplicant python-smbus i2c-tools python-requests python-configobj python-pip bluez bluez-firmware"
nexmon="libgmp3-dev gawk qpdf bison flex make git"

# kernel sauces take up space
size=7000 # Size of image in megabytes

# Git commit hash to check out for the kernel
#kernel_commit=20fe468

#packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras} ${nexmon}"

packages="${arm} ${base} ${services} ${extras} ${nexmon}"

architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.

if debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali
then
  echo "[*] Boostrap Success"
else
  echo "[*] Boostrap Failure"
  #exit 1
fi

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

if LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage
then
  echo "[*] Secondary Boostrap Success"
else
  echo "[*] Secondary Boostrap Failure"
  #exit 1
fi

cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

# Set hostname
echo "${kaliname}" > kali-$architecture/etc/hostname

# So X doesn't complain, we add kali to hosts
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       ${kaliname}    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

cat << EOF > kali-$architecture/etc/modprobe.d/ipv6.conf
# Don't load ipv6 by default
alias net-pf-10 off
#alias ipv6 off
EOF

cat << EOF > kali-$architecture/etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

cat << EOF > kali-$architecture/etc/resolv.conf
nameserver 8.8.8.8
EOF

cat << 'EOF' > kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service
[Unit]
Description=Regenerate SSH host keys
Before=ssh.service
[Service]
Type=oneshot
ExecStartPre=-/bin/dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096
ExecStartPre=-/bin/sh -c "/bin/rm -f -v /etc/ssh/ssh_host_*_key*"
ExecStart=/usr/bin/ssh-keygen -A -v
ExecStartPost=/bin/sh -c "for i in /etc/ssh/ssh_host_*_key*; do actualsize=$(wc -c <\"$i\") ;if [ $actualsize -eq 0 ]; then echo size is 0 bytes ; exit 1 ; fi ; done ; /bin/systemctl disable regenerate_ssh_host_keys"
[Install]
WantedBy=multi-user.target
EOF

chmod 644 kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << 'EOF' > kali-$architecture/usr/bin/monstart
#!/bin/bash
interface=wlan0mon
echo "Bring up monitor mode interface ${interface}"
iw phy phy0 interface add ${interface} type monitor
ifconfig ${interface} up
if [ $? -eq 0 ]; then
  echo "started monitor interface on ${interface}"
fi
EOF
chmod +x kali-$architecture/usr/bin/monstart

cat << 'EOF' > kali-$architecture/usr/bin/monstop
#!/bin/bash
interface=wlan0mon
ifconfig ${interface} down
sleep 1
iw dev ${interface} del
EOF
chmod +x kali-$architecture/usr/bin/monstop

# Bluetooth enabling
mkdir -p kali-$architecture/etc/udev/rules.d
cp ${basedir}/../misc/pi-bluetooth/99-com.rules kali-$architecture/etc/udev/rules.d/99-com.rules
mkdir -p kali-$architecture/lib/systemd/system/
cp ${basedir}/../misc/pi-bluetooth/hciuart.service kali-$architecture/lib/systemd/system/hciuart.service
mkdir -p kali-$architecture/usr/bin
cp ${basedir}/../misc/pi-bluetooth/btuart kali-$architecture/usr/bin/btuart
# Ensure btuart is executable
chmod +x kali-$architecture/usr/bin/btuart

cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
apt-get update
apt-get --yes --force-yes install locales-all
debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
# sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
# rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --force-yes install $packages
if [ $? > 0 ];
then
    apt-get --yes --allow-change-held-packages --fix-broken install
fi
apt-get --yes --force-yes autoremove
# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
# libinput seems to fail hard on RaspberryPi devices, so we make sure it's not
# installed here (and we have xserver-xorg-input-evdev and
# xserver-xorg-input-synaptics packages installed above!)
apt-get --yes --force-yes purge xserver-xorg-input-libinput
echo "Making the image insecure"
rm -f /etc/ssh/ssh_host_*_key*
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
# Enable hciuart for bluetooth device
systemctl enable hciuart
update-rc.d ssh enable
cp  /etc/bash.bashrc /root/.bashrc
# Fix startup time from 5 minutes to 15 secs on raise interface wlan0
sed -i 's/^TimeoutStartSec=5min/TimeoutStartSec=15/g' "/lib/systemd/system/networking.service"
rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
#rm -f /usr/bin/qemu*
EOF

chmod +x kali-$architecture/third-stage

cat << 'EOF' > kali-$architecture/tmp/buildnexmon.sh
#!/bin/bash
kernel=$(uname -r) # Kernel is read from fakeuname.c
git clone https://github.com/seemoo-lab/nexmon.git /opt/nexmon --depth 1
unset CROSS_COMPILE
export CROSS_COMPILE=/opt/nexmon/buildtools/gcc-arm-none-eabi-5_4-2016q2-linux-armv7l/bin/arm-none-eabi-
cd /opt/nexmon/
source setup_env.sh
make
cd buildtools/isl-0.10
CC=$CCgcc
./configure
make
make install
ln -s /usr/local/lib/libisl.so /usr/lib/arm-linux-gnueabihf/libisl.so.10
ln -s /usr/lib/arm-linux-gnueabihf/libmpfr.so.6.0.1 /usr/lib/arm-linux-gnueabihf/libmpfr.so.4
# make scripts doesn't work if we cross crompile. Needs libisl.so before we can compile in scripts
cd /usr/src/kernel
make ARCH=arm scripts
cd /opt/nexmon/
source setup_env.sh
# Build nexmon for pi 3
cd /opt/nexmon/patches/bcm43430a1/7_45_41_46/nexmon/
make clean
make
# Copy the ko file twice. Unsure if changes across both devices break compatibility
cp brcmfmac_kernel49/brcmfmac.ko /lib/modules/${kernel}/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko
cp brcmfmac43430-sdio.bin /lib/firmware/brcm/brcmfmac43430-sdio.bin
# Build nexmon for pi 3 b+
cd /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon
make clean
make
cp /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon/brcmfmac_4.9.y-nexmon/brcmfmac.ko /lib/modules/${kernel}/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko
cp /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon/brcmfmac43455-sdio.bin /lib/firmware/brcm/
EOF
chmod +x kali-$architecture/tmp/buildnexmon.sh

cat << 'EOF' > kali-$architecture/tmp/fakeuname.c
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
/* Fake uname -r because we are in a chroot:
https://gist.github.com/DamnedFacts/5239593
*/
int uname(struct utsname *buf)
{
 int ret;
 ret = syscall(SYS_uname, buf);
 strcpy(buf->release, "4.9.80-Re4son-v7+");
 strcpy(buf->machine, "armv7l");
 return ret;
}
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

if LANG=C chroot kali-$architecture /third-stage
then
  echo "[*] Third Stage Boostrap Success"
else
  echo "[*] Third Stage Boostrap Failure"
  exit 1
fi

rm -rf kali-$architecture/third-stage

umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for Raspberry Pi3 Nexmon"
dd if=/dev/zero of=${basedir}/kali-linux-$workfile-rpi3-nexmon.img bs=1M count=$size
parted kali-linux-$workfile-rpi3-nexmon.img --script -- mklabel msdos
parted kali-linux-$workfile-rpi3-nexmon.img --script -- mkpart primary fat32 0 64
parted kali-linux-$workfile-rpi3-nexmon.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-linux-$workfile-rpi3-nexmon.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat $bootp
mkfs.ext4 $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/bootp ${basedir}/root
mount $bootp ${basedir}/bootp
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt100" >> ${basedir}/root/etc/inittab

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/raspberrypi/firmware.git rpi-firmware
cp -rf rpi-firmware/boot/* ${basedir}/bootp/
rm -rf rpi-firmware
git clone --depth 1 https://github.com/nethunteros/re4son-raspberrypi-linux.git -b rpi-4.9.80-re4son ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
# ln -s /usr/include/asm-generic /usr/include/asm
# Set default defconfig
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
make re4son_pi2_defconfig

# Build kernel
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root


# Copy kernel to boot
perl scripts/mkknlimg --dtok arch/arm/boot/zImage ${basedir}/bootp/kernel7.img
cp arch/arm/boot/dts/*.dtb ${basedir}/bootp/
cp arch/arm/boot/dts/overlays/*.dtb* ${basedir}/bootp/overlays/
cp arch/arm/boot/dts/overlays/README ${basedir}/bootp/overlays/

# Make firmware and headers
make firmware_install INSTALL_MOD_PATH=${basedir}/root

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls ${basedir}/root/lib/modules/)
cd ${basedir}/root/lib/modules/$kernver
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source

# Create cmdline.txt file
cd ${basedir}  

cat << EOF > ${basedir}/bootp/cmdline.txt
dwc_otg.fiq_fix_enable=2 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rootwait rootflags=noload net.ifnames=0
EOF

# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
cat << EOF > ${basedir}/root/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    defaults          0       0
/dev/mmcblk0p1  /boot           vfat    defaults          0       2
/dev/mmcblk0p2  /               ext4    defaults,noatime  0       1
EOF

# Firmware needed for rpi3 wifi (copy nexmon firmware) 
mkdir -p ${basedir}/root/lib/firmware/brcm/
cp ${basedir}/../misc/rpi3/brcmfmac43430-sdio-nexmon.bin ${basedir}/root/lib/firmware/brcm/brcmfmac43430-sdio.bin # We build this now in buildnexmon.sh

# Firmware needed for rpi3 b+ wifi - we comment this out if building for nexmon
cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.bin ${basedir}/root/lib/firmware/brcm/
cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.txt ${basedir}/root/lib/firmware/brcm/
cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.clm_blob ${basedir}/root/lib/firmware/brcm/

cp ${basedir}/../misc/rpi3/nexutil ${basedir}/root/usr/bin/nexutil
chmod +x ${basedir}/root/usr/bin/nexutil

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

LANG=C chroot ${basedir}/root/ /bin/bash -c "cd /tmp && gcc -Wall -shared -o libfakeuname.so fakeuname.c"
LANG=C chroot ${basedir}/root/ /bin/bash -c "chmod +x /tmp/buildnexmon.sh && LD_PRELOAD=/tmp/libfakeuname.so /tmp/buildnexmon.sh"

umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

rm -rf ${basedir}/bootp
rm -rf ${basedir}/root
rm -rf ${basedir}/boot
rm -rf ${basedir}/patches

MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-linux-$workfile-rpi3-nexmon.img"
pixz ${basedir}/kali-linux-$workfile-rpi3-nexmon.img ${basedir}/kali-linux-$workfile-rpi3-nexmon.img.xz
mv ${basedir}/kali-linux-$workfile-rpi3-nexmon.img.xz ${basedir}/../
rm ${basedir}/kali-linux-$workfile-rpi3-nexmon.img
fi
# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}
