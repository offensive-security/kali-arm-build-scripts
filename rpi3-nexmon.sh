#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0, and (if you want) a hostname, default is kali"
    exit 0
fi

basedir=`pwd`/rpi3-nexmon-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-rpi3-nexmon}
# Size of image in megabytes (Default is 7000=7GB)
size=7000

# Generate a random machine name to be used.
machine=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="e2fsprogs initramfs-tools parted sudo usbutils firmware-linux firmware-realtek firmware-atheros firmware-libertas net-tools iw wget"
desktop="fonts-croscore kali-defaults kali-menu fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev xserver-xorg-input-evdev xserver-xorg-input-synaptics"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="iceweasel xfce4-terminal wpasupplicant python-smbus i2c-tools python-requests python-configobj python-pip bluez bluez-firmware raspi3-firmware"
nexmon="libgmp3-dev gawk qpdf bison flex make git"

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

if debootstrap --foreign --arch ${architecture} kali-rolling kali-${architecture} http://${mirror}/kali
then
  echo "[*] Boostrap Success"
else
  echo "[*] Boostrap Failure"
  #exit 1
fi

cp /usr/bin/qemu-arm-static kali-${architecture}/usr/bin/

if LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /debootstrap/debootstrap --second-stage
then
  echo "[*] Secondary Boostrap Success"
else
  echo "[*] Secondary Boostrap Failure"
  #exit 1
fi

cat << EOF > kali-${architecture}/etc/apt/sources.list
deb http://${mirror}/kali kali-rolling main contrib non-free
EOF

# Set hostname
echo "${hostname}" > kali-${architecture}/etc/hostname

# So X doesn't complain, we add kali to hosts
cat << EOF > kali-${architecture}/etc/hosts
127.0.0.1       ${hostname}    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

cat << EOF > kali-${architecture}/etc/modprobe.d/ipv6.conf
# Don't load ipv6 by default
alias net-pf-10 off
#alias ipv6 off
EOF

cat << EOF > kali-${architecture}/etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

cat << 'EOF' > kali-${architecture}/lib/systemd/system/regenerate_ssh_host_keys.service
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

chmod 644 kali-${architecture}/lib/systemd/system/regenerate_ssh_host_keys.service

cat << EOF > ${basedir}/kali-${architecture}/lib/systemd/system/rpiwiggle.service
[Unit]
Description=Resize filesystem
Before=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
ExecStart=/root/scripts/rpi-wiggle.sh
ExecStartPost=/bin/systemctl disable rpiwiggle
ExecStartPost=/sbin/reboot

[Install]
WantedBy=multi-user.target
EOF
chmod 644 ${basedir}/kali-${architecture}/lib/systemd/system/rpiwiggle.service

cat << EOF > ${basedir}/kali-${architecture}/lib/systemd/system/enable-ssh.service
[Unit]
Description=Turn on SSH if /boot/ssh is present
ConditionPathExistsGlob=/boot/ssh{,.txt}
After=regenerate_ssh_host_keys.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c "update-rc.d ssh enable && invoke-rc.d ssh start && rm -f /boot/ssh ; rm -f /boot/ssh.txt"

[Install]
WantedBy=multi-user.target
EOF
chmod 644 ${basedir}/kali-${architecture}/lib/systemd/system/enable-ssh.service

cat << EOF > ${basedir}/kali-${architecture}/lib/systemd/system/copy-user-wpasupplicant.service
[Unit]
Description=Copy user wpa_supplicant.conf
ConditionPathExists=/boot/wpa_supplicant.conf
Before=dhcpcd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mv /boot/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf
ExecStartPost=/bin/chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf

[Install]
WantedBy=multi-user.target
EOF
chmod 644 ${basedir}/kali-${architecture}/lib/systemd/system/copy-user-wpasupplicant.service

cat << EOF > ${basedir}/kali-${architecture}/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << 'EOF' > ${basedir}/kali-${architecture}/usr/bin/monstart
#!/bin/bash
interface=wlan0mon
echo "Bring up monitor mode interface ${interface}"
iw phy phy0 interface add ${interface} type monitor
ifconfig ${interface} up
if [ $? -eq 0 ]; then
  echo "started monitor interface on ${interface}"
fi
EOF
chmod 755 ${basedir}/kali-${architecture}/usr/bin/monstart

cat << 'EOF' > ${basedir}/kali-${architecture}/usr/bin/monstop
#!/bin/bash
interface=wlan0mon
ifconfig ${interface} down
sleep 1
iw dev ${interface} del
EOF
chmod 755 ${basedir}/kali-${architecture}/usr/bin/monstop

# Bluetooth enabling
mkdir -p ${basedir}/kali-${architecture}/etc/udev/rules.d
cp ${basedir}/../misc/pi-bluetooth/99-com.rules ${basedir}/kali-${architecture}/etc/udev/rules.d/99-com.rules
mkdir -p ${basedir}/kali-${architecture}/lib/systemd/system/
cp ${basedir}/../misc/pi-bluetooth/hciuart.service ${basedir}/kali-${architecture}/lib/systemd/system/hciuart.service
mkdir -p ${basedir}/kali-${architecture}/usr/bin
cp ${basedir}/../misc/pi-bluetooth/btuart ${basedir}/kali-${architecture}/usr/bin/btuart
# Ensure btuart is executable
chmod 755 ${basedir}/kali-${architecture}/usr/bin/btuart

cat << EOF > ${basedir}/kali-${architecture}/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get update
apt-get --yes --allow-change-held-packages install locales-all
debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --allow-change-held-packages install ${packages}
apt-get --yes --allow-change-held-packages install ${desktop} ${tools}
if [[ $? > 0 ]];
then
    apt-get --yes --allow-change-held-packages --fix-broken install || die "Packages failed to install"
fi
apt-get --yes --allow-change-held-packages autoremove
# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
# libinput seems to fail hard on RaspberryPi devices, so we make sure it's not
# installed here (and we have xserver-xorg-input-evdev and
# xserver-xorg-input-synaptics packages installed above!)
apt-get --yes --allow-change-held-packages purge xserver-xorg-input-libinput

echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

systemctl enable rpiwiggle
# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys

# Enable hciuart for bluetooth device
systemctl enable hciuart

# Enable copying of user wpa_supplicant.conf file
systemctl enable copy-user-wpasupplicant

# Enable... enabling ssh by putting ssh or ssh.txt file in /boot
systemctl enable enable-ssh

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

chmod 755 ${basedir}/kali-${architecture}/third-stage

cat << 'EOF' > ${basedir}/kali-${architecture}/root/buildnexmon.sh
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
# Make sure the firmware directory exists before we copy anything.
mkdir -p /lib/firmware/brcm
# Copy the ko file twice. Unsure if changes across both devices break compatibility
cp brcmfmac_kernel49/brcmfmac.ko /lib/modules/${kernel}/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko
cp brcmfmac43430-sdio.bin /lib/firmware/brcm/brcmfmac43430-sdio.bin
wget https://raw.githubusercontent.com/RPi-Distro/firmware-nonfree/master/brcm/brcmfmac43430-sdio.txt -O /lib/firmware/brcm/brcmfmac43430-sdio.txt

# Build nexmon for pi 3 b+
cd /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon
make clean
make
cp /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon/brcmfmac_4.9.y-nexmon/brcmfmac.ko /lib/modules/${kernel}/kernel/drivers/net/wireless/broadcom/brcm80211/brcmfmac/brcmfmac.ko
cp /opt/nexmon/patches/bcm43455c0/7_45_154/nexmon/brcmfmac43455-sdio.bin /lib/firmware/brcm/
EOF
chmod 755 ${basedir}/kali-${architecture}/root/buildnexmon.sh

# rpi-wiggle
mkdir -p ${basedir}/kali-${architecture}/root/scripts
wget https://raw.githubusercontent.com/offensive-security/rpiwiggle/master/rpi-wiggle -O kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 ${basedir}/kali-${architecture}/root/scripts/rpi-wiggle.sh

cat << 'EOF' > kali-${architecture}/root/fakeuname.c
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

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

if LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /third-stage
then
  echo "[*] Third Stage Boostrap Success"
else
  echo "[*] Third Stage Boostrap Failure"
  exit 1
fi

rm -rf kali-${architecture}/third-stage

#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt100" >> ${basedir}/kali-${architecture}/etc/inittab

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/nethunteros/re4son-raspberrypi-linux.git -b rpi-4.9.80-re4son ${basedir}/kali-${architecture}/usr/src/kernel
cd ${basedir}/kali-${architecture}/usr/src/kernel
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
make re4son_pi2_defconfig

# Build kernel
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/kali-${architecture}

# Copy kernel to boot
perl scripts/mkknlimg --dtok arch/arm/boot/zImage ${basedir}/kali-${architecture}/boot/kernel7.img
cp arch/arm/boot/dts/*.dtb ${basedir}/kali-${architecture}/boot/
mkdir -p ${basedir}/kali-${architecture}/boot/overlays/
cp arch/arm/boot/dts/overlays/*.dtb* ${basedir}/kali-${architecture}/boot/overlays/
cp arch/arm/boot/dts/overlays/README ${basedir}/kali-${architecture}/boot/overlays/

# Make firmware and headers
make firmware_install INSTALL_MOD_PATH=${basedir}/kali-${architecture}

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls ${basedir}/kali-${architecture}/lib/modules/)
cd ${basedir}/kali-${architecture}/lib/modules/${kernver}
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source
cd ${basedir}

# Create cmdline.txt file
cd ${basedir}

cat << EOF > ${basedir}/kali-${architecture}/boot/cmdline.txt
dwc_otg.fiq_fix_enable=2 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rootwait rootflags=noload net.ifnames=0
EOF

# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
cat << EOF > ${basedir}/kali-${architecture}/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    defaults          0       0
/dev/mmcblk0p1  /boot           vfat    defaults          0       2
/dev/mmcblk0p2  /               ext4    defaults,noatime  0       1
EOF

# Firmware needed for rpi3 wifi (copy nexmon firmware) 
#mkdir -p ${basedir}/kali-${architecture}/lib/firmware/brcm/
#cp ${basedir}/../misc/rpi3/brcmfmac43430-sdio-nexmon.bin ${basedir}/kali-${architecture}/lib/firmware/brcm/brcmfmac43430-sdio.bin # We build this now in buildnexmon.sh

# Firmware needed for rpi3 b+ wifi - we comment this out if building for nexmon
#cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.bin ${basedir}/kali-${architecture}/lib/firmware/brcm/
#cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.txt ${basedir}/kali-${architecture}/lib/firmware/brcm/
#cp ${basedir}/../misc/brcm/brcmfmac43455-sdio.clm_blob ${basedir}/kali-${architecture}/lib/firmware/brcm/

#cp ${basedir}/../misc/rpi3/nexutil ${basedir}/kali-${architecture}/usr/bin/nexutil
#chmod 755 ${basedir}/kali-${architecture}/usr/bin/nexutil

# Copy a default config, with everything commented out so people find it when
# they go to add something when they are following instructions on a website.
cp ${basedir}/../misc/config.txt ${basedir}/kali-${architecture}/boot/config.txt

cat << EOF >> ${basedir}/kali-${architecture}/boot/config.txt

# If you would like to enable USB booting on your Pi, uncomment the following line.
# Boot from microsd card with it, then reboot.
# Don't forget to comment this back out after using, especially if you plan to use
# sdcard with multiple machines!
#program_usb_boot_mode=1
EOF

# Because we use debian's firmware package and they install it to /boot/firmware instead of /boot directly
# we have to mv it to /boot so the thing will boot.
mv ${basedir}/kali-${architecture}/boot/firmware/* ${basedir}/kali-${architecture}/boot/

cp ${basedir}/../misc/zram ${basedir}/kali-${architecture}/etc/init.d/zram
chmod 755 ${basedir}/kali-${architecture}/etc/init.d/zram

# Create the disk and partition it
echo "Creating image file ${imagename}.img"
dd if=/dev/zero of=${basedir}/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary fat32 0 64
parted ${imagename}.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/${imagename}.img`
device=`kpartx -va ${loopdevice}| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat ${bootp}
mkfs.ext4 ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/root/
mount ${rootp} ${basedir}/root
mkdir -p ${basedir}/root/boot
mount ${bootp} ${basedir}/root/boot

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-${architecture}/ ${basedir}/root/

LANG=C systemd-nspawn -M ${machine} -D ${basedir}/root/ /bin/bash -c "cd /root && gcc -Wall -shared -o libfakeuname.so fakeuname.c"
LANG=C systemd-nspawn -M ${machine} -D ${basedir}/root/ /bin/bash -c "chmod 755 /root/buildnexmon.sh && LD_PRELOAD=/root/libfakeuname.so /root/buildnexmon.sh"

rm -rf ${basedir}/root/root/{fakeuname.c,buildnexmon.sh,libfakeuname.so}

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > ${basedir}/root/etc/resolv.conf
nameserver 8.8.8.8
EOF

# Make sure to enable ssh on the device by default
touch ${basedir}/root/boot/ssh

sync
umount -l ${bootp}
umount -l ${rootp}
kpartx -dv ${loopdevice}
losetup -d ${loopdevice}

MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing ${imagename}.img"
pixz ${basedir}/${imagename}.img ${basedir}/../${imagename}.img.xz
rm ${basedir}/${imagename}.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}