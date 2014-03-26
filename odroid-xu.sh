#!/bin/bash

# This is the HardKernel Odroid XU Kali ARM build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com


if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/odroidxu-$1

# This is used for cross compiling the exynos5-hwcomposer.
# If this isn't built/installed, there will be no framebuffer console.
hosttuple=arm-linux-gnueabihf

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-menu kali-defaults initramfs-tools"
desktop="xfce4 network-manager network-manager-gnome xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc"
services="openssh-server apache2"
extras="iceweasel wpasupplicant"

export packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
export architecture="armhf"

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture kali kali-$architecture http://http.kali.org/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage

# Create sources.list
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
EOF

# Set hostname
echo "kali" > kali-$architecture/etc/hostname

# So X doesn't complain, we add kali to hosts
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       kali    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
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

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools uboot-mkimage
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
apt-get --yes --force-yes install $packages
apt-get -f install

rm /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C chroot kali-$architecture /third-stage

cat << EOF > kali-$architecture/cleanup
#!/bin/bash
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*
EOF

chmod +x kali-$architecture/cleanup
LANG=C chroot kali-$architecture /cleanup

umount kali-$architecture/proc/sys/fs/binfmt_misc
umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for ODROID-XU"
dd if=/dev/zero of=${basedir}/kali-$1-odroidxu.img bs=1M count=7000
parted kali-$1-odroidxu.img --script -- mklabel msdos
parted kali-$1-odroidxu.img --script -- mkpart primary fat32 2048s 264191s
parted kali-$1-odroidxu.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-odroidxu.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
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

# Serial console settings.
# (Auto login on serial console)
#T1:12345:respawn:/sbin/agetty 115200 ttySAC2 vt100 >> ${basedir}/root/etc/inittab
# (No auto login)
#T1:12345:respawn:/bin/login -f root ttySAC2 /dev/ttySAC2 2>&1' >> ${basedir}/root/etc/inittab
# Make sure ttySAC1 is in root/etc/securetty so root can login on serial console.
echo 'T1:12345:respawn:/bin/login -f root ttySAC2 /dev/ttySAC2 2>&1' >> ${basedir}/root/etc/inittab

cat << EOF >> ${basedir}/root/etc/udev/links.conf
M   ttySAC2 c 5 1
EOF

cat << EOF >> ${basedir}/root/etc/securetty
ttySAC0
ttySAC1
ttySAC2
EOF

# Start X on the ODROID XU.
cp ${basedir}/root/etc/skel/.profile ${basedir}/root/root/.bash_profile

cat << EOF >> ${basedir}/root/root/.bash_profile
if [ -z "$DISPLAY" ] && [ $(tty) = /dev/ttySAC1 ]; then
startx
fi
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/hardkernel/linux.git -b odroidxu-3.4.y ${basedir}/kernel
cd ${basedir}/kernel
mkdir -p ../patches
wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O ../patches/mac80211.patch
patch -p1 --no-backup-if-mismatch < ../patches/mac80211.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/xu.config .config
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm/boot/zImage ${basedir}/bootp

# This is to build the console framebuffer application.
echo "Building the hwcomposer"
cd ${basedir}/kernel/tools/hardkernel/exynos5-hwcomposer
# It's quite chatty still, so we if 0 the logging, and also add a missing #define
sed -i -e 's/if 1/if 0/g' include/log.h
sed -i -e 's/#define ALOGD/#define ALOGD\r#define ALOGF/g' include/log.h

./configure --prefix=/usr --build x86_64-pc-linux-gnu --host $hosttuple
make
make DESTDIR=${basedir}/root install

sed -i -e 's~^exit 0~exynos5-hwcomposer > /dev/null 2>\&1 \&\nexit 0~' ${basedir}/root/etc/rc.local

cd ${basedir}

# XU can do 720p or 1080p so create 2 boot.txt, default to 720p
cat << EOF > ${basedir}/bootp/boot-hdmi-720.txt
setenv initrd_high "0xffffffff"
setenv fdt_high "0xffffffff"
setenv fb_x_res "1280"
setenv fb_y_res "720"
setenv hdmi_phy_res "720"
setenv bootcmd "fatload mmc 0:1 0x40008000 zImage; fatload mmc 0:1 0x42000000 uInitrd; bootz 0x40008000 0x42000000"
setenv bootargs "console=tty1 console=ttySAC2,115200n8 vmalloc=512M fb_x_res=${fb_x_res} fb_y_res=${fb_y_res} hdmi_phy_res=${hdmi_phy_res} vout=hdmi led_blink=1 fake_fb=true root=/dev/mmcblk0p2 rootwait ro"
boot
EOF

cat << EOF > ${basedir}/bootp/boot-hdmi-1080.txt
setenv initrd_high "0xffffffff"
setenv fdt_high "0xffffffff"
setenv fb_x_res "1920"
setenv fb_y_res "1080"
setenv hdmi_phy_res "1080"
setenv bootcmd "fatload mmc 0:1 0x40008000 zImage; fatload mmc 0:1 0x42000000 uInitrd; bootz 0x40008000 0x42000000"
setenv bootargs "console=tty1 console=ttySAC2,115200n8 vmalloc=512M fb_x_res=${fb_x_res} fb_y_res=${fb_y_res} hdmi_phy_res=${hdmi_phy_res} vout=hdmi led_blink=1 fake_fb=true root=/dev/mmcblk0p2 rootwait ro"
boot
EOF

# Create boot.scr(s)
mkimage -A arm -T script -C none -d ${basedir}/bootp/boot-hdmi-720.txt ${basedir}/bootp/boot-720.scr
mkimage -A arm -T script -C none -d ${basedir}/bootp/boot-hdmi-1080.txt ${basedir}/bootp/boot-1080.scr
cp ${basedir}/bootp/boot-720.scr ${basedir}/bootp/boot.scr

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice

# Write the signed u-boot binary to the image so that it will boot.
cd ${basedir}/kernel/tools/hardkernel/u-boot-pre-built
sh sd_fusing.sh $loopdevice
cd ${basedir}

# The XU u-boot version is 2012.07
# as of 10/13/2013 the bl1 and bl2 aren't in u-boot sources.
# So, we'll need to copy them from the kernel directory into here.
# We also need to modify some files in u-boot to work with the cross compiler.
#git clone --depth 1 https://github.com/hardkernel/u-boot -b odroid-v2012.07
#cd ${basedir}/u-boot
# https://code.google.com/p/chromium/issues/detail?id=213120
#sed -i -e "s/soft-float/float-abi=hard -mfpu=vfpv3/g" \
#    arch/arm/cpu/armv7/config.mk
#make smdk5410_config
#make -j $(grep -c processor /proc/cpuinfo)
#cd ${basedir}/u-boot/sd_fuse/smdk5410/
#cp ${basedir}/kernel/tools/hardkernel/u-boot-pre-built/
#sh sd_fuse.sh $loopdevice
#cd ${basedir}

losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/patches ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/boot

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-odroidxu.img"
sha1sum kali-$1-odroidxu.img > ${basedir}/kali-$1-odroidxu.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-$1-odroidxu.img"
pixz ${basedir}/kali-$1-odroidxu.img ${basedir}/kali-$1-odroidxu.img.xz
rm ${basedir}/kali-$1-odroidxu.img
echo "Generating sha1sum for kali-$1-odroidxu.img.xz"
sha1sum kali-$1-odroidxu.img.xz > ${basedir}/kali-$1-odroidxu.img.xz.sha1sum
fi
