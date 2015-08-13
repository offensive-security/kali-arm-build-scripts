#!/bin/bash

# This is the HardKernel ODROID XU3 Kali ARM build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com


if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/odroidxu3-$1

# Make sure that the cross compiler can be found in the path before we do
# anything else, that way the builds don't fail half way through.
export CROSS_COMPILE=arm-linux-gnueabihf-
if [ $(compgen -c $CROSS_COMPILE | wc -l) -eq 0 ] ; then
    echo "Missing cross compiler. Set up PATH according to the README"
    exit 1
fi
# Unset CROSS_COMPILE so that if there is any native compiling needed it doesn't
# get cross compiled.
unset CROSS_COMPILE

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="e2fsprogs initramfs-tools kali-defaults kali-menu parted sudo usbutils"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="iceweasel xfce4-terminal wpasupplicant"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# You may want to leave security.kali.org alone, but if you trust your local
# mirror, feel free to change this as well.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=repo.kali.org
security=security.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture sana kali-$architecture http://$mirror/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage

# Create sources.list
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali sana main contrib non-free
deb http://$security/kali-security sana/updates main contrib non-free
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
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --force-yes install $packages
apt-get --yes --force-yes dist-upgrade
apt-get --yes --force-yes autoremove

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
echo "Creating image file for ODROID-XU3"
dd if=/dev/zero of=${basedir}/kali-$1-odroidxu3.img bs=1M count=7000
parted kali-$1-odroidxu3.img --script -- mklabel msdos
parted kali-$1-odroidxu3.img --script -- mkpart primary fat32 2048s 264191s
parted kali-$1-odroidxu3.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-odroidxu3.img`
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

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali sana main non-free contrib
deb http://security.kali.org/kali-security sana/updates main contrib non-free

deb-src http://http.kali.org/kali sana main non-free contrib
deb-src http://security.kali.org/kali-security sana/updates main contrib non-free
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/hardkernel/linux.git -b odroidxu3-3.10.y ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ../kernel-at-commit
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/mac80211.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/odroid-xu3.config .config
cp ${basedir}/../kernel-configs/odroid-xu3.config ../odroid-xu3.config
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm/boot/zImage ${basedir}/bootp
cp arch/arm/boot/dts/exynos5422-odroidxu3.dtb ${basedir}/bootp
make mrproper
cp ../odroid-xu3.config .config
make modules_prepare
cd ${basedir}

cat << EOF > ${basedir}/bootp/boot.ini
ODROIDXU-UBOOT-CONFIG

# U-Boot Parameters
setenv initrd_high "0xffffffff"
setenv fdt_high "0xffffffff"

# Mac address configuration
setenv macaddr "00:1e:06:61:7a:39"

#------------------------------------------------------------------------------------------------------
# Basic Ubuntu Setup. Don't touch unless you know what you are doing.
# --------------------------------
setenv bootrootfs "console=tty1 console=ttySAC2,115200n8 root=/dev/mmcblk0p2 rootwait"

# boot commands
setenv bootcmd "fatload mmc 0:1 0x40008000 zImage; fatload mmc 0:1 0x42000000 uInitrd; fatload mmc 0:1 0x44000000 exynos5422-odroidxu3.dtb; bootz 0x40008000 0x42000000 0x44000000"

# --- Screen Configuration for HDMI --- # 
# ---------------------------------------
# Uncomment only ONE line! Leave all commented for automatic selection.
# Uncomment only the setenv line!
# ---------------------------------------
# ODROID-VU forced resolution
# setenv videoconfig "video=HDMI-A-1:1280x800@60"
# -----------------------------------------------
# 1920x1080 (1080P) with monitor provided EDID information. (1080p-edid)
# setenv videoconfig "video=HDMI-A-1:1920x1080@60"
# -----------------------------------------------
# 1920x1080 (1080P) without monitor data using generic information (1080p-noedid)
# setenv videoconfig "drm_kms_helper.edid_firmware=edid/1920x1080.bin"
# -----------------------------------------------
# 1280x720 (720P) with monitor provided EDID information. (720p-edid)
# setenv videoconfig "video=HDMI-A-1:1280x720@60"
# -----------------------------------------------
# 1280x720 (720P) without monitor data using generic information (720p-noedid)
# setenv videoconfig "drm_kms_helper.edid_firmware=edid/1280x720.bin"
# -----------------------------------------------
# 1024x768 without monitor data using generic information
# setenv videoconfig "drm_kms_helper.edid_firmware=edid/1024x768.bin"


# final boot args
setenv bootargs "\${bootrootfs} \${videoconfig} smsc95xx.macaddr=\${macaddr}"
# drm.debug=0xff
# Boot the board
boot
EOF

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram


# Write the signed u-boot binary to the image so that it will boot.
cd ${basedir}/root/usr/src/kernel/tools/hardkernel/prebuilt_uboot
sh sd_fusing.sh $loopdevice
cd ${basedir}

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice

losetup -d $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/patches ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/boot

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-odroidxu3.img"
sha1sum kali-$1-odroidxu3.img > ${basedir}/kali-$1-odroidxu3.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-$1-odroidxu3.img"
pixz ${basedir}/kali-$1-odroidxu3.img ${basedir}/kali-$1-odroidxu3.img.xz
rm ${basedir}/kali-$1-odroidxu3.img
echo "Generating sha1sum for kali-$1-odroidxu3.img.xz"
sha1sum kali-$1-odroidxu3.img.xz > ${basedir}/kali-$1-odroidxu3.img.xz.sha1sum
fi
