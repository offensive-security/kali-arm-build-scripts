#!/bin/bash

# This is for the Original (Marvell based) NOT the Cubox-i (Freescale based)

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/cubox-i-$1

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

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-menu kali-defaults initramfs-tools usbutils"
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
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
EOF
echo "kali" > kali-$architecture/etc/hostname
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

rm -f /usr/sbin/policy-rc.d
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

echo "Creating image file for Cubox-i"
dd if=/dev/zero of=${basedir}/kali-$1-cubox-i.img bs=1 count=0 seek=7G
parted kali-$1-cubox-i.img --script -- mklabel msdos
parted kali-$1-cubox-i.img --script -- mkpart primary ext4 2048 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-cubox-i.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
device="/dev/mapper/${device}"
rootp=${device}p1

# Create file systems
mkfs.ext4 $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/root
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

# Enable serial console
echo 'T1:12345:respawn:/sbin/agetty 115200 ttymxc0 vt100' >> \
    ${basedir}/root/etc/inittab

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/SolidRun/linux-linaro-stable-mx6.git ${basedir}/kernel
cd ${basedir}/kernel
mkdir -p ../patches
wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O ../patches/mac80211.patch
patch -p1 --no-backup-if-mismatch < ../patches/mac80211.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/cubox-i.config .config
make -j $(grep -c processor /proc/cpuinfo) zImage imx6q-cubox-i.dtb imx6dl-cubox-i.dtb imx6dl-hummingboard.dtb modules
make modules_install INSTALL_MOD_PATH=${basedir}/root
# This is kinda hacky, but since we're using 1 single partition
# and their u-boot is kinda wonky, we put zImage and the dtbs in / because
# otherwise there's no autodetection of the dtb and we'd have to release an
# image for each version of the cubox-i.
cp arch/arm/boot/zImage ${basedir}/root/
cp arch/arm/boot/dts/imx6q-cubox-i.dtb ${basedir}/root/
cp arch/arm/boot/dts/imx6dl-cubox-i.dtb ${basedir}/root/
cd ${basedir}

# Create boot.txt file
cat << EOF > ${basedir}/root/uEnv.txt
bootfile=zImage
mmcargs=setenv bootargs root=/dev/mmcblk0p1 rootwait video=mxcfb0:dev=hdmi \
consoleblank=0 console=ttymxc0,115200
EOF

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

# For some reason the brcm firmware doesn't work properly in linux-firmware git
# so we grab the ones from OpenELEC
git clone https://github.com/OpenELEC/wlan-firmware
cd wlan-firmware
rm -rf ${basedir}/root/lib/firmware/brcm
cp -a ${basedir}/wlan-firmware/firmware/brcm ${basedir}/root/lib/firmware/
cd ${basedir}


git clone https://github.com/SolidRun/u-boot-imx6.git
cd ${basedir}/u-boot-imx6
make mx6_cubox-i_config
make

dd if=SPL of=$loopdevice bs=1K seek=1
dd if=u-boot.img of=$loopdevice bs=1K seek=42

cd ${basedir}

# Unmount partitions
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/kernel ${basedir}/root ${basedir}/u-boot-imx6 ${basedir}/wlan-firmware ${basedir}/kali-$architecture ${basedir}/patches

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-cubox-i.img"
sha1sum kali-$1-cubox-i.img > ${basedir}/kali-$1-cubox-i.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-$1-cubox-i.img"
pixz ${basedir}/kali-$1-cubox-i.img ${basedir}/kali-$1-cubox-i.img.xz
rm ${basedir}/kali-$1-cubox-i.img
echo "Generating sha1sum for kali-$1-cubox-i.img.xz"
sha1sum kali-$1-cubox-i.img.xz > ${basedir}/kali-$1-cubox-i.img.xz.sha1sum
fi
