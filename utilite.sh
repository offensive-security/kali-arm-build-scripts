#!/bin/bash

# This is the Utilite Kali ARM build script - http://utilite-computer.com/web/home
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/utilite-$1

# Package installations for various sections. 
# This will build a minimal XFCE Kali system with the top 10 tools.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-menu kali-defaults initramfs-tools"
desktop="xfce4 network-manager network-manager-gnome xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc"
services="openssh-server apache2"
extras="iceweasel wpasupplicant"

export packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
export architecture="armhf"

#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs
debootstrap --foreign --arch $architecture kali kali-$architecture http://http.kali.org/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://http.kali.org/kali kali main contrib non-free
deb http://security.kali.org/kali-security kali/updates main contrib non-free
EOF

# Set hostname
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

# Create the disk and partition it
echo "Creating image file for Utilite"
dd if=/dev/zero of=${basedir}/kali-$1-utilite.img bs=1M count=7000
parted kali-$1-utilite.img --script -- mklabel msdos
parted kali-$1-utilite.img --script -- mkpart primary fat32 2048s 264191s
parted kali-$1-utilite.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-utilite.img`
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

echo "T1:23:/sbin/agetty -L ttymxc3 115200 vt100" >> ${basedir}/root/etc/inittab

cat << EOF >> ${basedir}/root/etc/udev/links.conf
M   ttymxc3 c   5 1
EOF

cat << EOF >> ${basedir}/root/etc/securetty
ttymxc3
EOF

#unset http_proxy

# Get, compile and install kernel
git clone --depth 1 git://gitorious.org/utilite/utilite.git ${basedir}/kernel
cd ${basedir}/kernel
mkdir -p ../patches
wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O ../patches/mac80211.patch
patch -p1 --no-backup-if-mismatch < ../patches/mac80211.patch
cp ${basedir}/../kernel-configs/utilite.config .config
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
make -j $(grep -c processor /proc/cpuinfo) uImage modules
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm/boot/uImage ${basedir}/bootp/uImage-cm-fx6
cd ${basedir}

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

echo "Removing temporary build files"
rm -rf ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/boot

echo "Generating sha1sum for kali-$1-utilite.img"
sha1sum kali-$1-utilite.img > ${basedir}/kali-$1-utilite.img.sha1sum
echo "Compressing kali-$1-utilite.img"
pixz ${basedir}/kali-$1-utilite.img ${basedir}/kali-$1-utilite.img.xz
rm ${basedir}/kali-$1-utilite.img
echo "Generating sha1sum for kali-$1-utilite.img.xz"
sha1sum kali-$1-utilite.img.xz > ${basedir}/kali-$1-utilite.img.xz.sha1sum
