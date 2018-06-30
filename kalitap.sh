#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/kalitap-$1

# Custom hostname variable
hostname=kali
# Custom image file name variable - MUST NOT include .img at the end.
imagename=kali-linux-$1-kalitap

if [ $2 ]; then
    hostname=$2
fi

if [ $3 ]; then
	imagename=$3
fi

# Generate a random machine name to be used.
machine=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/news/kali-linux-metapackages/ for meta packages you
# can use. You can also install packages, using just the package name, but keep
# in mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils u-boot-tools"
base="kali-menu kali-defaults initramfs-tools usbutils firmware-linux firmware-atheros firmware-libertas firmware-realtek"
desktop="xfce4 network-manager network-manager-gnome ntpdate xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc"
services="openssh-server apache2"
extras="iceweasel wpasupplicant"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# You may want to leave security.kali.org alone, but if you trust your local
# mirror, feel free to change this as well.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C systemd-nspawn -M $machine -D kali-$architecture /debootstrap/debootstrap --second-stage
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF
echo "$hostname" > kali-$architecture/etc/hostname
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       $hostname   localhost
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

iface usb0 inet static
    address 192.168.7.2
    netmask 255.255.255.0
    network 192.168.7.0
    gateway 192.168.7.1
EOF

cat << EOF > kali-$architecture/etc/resolv.conf
nameserver 8.8.8.8
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d

apt-get update
apt-get --yes --allow-change-held-packages install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --allow-change-held-packages install $packages
if [ $? > 0 ];
then
    apt-get --yes --allow-change-held-packages --fix-broken install
fi
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.

echo "Making the image insecure"
sed -i -e 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

update-rc.d ssh enable

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod 755 kali-$architecture/third-stage
LANG=C systemd-nspawn -M $machine -D kali-$architecture /third-stage

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

chmod 755 kali-$architecture/cleanup
LANG=C systemd-nspawn -M $machine -D kali-$architecture /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file $imagename.img"
dd if=/dev/zero of=${basedir}/$imagename.img bs=1M count=7000
parted $imagename.img --script -- mklabel msdos
parted $imagename.img --script -- mkpart primary fat32 2048s 264191s
parted $imagename.img --script -- mkpart primary ext4 264192s 100%
parted $imagename.img --script -- set 1 boot on

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/$imagename.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat -F 16 $bootp
mkfs.ext4 -O ^flex_bg -O ^metadata_csum $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/bootp ${basedir}/root
mount $bootp ${basedir}/bootp
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

# Enable serial console on ttyO0
echo 'T1:12345:respawn:/sbin/agetty 115200 ttyO0 vt100' >> ${basedir}/root/etc/inittab

cat << EOF >> ${basedir}/root/etc/udev/links.conf
M   ttyO0 c 5 1
EOF

cat << EOF >> ${basedir}/root/etc/securetty
ttyO0
EOF

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng or else git clones will fail.
#unset http_proxy

# Get, compile and install kernel
git clone --depth 1 https://github.com/wawtechnologies/linux-kernel-3.14.51-catchwire-kalitap.git ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ${basedir}/root/usr/src/kernel-at-commit
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-3.14.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/kalitap.config .config
cp ${basedir}/../kernel-configs/kalitap.config ../kalitap.config
make -j $(grep -c processor /proc/cpuinfo)
make catchwire.dtb catchwire-demac.dtb catchwire-switch.dtb
make INSTALL_MOD_PATH=${basedir}/root/ modules_install
cp arch/arm/boot/zImage ${basedir}/bootp/
cp arch/arm/boot/dts/catchwire*.dtb ${basedir}/bootp/
make mrproper
cp ../kalitap.config .config
make modules_prepare
cd ${basedir}

cat << EOF > ${basedir}/root/etc/fstab
/dev/mmcblk0p2 / auto errors=remount-ro 0 1
/dev/mmcblk0p1 /boot auto noauto 0 0
EOF

cd ${basedir}

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls ${basedir}/root/lib/modules/)
cd ${basedir}/root/lib/modules/$kernver
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source
cd ${basedir}

git clone https://github.com/wawtechnologies/utilities-catchwire-kalitap ${basedir}/utilities
cd ${basedir}/utilities
cp cpswutils/cpswaleget ${basedir}/root/usr/sbin
cp cpswutils/cpswaleset ${basedir}/root/usr/sbin
cp udp0srv/udp0srv ${basedir}/root/usr/sbin
cd ${basedir}

#u-boot kalitap specific overrides:
cat << EOF > ${basedir}/bootp/uEnv.txt
optargs="consoleblank=0 mem=1G rootwait fixrtc net.ifnames=0 rootwait"
kernel_file=zImage
initrd_file=initrd.img
loadaddr=0x82000000
initrd_addr=0x88080000
fdtaddr=0x88000000
fdtfile=catchwire.dtb
initrd_high=0xffffffff
fdt_high=0xffffffff
loadimage=load mmc \${mmcdev}:\${mmcpart} \${loadaddr} \${kernel_file}
loadinitrd=load mmc \${mmcdev}:\${mmcpart} \${initrd_addr} \${initrd_file}; setenv initrd_size \${filesize}
loadfdt=load mmc \${mmcdev}:\${mmcpart} \${fdtaddr} \${fdtfile}
console=ttyO0,115200n8
mmcroot=/dev/mmcblk0p2
mmcrootfstype=ext4
mmcargs=setenv bootargs console=\${console} root=\${mmcroot} rootfstype=\${mmcrootfstype} \${optargs}
uenvcmd=run loadimage; run loadfdt; run mmcargs; bootz \${loadaddr} - \${fdtaddr}
EOF

# Need MLO/u-boot on the sdcard.
git clone https://github.com/wawtechnologies/u-boot-2014.04-catchwire-kalitap.git ${basedir}/u-boot
cd ${basedir}/u-boot
make ARCH=arm distclean
make ARCH=arm catchwire_config
make ARCH=arm

cp MLO ${basedir}/bootp/
cp u-boot.img ${basedir}/bootp/

cd ${basedir}

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/root/etc/ssh/sshd_config

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing $imagename.img"
pixz ${basedir}/$imagename.img ${basedir}/../$imagename.img.xz
rm ${basedir}/$imagename.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}