#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/usbarmory-$1

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
#desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server shellinabox"
#extras="cryptsetup iceweasel lvm2 xfce4-terminal wpasupplicant"
extras="cryptsetup lvm2 wpasupplicant"

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

echo "Enabling sshd"
update-rc.d ssh enable
echo "Enabling shellinabox"
ln -sf '/var/run/systemd/generator.late/shellinabox.service' '/etc/systemd/system/multi-user.target.wants/shellinabox.service'

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
# Not sure why this gets created...
rm -f /0
# If java bombs for some reason...
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
echo "Creating image file for USB Armory"
dd if=/dev/zero of=${basedir}/kali-$1-usbarmory.img bs=1M count=7000
parted kali-$1-usbarmory.img --script -- mklabel msdos
parted kali-$1-usbarmory.img --script -- mkpart primary ext2 5M 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-usbarmory.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
device="/dev/mapper/${device}"
rootp=${device}p1

# Create file systems
mkfs.ext2 $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/root
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

echo "Setting up modules.conf"
# rm the symlink if it exists, and the original files if they exist
rm ${basedir}/root/etc/modules
rm ${basedir}/root/etc/modules-load.d/modules.conf
cat << EOF > ${basedir}/root/etc/modules-load.d/modules.conf
ledtrig_heartbeat
ci_hdrc_imx
#g_mass_storage
g_ether
EOF

echo "Setting up modprobe.d"
cat << EOF > ${basedir}/root/etc/modprobe.d/g_ether.conf
options g_ether use_eem=0 dev_addr=1a:55:89:a2:69:41 host_addr=1a:55:89:a2:69:42
EOF

cat << EOF > ${basedir}/root/etc/modprobe.d/g_mass.conf
# Create this file if you want to use usb mass storage!
# For example, this will create a 2GB img file for mass storage use.
# dd if=/dev/zero of=/massstorage.img bs=1M count=2000
#options g_mass_storage file=/massstorage.img
EOF

cat << EOF > ${basedir}/root/etc/network/interfaces
auto lo
iface lo inet loopback

allow-hotplug usb0
iface usb0 inet static
address 10.42.0.3
netmask 255.255.255.0
gateway 10.42.0.1
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
git clone -b linux-4.1.y --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ../kernel-at-commit
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/mac80211.patch
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-common.dtsi -O arch/arm/boot/dts/imx53-usbarmory-common.dtsi
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-host.dts -O arch/arm/boot/dts/imx53-usbarmory-host.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-gpio.dts -O arch/arm/boot/dts/imx53-usbarmory-gpio.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory.dts -O arch/arm/boot/dts/imx53-usbarmory.dts
cp ${basedir}/../kernel-configs/usbarmory-4.1.config .config
cp ${basedir}/../kernel-configs/usbarmory-4.1.config ../usbarmory-4.1.config
make LOADADDR=0x70008000 -j $(grep -c processor /proc/cpuinfo) uImage modules imx53-usbarmory-gpio.dtb imx53-usbarmory.dtb imx53-usbarmory-host.dtb
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm/boot/uImage ${basedir}/root/boot/
cp arch/arm/boot/dts/imx53-usbarmory-gpio.dtb ${basedir}/root/boot/
cp arch/arm/boot/dts/imx53-usbarmory.dtb ${basedir}/root/boot/
cp arch/arm/boot/dts/imx53-usbarmory-host.dtb ${basedir}/root/boot/
make mrproper
# Since these aren't integrated into the kernel yet, mrproper removes them.
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-common.dtsi -O arch/arm/boot/dts/imx53-usbarmory-common.dtsi
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-host.dts -O arch/arm/boot/dts/imx53-usbarmory-host.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory-gpio.dts -O arch/arm/boot/dts/imx53-usbarmory-gpio.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/imx53-usbarmory.dts -O arch/arm/boot/dts/imx53-usbarmory.dts
cp ../usbarmory-4.1.config .config
make modules_prepare
cd ${basedir}


rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
cd firmware
rm -rf .git
cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

wget ftp://ftp.denx.de/pub/u-boot/u-boot-2015.04.tar.bz2
tar -xf u-boot-2015.04.tar.bz2
cd ${basedir}/u-boot-2015.04
make distclean
make usbarmory_config
make
dd if=u-boot.imx of=$loopdevice bs=512 seek=2 conv=fsync
cd ${basedir}

# Unmount partitions
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/kernel ${basedir}/u-boot* ${basedir}/root ${basedir}/kali-$architecture ${basedir}/patches

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-usbarmory.img"
sha1sum kali-$1-usbarmory.img > ${basedir}/kali-$1-usbarmory.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-$1-usbarmory.img"
pixz ${basedir}/kali-$1-usbarmory.img ${basedir}/kali-$1-usbarmory.img.xz
rm ${basedir}/kali-$1-usbarmory.img
echo "Generating sha1sum for kali-$1-usbarmory.img.xz"
sha1sum kali-$1-usbarmory.img.xz > ${basedir}/kali-$1-usbarmory.img.xz.sha1sum
fi
