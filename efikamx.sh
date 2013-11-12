#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/efikamx-$1

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils uboot-mkimage"
base="kali-linux kali-menu kali-linux-full kali-defaults initramfs-tools"
desktop="xfce4 network-manager network-manager-gnome xserver-xorg-video-fbdev"
pth="passing-the-hash unicornscan winexe enum4linux polenum nfspy wmis nipper-ng jsql ghost-phisher uniscan lbd automater arachni bully inguma sslsplit dumpzilla recon-ng ridenum jd-gui"
export packages="${arm} ${base} ${desktop} ${pth} armitage iceweasel metasploit wpasupplicant openssh-server"
export architecture="armhf"

#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs
debootstrap --foreign --arch $architecture kali kali-$architecture http://archive.kali.org/kali

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
echo "Creating image file for EfikaMX"
dd if=/dev/zero of=${basedir}/kali-$1-efikamx.img bs=1M count=7000
parted kali-$1-efikamx.img --script -- mklabel msdos
parted kali-$1-efikamx.img --script -- mkpart primary ext2 4096s 266239s
parted kali-$1-efikamx.img --script -- mkpart primary ext4 266240s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-efikamx.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.ext2 $bootp
mkfs.ext4 $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/bootp ${basedir}/root
mount $bootp ${basedir}/bootp
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

# Now some fixes/changes needed!

# (No auto login)
#T1:12345:respawn:/sbin/agetty 115200 ttymxc0 vt100 >> ${basedir}/root/etc/inittab
# (Auto login on serial console)
#T1:12345:respawn:/bin/login -f root ttymxc0 /dev/ttymxc0 2>&1
echo 'T1:12345:respawn:/sbin/agetty 115200 ttymxc0 vt100' >> \
    ${basedir}/root/etc/inittab

cat << EOF >> ${basedir}/root/etc/udev/links.conf
M   ttymxc0 c 5 1
EOF

cat << EOF >> ${basedir}/root/etc/securetty
ttymxc0
EOF

# Currently we use a 2.6.31 kernel, it's patched so udev will work, but Debian's
# udev doesn't know that.  So we yank this line out of the init script otherwise
# udev won't start and we have no devices, including keyboard/usb support.
sed -i -e "s/2.6.3\[0-1\]/2.6.30/g" ${basedir}/root/etc/init.d/udev

#unset http_proxy

# Get, compile and install kernel
git clone --depth 1 https://github.com/genesi/linux-legacy ${basedir}/kernel
cd ${basedir}/kernel
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
mkdir -p ../patches
wget http://patches.aircrack-ng.org/mac80211.compat08082009.wl_frag+ack_v1.patch -O ../patches/mac80211.patch
patch -p1 --no-backup-if-mismatch < ../patches/mac80211.patch
make mx51_efikamx_defconfig
make -j $(grep -c processor /proc/cpuinfo) uImage modules
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm/boot/uImage ${basedir}/bootp
cd ${basedir}

# Create boot.txt file
cat << EOF > ${basedir}/bootp/boot.script
setenv ramdisk uInitrd;
setenv kernel uImage;
setenv bootargs console=tty1 root=/dev/mmcblk0p2 rootwait rootfstype=ext4 rw quiet;
\${loadcmd} \${ramdiskaddr} \${ramdisk};
if imi \${ramdiskaddr}; then; else
setenv bootargs \${bootargs} noinitrd;
setenv ramdiskaddr "";
fi;
\${loadcmd} \${kerneladdr} \${kernel}
if imi \${kerneladdr}; then
bootm \${kerneladdr} \${ramdiskaddr}
fi;
EOF

# Create image
mkimage -A arm -T script -C none -d ${basedir}/bootp/boot.script ${basedir}/bootp/boot.scr

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
cd firmware
rm -rf .git
cd ${basedir}

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# Remove all the various bits used to generate the image.
rm -rf ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/patches

echo "Generating sha1sum for kali-$1-efikamx.img"
sha1sum kali-$1-efikamx.img > ${basedir}/kali-$1-efikamx.img.sha1sum
echo "Compressing kali-$1-efikamx.img"
pixz ${basedir}/kali-$1-efikamx.img ${basedir}/kali-$1-efikamx.img.xz
rm ${basedir}/kali-$1-efikamx.img
echo "Generating sha1sum for kali-$1-efikamx.img.xz"
sha1sum kali-$1-efikamx.img.xz > ${basedir}/kali-$1-efikamx.img.xz.sha1sum
