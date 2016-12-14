#!/bin/bash
# This is the Pine64 Kali ARM64 build script by LSawyer, based on the HardKernel ODROID-c2 script and
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

debug() {
    if [ ${DEBUG:-0} -eq 1 ]; then
	TEXT=${1}
	if [ -z "$TEXT" ]; then
		echo -n "paused - hit return to continue: "
	else
		echo -n "${TEXT}: "
	fi
	read SLEEP
	echo ""
    fi
}

MACHINE_TYPE=`uname -m`
DEBUG=1

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
else
    MYVER=${1//[^0-9.]/}
fi

if [ -z "$(which debootstrap)" ]; then
    echo "have you run the build-deps.sh script yet?"
    exit 1
fi

basedir=`pwd`/pine64-${MYVER}

# Make sure that the cross compiler can be found in the path before we do
# anything else, that way the builds don't fail half way through.
if [ "${MACHINE_TYPE}" != "aarch64" ] ; then
    export CROSS_COMPILE=aarch64-linux-gnu-
    if [ $(compgen -c $CROSS_COMPILE | wc -l) -eq 0 ] ; then
        echo "Missing cross compiler. Set up PATH according to the README"
        exit 1
    fi
    # Unset CROSS_COMPILE so that if there is any native compiling needed it doesn't
    # get cross compiled.
else
    BUILD_NATIVE=1
fi
# so, always...
unset CROSS_COMPILE

# Package installations for various sections.
# This will build a mostly-useable XFCE Kali system for Pine64.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg fake-hwclock ntpdate u-boot-tools"
base="e2fsprogs initramfs-tools kali-defaults kali-menu parted sudo usbutils"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="fbset iceweasel xfce4-terminal wpasupplicant kali-linux kali-linux-forensic kali-linux-pwtools kali-linux-top10"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="arm64"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

debug "starting debootstrap"
# create the rootfs - not much to modify here, except maybe the hostname.
if [ ${BUILD_NATIVE:0} -eq 0 ] ; then
    debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali
    cp /usr/bin/qemu-aarch64-static kali-$architecture/usr/bin/

    LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage
else
    debootstrap --arch $architecture kali-rolling kali-$architecture http://$mirror/kali
fi

cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

echo "kali-arm64" > kali-$architecture/etc/hostname

cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       kali-arm64    localhost
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

debug "mounting bind dirs"

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
apt-get --yes --force-yes install locales-all

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

debug "executing third-stage script in chroot"

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

debug "executing cleanup script in chroot"

chmod +x kali-$architecture/cleanup
LANG=C chroot kali-$architecture /cleanup

umount kali-$architecture/proc/sys/fs/binfmt_misc
umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for Pine64"
debug ""
dd if=/dev/zero of=${basedir}/kali-$1-pine64.img bs=1M count=7000
parted kali-$1-pine64.img --script -- mklabel msdos
parted kali-$1-pine64.img --script -- mkpart primary fat32 2048s 264191s
parted kali-$1-pine64.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-$1-pine64.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

debug "creating file systems"
# Create file systems
mkfs.vfat $bootp
mkfs.ext4 -L rootfs $rootp

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/bootp ${basedir}/root
mount $bootp ${basedir}/bootp
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
# For some reason, building the kernel in the image fails claiming it's run out
# of space - for the moment, let's build the kernel outside of it, but still
# keep the sources around for those who want/need to build external modules.

debug "setting up kernel for build"
# this is held at kernel 3.10, at least until Pine64 is fully mainlined.
git clone --depth 1 https://github.com/longsleep/linux-pine64 -b pine64-hacks-1.2 ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ../kernel-at-commit
touch .scmversion

if [ ${BUILD_NATIVE:0} -eq 0 ] ; then
    export ARCH=arm64
    export CROSS_COMPILE=aarch64-linux-gnu-
fi

patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-3.12.patch
# Patches for misc fixes
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-Bluetooth-allocate-static-minor-for-vhci.patch

cp ${basedir}/../kernel-configs/pine64.config .config
cp .config ../pine64.config
test -e ${basedir}/root/usr/src/kernel/arch/arm64/boot/dts/sun50i-a64-pine64-plus.dts || \
		curl -sSL https://github.com/longsleep/build-pine64-image/raw/master/blobs/pine64.dts > \
		${basedir}/root/usr/src/kernel/arch/arm64/boot/dts/sun50i-a64-pine64-plus.dts
cp -a ${basedir}/root/usr/src/kernel ${basedir}/
cd ${basedir}/kernel/

debug "building kernel"
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root
kver=$( make kernelrelease )

cp arch/arm64/boot/Image ${basedir}/bootp/
cp arch/arm64/boot/dts/sun50i-a64-*.dtb ${basedir}/bootp/
cd ${basedir}/root/usr/src/kernel
make modules_prepare
cd ${basedir}

cat << EOF > ${basedir}/bootp/mkuinitrd
#!/bin/bash
if [ -a /boot/initrd.img-\$(uname -r) ] ; then
    update-initramfs -u -k \$(uname -r)
else
    update-initramfs -c -k \$(uname -r)
fi
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-\$(uname -r) /boot/uInitrd
EOF

cat << EOF > ${basedir}/bootp/uEnv.txt
kernel_filename=Image
initrd_filename=initrd.img-${kver}
fdt_filename_prefix=sun50i-a64-
console=tty0 console=ttyS0,115200n8 no_console_suspend disp.screen0_output_mode=EDID
optargs=disp.screen0_output_mode=1080p60
EOF

debug "fetching firmware"
rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

# Now, to make sure we're working properly, we need an initramfs
# Hack...
debug "building initrd"
mount --bind ${basedir}/bootp ${basedir}/root/boot
cat << EOF > ${basedir}/root/create-initrd
#!/bin/bash
update-initramfs -c -k ${kver}
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-${kver} /boot/uInitrd
rm -f /create-initrd
rm -f /usr/bin/qemu-*
EOF
chmod +x ${basedir}/root/create-initrd
LANG=C chroot ${basedir}/root /create-initrd
umount ${basedir}/root/boot

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice

# We need to work on the uboot helper script, probably by modifying this
# https://raw.githubusercontent.com/longsleep/build-pine64-image/master/simpleimage/platform-scripts/pine64_update_uboot.sh
# so for now....

debug "calling external script for pine64_update_uboot"

bash ${basedir}/../misc/pine64/pine64_update_uboot.sh $loopdevice

losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Clean up the build system"
debug ""
rm -rf ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/patches ${basedir}/u-boot

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-pine64.img"
sha1sum kali-$1-pine64.img > ${basedir}/kali-$1-pine64.img.sha1sum
# Don't xz on 32bit, there isn't enough memory to compress the images.
if [ -z "${MACHINE_TYPE##*64*}" ]; then
    echo "Compressing kali-$1-pine64.img"
    pixz ${basedir}/kali-$1-pine64.img ${basedir}/kali-$1-pine64.img.xz
    if [ $? ] ; then
	echo "Deleting kali-$1-pine64.img"
	rm ${basedir}/kali-$1-pine64.img
    fi
    echo "Generating sha1sum for kali-$1-pine64.img"
    sha1sum kali-$1-pine64.img.xz > ${basedir}/kali-$1-pine64.img.xz.sha1sum
fi
