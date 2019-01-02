#!/bin/bash
set -e

# This is the HardKernel ODROID XU3 Kali ARM build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/odroidxu3-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-odroidxu3}
# Size of image in megabytes (Default is 7000=7GB)
size=7000
# Suite to use.
# Valid options are:
# kali-rolling, kali-dev, kali-bleeding-edge, kali-dev-only, kali-experimental, kali-last-snapshot
# A release is done against kali-last-snapshot, but if you're building your own, you'll probably want to build
# kali-rolling.
suite=kali-rolling

# Generate a random machine name to be used.
machine=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

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
base="apt-utils kali-defaults e2fsprogs ifupdown initramfs-tools kali-defaults kali-menu parted sudo usbutils firmware-linux firmware-atheros firmware-libertas firmware-realtek"
desktop="kali-menu fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="firefox-esr xfce4-terminal wpasupplicant"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p "${basedir}"
cd "${basedir}"

# create the rootfs - not much to modify here, except maybe throw in some more packages if you want.
debootstrap --foreign --keyring=/usr/share/keyrings/kali-archive-keyring.gpg --include=kali-archive-keyring --arch ${architecture} ${suite} kali-${architecture} http://${mirror}/kali

LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /debootstrap/debootstrap --second-stage

mkdir -p kali-${architecture}/etc/apt/
cat << EOF > kali-${architecture}/etc/apt/sources.list
deb http://${mirror}/kali ${suite} main contrib non-free
EOF

# Set hostname
echo "${hostname}" > kali-${architecture}/etc/hostname

# So X doesn't complain, we add $hostname to hosts
cat << EOF > kali-${architecture}/etc/hosts
127.0.0.1       ${hostname}    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

mkdir -p kali-${architecture}/etc/network/
cat << EOF > kali-${architecture}/etc/network/interfaces
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

mkdir -p kali-${architecture}/lib/systemd/system/
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


export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

cat << EOF > kali-${architecture}/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-${architecture}/third-stage
#!/bin/bash
set -e
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
# This looks weird, but we do it twice because every so often, there's a failure to download from the mirror
# So to workaround it, we attempt to install them twice.
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove

# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

# Copy bashrc
cp  /etc/skel/.bashrc /root/.bashrc

rm /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod 755 kali-${architecture}/third-stage
LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /third-stage

cat << EOF > kali-${architecture}/cleanup
#!/bin/bash
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*
EOF

chmod 755 kali-${architecture}/cleanup
LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Serial console settings.
# (Auto login on serial console)
#T1:12345:respawn:/sbin/agetty 115200 ttySAC2 vt100 >> "${basedir}"/kali-${architecture}/etc/inittab
# (No auto login)
#T1:12345:respawn:/bin/login -f root ttySAC2 /dev/ttySAC2 2>&1' >> "${basedir}"/kali-${architecture}/etc/inittab
# Make sure ttySAC1 is in root/etc/securetty so root can login on serial console.
echo 'T1:12345:respawn:/bin/login -f root ttySAC2 /dev/ttySAC2 2>&1' >> "${basedir}"/kali-${architecture}/etc/inittab

cat << EOF >> "${basedir}"/kali-${architecture}/etc/udev/links.conf
M   ttySAC2 c 5 1
EOF

cat << EOF >> "${basedir}"/kali-${architecture}/etc/securetty
ttySAC0
ttySAC1
ttySAC2
EOF

cat << EOF > "${basedir}"/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/hardkernel/linux.git -b odroidxu4-4.14.y "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
git rev-parse HEAD > "${basedir}"/kali-${architecture}/usr/src/kernel-at-commit
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/kali-wifi-injection-4.14.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
make odroidxu4_defconfig
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cp arch/arm/boot/zImage "${basedir}"/kali-${architecture}/boot
cp arch/arm/boot/dts/exynos5422-odroidxu3.dtb "${basedir}"/kali-${architecture}/boot
cp arch/arm/boot/dts/exynos5422-odroidxu3-lite.dtb "${basedir}"/kali-${architecture}/boot
cp arch/arm/boot/dts/exynos5422-odroidxu4.dtb "${basedir}"/kali-${architecture}/boot
cp arch/arm/boot/dts/exynos5422-odroidxu4-kvm.dtb "${basedir}"/kali-${architecture}/boot
make mrproper
make odroidxu4_defconfig
cd "${basedir}"

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls "${basedir}"/kali-${architecture}/lib/modules/)
cd "${basedir}"/kali-${architecture}/lib/modules/${kernver}
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source
cd "${basedir}"

cat << EOF > "${basedir}"/kali-${architecture}/boot/boot.ini
ODROIDXU-UBOOT-CONFIG

# U-Boot Parameters
setenv initrd_high "0xffffffff"
setenv fdt_high "0xffffffff"

# Mac address configuration
setenv macaddr "00:1e:06:61:7a:39"

#------------------------------------------------------------------------------------------------------
# Basic Ubuntu Setup. Don't touch unless you know what you are doing.
# --------------------------------
setenv bootrootfs "console=tty1 console=ttySAC2,115200n8 root=/dev/mmcblk0p2 rootwait rootfstype=ext4 net.ifnames=0 rw"

# boot commands
# Uncomment the following if you use an initrd
#setenv bootcmd "fatload mmc 0:1 0x40008000 zImage; fatload mmc 0:1 0x42000000 uInitrd; fatload mmc 0:1 0x44000000 exynos5422-odroidxu3.dtb; bootz 0x40008000 0x42000000 0x44000000"
# Uncomment the following if you do NOT use an initrd
setenv bootcmd "fatload mmc 0:1 0x40008000 zImage; fatload mmc 0:1 0x42000000 uInitrd; fatload mmc 0:1 0x44000000 exynos5422-odroidxu3.dtb; bootz 0x40008000 - 0x44000000"

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

cd "${basedir}"

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

# Create the disk and partition it
echo "Creating image file ${imagename}.img"
dd if=/dev/zero of="${basedir}"/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary fat32 3072s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat ${bootp}
mkfs.ext4 -O ^flex_bg -O ^metadata_csum ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p "${basedir}"/root
mount ${rootp} "${basedir}"/root
mkdir -p "${basedir}"/root/boot
mount ${bootp} "${basedir}"/root/boot

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

echo "Rsyncing rootfs into image file"
rsync -HPavz -q "${basedir}"/kali-${architecture}/ "${basedir}"/root/

# Write the signed u-boot binary to the image so that it will boot.
cd "${basedir}"
git clone https://github.com/hardkernel/u-boot.git -b odroidxu4-v2017.05
cd "${basedir}"/u-boot
make odroid-xu4_defconfig
make
cd sd_fuse
sh sd_fusing.sh ${loopdevice}
cd "${basedir}"

# Unmount partitions
sync
umount ${bootp}
umount ${rootp}
kpartx -dv ${loopdevice}

losetup -d ${loopdevice}

# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing ${imagename}.img"
pixz "${basedir}"/${imagename}.img "${basedir}"/../${imagename}.img.xz
rm "${basedir}"/${imagename}.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf "${basedir}"
