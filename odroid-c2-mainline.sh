#!/bin/bash
set -e

# This is the HardKernel ODROID C2 Kali ARM64 build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/odroidc2-mainline-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-odroidc2-mainline}
# Size of image in megabytes (Default is 5500=5.5GB)
size=5500
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
export CROSS_COMPILE=aarch64-linux-gnu-
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

# The package "fbset" is required to init the display.
# The video needs to be "kicked" before xorg starts, otherwise the video shows
# up in a weird state.
# DO NOT REMOVE IT FROM THE PACKAGE LIST.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils"
base="apt-transport-https apt-utils console-setup e2fsprogs firmware-linux firmware-realtek firmware-atheros firmware-libertas firmware-brcm80211 ifupdown initramfs-tools iw kali-defaults man-db mlocate netcat-traditional net-tools parted psmisc rfkill screen snmpd snmp sudo tftp tmux unrar usbutils vim wget zerofree"
desktop="kali-menu fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng crunch cewl dnsrecon dnsutils ethtool exploitdb hydra john libnfc-bin medusa metasploit-framework mfoc ncrack nmap passing-the-hash proxychains recon-ng sqlmap tcpdump theharvester tor tshark usbutils whois windows-binaries winexe wpscan wireshark"
services="apache2 atftpd openssh-server openvpn tightvncserver"
extras="fbset xfce4-terminal xfce4-goodies wpasupplicant libnss-systemd"
#kali="build-essential debhelper devscripts dput lintian quilt git-buildpackage gitk dh-make sbuild"

packages="${arm} ${base} ${services} ${extras} ${kali}"
architecture="arm64"
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

echo "${hostname}" > kali-${architecture}/etc/hostname

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

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-${architecture}/proc
#mount -o bind /dev/ kali-${architecture}/dev/
#mount -o bind /dev/pts kali-${architecture}/dev/pts

cat << EOF > kali-${architecture}/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
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

cat << EOF > kali-${architecture}/lib/systemd/system/rpiwiggle.service
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
chmod 644 kali-${architecture}/lib/systemd/system/rpiwiggle.service

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
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Resize FS on first run (hopefully)
systemctl enable rpiwiggle

# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

# Copy bashrc
cp  /etc/skel/.bashrc /root/.bashrc

rm -f /usr/sbin/policy-rc.d
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

#umount kali-${architecture}/proc/sys/fs/binfmt_misc
#umount kali-${architecture}/dev/pts
#umount kali-${architecture}/dev/
#umount kali-${architecture}/proc

cat << EOF > "${basedir}"/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
touch .scmversion
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
# We need to apply a "few" various fixes...  this is gonna take a while.
git apply "${basedir}"/../patches/mainline/0001-clk-meson-gxbb-set-fclk_div2-as-CLK_IS_CRITICAL.patch
git apply "${basedir}"/../patches/mainline/0002-ARM64-dts-meson-gxbb-nanopi-k2-Add-HDMI-CEC-and-CVBS.patch
git apply "${basedir}"/../patches/mainline/0003-drm-meson-Make-DMT-timings-parameters-and-pixel-cloc.patch
git apply "${basedir}"/../patches/mainline/0004-ARM64-defconfig-enable-CEC-support.patch
git apply "${basedir}"/../patches/mainline/0005-clk-meson-switch-gxbb-cts-amclk-div-to-the-generic-d.patch
git apply "${basedir}"/../patches/mainline/0006-clk-meson-remove-unused-clk-audio-divider-driver.patch
git apply "${basedir}"/../patches/mainline/0007-ASoC-meson-add-meson-audio-core-driver.patch
git apply "${basedir}"/../patches/mainline/0008-ASoC-meson-add-register-definitions.patch
git apply "${basedir}"/../patches/mainline/0009-ASoC-meson-add-aiu-i2s-dma-support.patch
git apply "${basedir}"/../patches/mainline/0010-ASoC-meson-add-initial-i2s-dai-support.patch
git apply "${basedir}"/../patches/mainline/0011-ASoC-meson-add-aiu-spdif-dma-support.patch
git apply "${basedir}"/../patches/mainline/0012-ASoC-meson-add-initial-spdif-dai-support.patch
git apply "${basedir}"/../patches/mainline/0013-ARM64-defconfig-enable-audio-support-for-meson-SoCs-.patch
git apply "${basedir}"/../patches/mainline/0014-ARM64-dts-meson-gx-add-audio-controller-nodes.patch
git apply "${basedir}"/../patches/mainline/0015-snd-meson-activate-HDMI-audio-path.patch
git apply "${basedir}"/../patches/mainline/0016-drm-meson-select-dw-hdmi-i2s-audio-for-meson-hdmi.patch
git apply "${basedir}"/../patches/mainline/0017-ARM64-dts-meson-gx-add-sound-dai-cells-to-HDMI-node.patch
git apply "${basedir}"/../patches/mainline/0018-ARM64-dts-meson-activate-hdmi-audio-HDMI-enabled-boa.patch
git apply "${basedir}"/../patches/mainline/0019-drm-bridge-dw-hdmi-Use-AUTO-CTS-setup-mode-when-non-.patch
git apply "${basedir}"/../patches/mainline/0020-drm-meson-Call-drm_crtc_vblank_on-drm_crtc_vblank_of.patch
git apply "${basedir}"/../patches/mainline/0021-media-platform-meson-ao-cec-make-busy-TX-warning-sil.patch
git apply "${basedir}"/../patches/mainline/90dc377aa5ed708a38a010e6861b468cd9373f4f.patch
# And now the two wifi related so we can do things.
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/kali-wifi-injection-4.16.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
# Now copy in the config file and then build this sucker
cp "${basedir}"/../kernel-configs/odroidc2-mainline.config .config
cp .config "${basedir}"/kali-${architecture}/usr/src/odroidc2-mainline.config
cd "${basedir}"/kali-${architecture}/usr/src/kernel/
rm -rf "${basedir}"/kali-${architecture}/usr/src/kernel/.git
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cp arch/arm64/boot/Image "${basedir}"/kali-${architecture}/boot/
cp arch/arm64/boot/dts/amlogic/meson-gxbb-odroidc2.dtb "${basedir}"/kali-${architecture}/boot/
cd "${basedir}"/kali-${architecture}/usr/src/kernel
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- mrproper
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

cd "${basedir}"

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

# rpi-wiggle
mkdir -p "${basedir}"/kali-${architecture}/root/scripts
wget https://raw.github.com/offensive-security/rpiwiggle/master/rpi-wiggle -O "${basedir}"/kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 "${basedir}"/kali-${architecture}/root/scripts/rpi-wiggle.sh

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

# For some reason, u-boot sees whatever boot media as mmc1 instead of mmc0.  So default to mmc 1 instead of mmc 0.
# As per usual, the kernel does the right thing, so the boot media is seen as mmcblk0.
cat << 'EOF' > "${basedir}"/kali-${architecture}/boot/boot.cmd
setenv loadaddr "0x20000000"
setenv dtb_loadaddr "0x01000000"
setenv initrd_high "0xffffffff"
setenv fdt_high "0xffffffff"
setenv kernel_filename Image
setenv fdt_filename meson-gxbb-odroidc2.dtb
setenv bootargs "root=/dev/mmcblk0p2 rootfstype=ext4 rootwait rw"
# Without an initramfs
setenv bootcmd "load ${devtype} ${devnum}:${partition} '${loadaddr}' '${kernel_filename}'; load ${devtype} ${devnum}:${partition} '${dtb_loadaddr}' '${fdt_filename}'; booti '${loadaddr}' - '${dtb_loadaddr}'"
# With an initramfs
# NOTE: EXPECTS THE INITRAMFS FILENAME TO BE "initramfs.gz"
# setenv bootcmd "load ${devtype} ${devnum}:${partition} '${loadaddr}' '${kernel_filename}'; load ${devtype} ${devnum}:${partition} '${dtb_loadaddr}' '${fdt_filename}'; load ${devtype} ${devnum}:${partition} ${ramdisk_addr_r} initramfs.gz; booti '${loadaddr}' ${ramdisk_addr_r}:${filesize} '${dtb_loadaddr}'"
boot
EOF

echo "Running du to see how big kali-${architecture} is"
du -sh "${basedir}"/kali-${architecture}
echo "the above is how big the sdcard needs to be"

# Some maths here... it's not magic, we just want the block size a certain way
# so that partitions line up in a way that's more optimal.
RAW_SIZE_MB=${size}
BLOCK_SIZE=1024
let RAW_SIZE=(${RAW_SIZE_MB}*1000*1000)/${BLOCK_SIZE}

# Create the disk and partition it
echo "Creating image file ${imagename}.img"
dd if=/dev/zero of="${basedir}"/${imagename}.img bs=${BLOCK_SIZE} count=0 seek=${RAW_SIZE}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary ext4 4096s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.ext4 -L boot ${bootp}
mkfs.ext4 -L rootfs ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p "${basedir}"/root
mount ${rootp} "${basedir}"/root
mkdir -p "${basedir}"/root/boot
mount ${bootp} "${basedir}"/root/boot

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

# u-boot sees the sdcard as mmc0, emmc as mmc1
# kernel sees the sdcard as mmcblk1, emmc as mmc0
# So we need to use the PARTUUID for the rootfs partition in order to boot, since
# we can't pass /dev/mmcblkXp2 for the rootdevice.  If an initramfs is used, this could probably be skipped
# by using the LABEL or UUID, but either way, here we go.
sed -i -e "s/root=\/dev\/mmcblk0p2/root=PARTUUID=$(blkid -s PARTUUID -o value ${rootp})/g" "${basedir}"/kali-${architecture}/boot/boot.cmd

# Let's cat the output of the file so we can make sure it's correct.
cat "${basedir}"/kali-${architecture}/boot/boot.cmd
# And NOW we can actually make it the boot.scr that is needed.
mkimage -A arm -T script -C none -d "${basedir}"/kali-${architecture}/boot/boot.cmd "${basedir}"/kali-${architecture}/boot/boot.scr

echo "Rsyncing rootfs into image file"
rsync -HPavz -q "${basedir}"/kali-${architecture}/ "${basedir}"/root/

# Unmount partitions
# Sync before unmounting to ensure everything is written
sync
umount -l ${bootp}
umount -l ${rootp}
kpartx -dv ${loopdevice}

# We are gonna use as much open source as we can here, hopefully we end up with a nice
# mainline u-boot and signed bootloader - unfortunately, due to the way this is packaged up
# we have to clone two different u-boot repositories - the one from HardKernel which
# has the bootloader binary blobs we need, and the denx mainline u-boot repository.
# Let the fun begin.

# Unset these because we're building on the host.
unset ARCH
unset CROSS_COMPILE

mkdir -p "${basedir}"/bootloader
cd "${basedir}"/bootloader
git clone https://github.com/afaerber/meson-tools --depth 1
git clone git://git.denx.de/u-boot --depth 1
git clone https://github.com/hardkernel/u-boot -b odroidc2-v2015.01 u-boot-hk --depth 1

# First things first, let's build the meson-tools, of which, we only really need amlbootsig
cd "${basedir}"/bootloader/meson-tools/
make
# Now we need to build fip_create
cd "${basedir}"/bootloader/u-boot-hk/tools/fip_create
HOSTCC=cc HOSTLD=ld make

cd "${basedir}"/bootloader/u-boot/
make ARCH=arm CROSS_COMPILE=aarch64-linux-gnu- odroid-c2_defconfig
make ARCH=arm CROSS_COMPILE=aarch64-linux-gnu-

# Now the real fun... keeping track of file locations isn't fun, and i should probably move them to 
# one single directory, but since we're not keeping these things around afterwards, it's fine to 
# leave them where they are.
# See:
# https://forum.odroid.com/viewtopic.php?t=26833
# https://github.com/nxmyoz/c2-overlay/blob/master/Readme.md
# for the inspirations for it.  Specifically Adrian's posts got us closest.

# This is funky, but in the end, it should do the right thing.
cd "${basedir}"/bootloader/
# Create the fip.bin
./u-boot-hk/tools/fip_create/fip_create --bl30 ./u-boot-hk/fip/gxb/bl30.bin \
--bl301 ./u-boot-hk/fip/gxb/bl301.bin --bl31 ./u-boot-hk/fip/gxb/bl31.bin \
--bl33 u-boot/u-boot.bin fip.bin

# Create the stage2 bootloader thingie?
cat ./u-boot-hk/fip/gxb/bl2.package fip.bin > boot_new.bin
# Now sign it, and call it u-boot.bin
./meson-tools/amlbootsig boot_new.bin u-boot.bin
# Now strip a portion of it off, and put it in the sd_fuse directory
dd if=u-boot.bin of=./u-boot-hk/sd_fuse/u-boot.bin bs=512 skip=96
# Finally, write it to the loopdevice so we have our bootloader on the card.
cd ./u-boot-hk/sd_fuse
./sd_fusing.sh ${loopdevice}
sync
cd "${basedir}"

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
echo "Cleaning up the temporary build files..."
rm -rf "${basedir}"