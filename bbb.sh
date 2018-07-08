#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/beaglebone-black-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-bbb}
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

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/news/kali-linux-metapackages/ for meta packages you
# can use. You can also install packages, using just the package name, but keep
# in mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="apt-utils kali-defaults e2fsprogs ifupdown initramfs-tools kali-defaults kali-menu parted sudo usbutils firmware-linux firmware-realtek firmware-atheros firmware-libertas"
desktop="kali-menu fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="iceweasel udhcpd xfce4-terminal wpasupplicant"

packages="${arm} ${base} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe throw in some more packages if you want.
debootstrap --foreign --variant minbase --keyring=/usr/share/keyrings/kali-archive-keyring.gpg --include=kali-archive-keyring --arch ${architecture} ${suite} kali-${architecture} http://${mirror}/kali

cp /usr/bin/qemu-arm-static kali-${architecture}/usr/bin/

LANG=C systemd-nspawn -M $machine -D kali-${architecture} /debootstrap/debootstrap --second-stage

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

auto usb0
iface usb0 inet static
    address 192.168.7.2
    netmask 255.255.255.0
    network 192.168.7.0
    gateway 192.168.7.1
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

echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Resize FS on first run (hopefully)
systemctl enable rpiwiggle

# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

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

# Enable serial console on ttyO0
echo 'T1:12345:respawn:/sbin/agetty 115200 ttyO0 vt100' >> ${basedir}/kali-${architecture}/etc/inittab

cat << EOF >> ${basedir}/kali-${architecture}/etc/udev/links.conf
M   ttyO0 c 5 1
EOF

cat << EOF >> ${basedir}/kali-${architecture}/etc/securetty
ttyO0
EOF

cat << EOF > ${basedir}/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

echo "Setting up modules.conf"
# rm the symlink if it exists, and the original files if they exist
rm ${basedir}/kali-${architecture}/etc/modules
rm ${basedir}/kali-${architecture}/etc/modules-load.d/modules.conf
cat << EOF > ${basedir}/kali-${architecture}/etc/modules-load.d/modules.conf
g_ether
EOF

# Uncomment this if you use apt-cacher-ng or else git clones will fail.
#unset http_proxy

git clone https://github.com/beagleboard/linux -b 4.9 --depth 1 ${basedir}/kali-${architecture}/usr/src/kernel
cd ${basedir}/kali-${architecture}/usr/src/kernel
git rev-parse HEAD > ${basedir}/kali-${architecture}/usr/src/kernel-at-commit
export ARCH=arm
# Edit the CROSS_COMPILE variable as needed.
export CROSS_COMPILE=arm-linux-gnueabihf-
touch .scmversion
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-4.9.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
make bb.org_defconfig
make -j $(grep -c processor /proc/cpuinfo)
cp arch/arm/boot/zImage ${basedir}/kali-${architecture}/boot/zImage
mkdir -p ${basedir}/kali-${architecture}/boot/dtbs
cp arch/arm/boot/dts/*.dtb ${basedir}/kali-${architecture}/boot/dtbs/
make INSTALL_MOD_PATH=${basedir}/kali-${architecture} modules_install
make INSTALL_MOD_PATH=${basedir}/kali-${architecture} firmware_install
make mrproper
make bb.org_defconfig
make modules_prepare
cd ${basedir}

# Create uEnv.txt file
cat << EOF > ${basedir}/kali-${architecture}/boot/uEnv.txt
#u-boot eMMC specific overrides; Angstrom Distribution (BeagleBone Black) 2013-06-20
kernel_file=zImage
initrd_file=uInitrd
 
loadzimage=load mmc \${mmcdev}:\${mmcpart} \${loadaddr} \${kernel_file}
loadinitrd=load mmc \${mmcdev}:\${mmcpart} 0x81000000 \${initrd_file}; setenv initrd_size \${filesize}
loadfdt=load mmc \${mmcdev}:\${mmcpart} \${fdtaddr} /dtbs/\${fdtfile}
#
 
console=ttyO0,115200n8
mmcroot=/dev/mmcblk0p2 rw net.ifnames=0
mmcrootfstype=ext4 rootwait fixrtc
 
##To disable HDMI/eMMC...
#optargs=capemgr.disable_partno=BB-BONELT-HDMI,BB-BONELT-HDMIN,BB-BONE-EMMC-2G
 
##3.1MP Camera Cape
#optargs=capemgr.disable_partno=BB-BONE-EMMC-2G
 
mmcargs=setenv bootargs console=\${console} root=\${mmcroot} rootfstype=\${mmcrootfstype} \${optargs}
 
#zImage:
uenvcmd=run loadzimage; run loadfdt; run mmcargs; bootz \${loadaddr} - \${fdtaddr}
 
#zImage + uInitrd: where uInitrd has to be generated on the running system.
#boot_fdt=run loadzimage; run loadinitrd; run loadfdt
#uenvcmd=run boot_fdt; run mmcargs; bootz \${loadaddr} 0x81000000:\${initrd_size} \${fdtaddr}
EOF

cat << EOF > ${basedir}/kali-${architecture}/etc/fstab
/dev/mmcblk0p2 / auto errors=remount-ro 0 1
/dev/mmcblk0p1 /boot auto defaults 0 0
EOF

mkdir -p ${basedir}/kali-${architecture}/etc/X11/
cat << EOF > ${basedir}/kali-${architecture}/etc/X11/xorg.conf
Section "Monitor"
  Identifier    "Builtin Default Monitor"
EndSection

Section "Device"
  Identifier    "Builtin Default fbdev Device 0"
  Driver        "fbdev"
  Option        "SWCursor"  "true"
EndSection

Section "Screen"
  Identifier    "Builtin Default fbdev Screen 0"
  Device        "Builtin Default fbdev Device 0"
  Monitor       "Builtin Default Monitor"
  DefaultDepth  16
  # Comment out the above and uncomment the below if using a
  # bbb-view or bbb-exp
  #DefaultDepth 24
EndSection

Section "ServerLayout"
  Identifier    "Builtin Default Layout"
  Screen        "Builtin Default fbdev Screen 0"
EndSection
EOF

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls ${basedir}/kali-${architecture}/lib/modules/)
cd ${basedir}/kali-${architecture}/lib/modules/${kernver}
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source
cd ${basedir}

# Unused currently, but this script is a part of using the usb as an ethernet
# device.
wget -c https://raw.github.com/RobertCNelson/tools/master/scripts/beaglebone-black-g-ether-load.sh -O ${basedir}/kali-${architecture}/root/beaglebone-black-g-ether-load.sh
chmod 755 ${basedir}/kali-${architecture}/root/beaglebone-black-g-ether-load.sh

cp ${basedir}/../misc/zram ${basedir}/kali-${architecture}/etc/init.d/zram
chmod 755 ${basedir}/kali-${architecture}/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/kali-${architecture}/etc/ssh/sshd_config

# rpi-wiggle
mkdir -p ${basedir}/kali-${architecture}/root/scripts
wget https://raw.github.com/offensive-security/rpiwiggle/master/rpi-wiggle -O ${basedir}/kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 ${basedir}/kali-${architecture}/root/scripts/rpi-wiggle.sh

# Create the disk and partition it
echo "Creating image file for ${imagename}.img"
dd if=/dev/zero of=${basedir}/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary fat32 2048s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat -F 16 ${bootp}
mkfs.ext4 -O ^flex_bg -O ^metadata_csum ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/root
mount ${rootp} ${basedir}/root
mkdir -p ${basedir}/root/boot
mount ${bootp} ${basedir}/root/boot

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-${architecture}/ ${basedir}/root/

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
pixz ${basedir}/${imagename}.img ${basedir}/../${imagename}.img.xz
rm ${basedir}/${imagename}.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}