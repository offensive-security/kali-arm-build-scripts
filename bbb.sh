#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/beaglebone-black-$1

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/news/kali-linux-metapackages/ for meta packages you
# can use. You can also install packages, using just the package name, but keep
# in mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="e2fsprogs initramfs-tools kali-defaults kali-menu parted sudo usbutils firmware-linux firmware-realtek firmware-atheros firmware-libertas"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="iceweasel udhcpd xfce4-terminal wpasupplicant"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
if [ $0 == 'nightly' ]; then
    debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali
else
    debootstrap --foreign --arch $architecture kali-last-snapshot kali-$architecture http://$mirror/kali
fi

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C systemd-nspawn -M bbb -D kali-$architecture /debootstrap/debootstrap --second-stage

if [ $0 == 'nightly' ]; then
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF
else
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-last-snapshot main contrib non-free
EOF
fi

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

auto usb0
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

cat << 'EOF' > kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service
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
chmod 644 kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service

cat << EOF > kali-$architecture/third-stage
#!/bin/bash
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get --yes --allow-change-held-packages install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --allow-change-held-packages install $packages
if [ $? > 0 ];
then
    apt-get --yes --allow-change-held-packages --fix-broken install
fi
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove

echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C systemd-nspawn -M bbb -D kali-$architecture /third-stage

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
LANG=C systemd-nspawn -M bbb -D kali-$architecture /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for Beaglebone Black"
dd if=/dev/zero of=${basedir}/kali-linux-$1-bbb.img bs=1M count=7000
parted kali-linux-$1-bbb.img --script -- mklabel msdos
parted kali-linux-$1-bbb.img --script -- mkpart primary fat32 2048s 264191s
parted kali-linux-$1-bbb.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-linux-$1-bbb.img`
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

echo "Setting up modules.conf"
# rm the symlink if it exists, and the original files if they exist
rm ${basedir}/root/etc/modules
rm ${basedir}/root/etc/modules-load.d/modules.conf
cat << EOF > ${basedir}/root/etc/modules-load.d/modules.conf
g_ether
EOF

# Uncomment this if you use apt-cacher-ng or else git clones will fail.
#unset http_proxy

git clone https://github.com/beagleboard/linux -b 4.9 --depth 1 ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ../kernel-at-commit
export ARCH=arm
# Edit the CROSS_COMPILE variable as needed.
export CROSS_COMPILE=arm-linux-gnueabihf-
touch .scmversion
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-4.9.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
make bb.org_defconfig
make -j $(grep -c processor /proc/cpuinfo)
cp arch/arm/boot/zImage ${basedir}/bootp/zImage
mkdir -p ${basedir}/bootp/dtbs
cp arch/arm/boot/dts/*.dtb ${basedir}/bootp/dtbs/
make INSTALL_MOD_PATH=${basedir}/root modules_install
cd ${basedir}

# Create uEnv.txt file
cat << EOF > ${basedir}/bootp/uEnv.txt
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

cat << EOF > ${basedir}/root/etc/fstab
/dev/mmcblk0p2 / auto errors=remount-ro 0 1
/dev/mmcblk0p1 /boot auto defaults 0 0
EOF

mkdir -p ${basedir}/root/etc/X11/
cat << EOF > ${basedir}/root/etc/X11/xorg.conf
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

cd ${basedir}/root/usr/src/kernel
make INSTALL_MOD_PATH=${basedir}/root firmware_install
make mrproper
make bb.org_defconfig
make modules_prepare
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

# Unused currently, but this script is a part of using the usb as an ethernet
# device.
wget -c https://raw.github.com/RobertCNelson/tools/master/scripts/beaglebone-black-g-ether-load.sh -O ${basedir}/root/root/beaglebone-black-g-ether-load.sh
chmod +x ${basedir}/root/root/beaglebone-black-g-ether-load.sh

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/root/etc/ssh/sshd_config

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice


# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/patches ${basedir}/kernel

# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-linux-$1-bbb.img"
pixz ${basedir}/kali-linux-$1-bbb.img ${basedir}/../kali-linux-$1-bbb.img.xz
rm ${basedir}/kali-linux-$1-bbb.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}

