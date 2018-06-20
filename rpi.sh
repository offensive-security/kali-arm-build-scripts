#!/bin/bash
set -e
# This is the Raspberry Pi Kali ARM build script - https://www.kali.org/downloads
# A trusted Kali Linux image created by Offensive Security - https://www.offensive-security.com

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0, and (if you want) a hostname, default is kali"
    exit 0
fi

basedir=`pwd`/rpi-$1
workfile=$1
kaliname=kali

if [ $2 ]; then
    kalname=$2
fi

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils u-boot-tools"
base="kali-menu kali-defaults initramfs-tools sudo parted e2fsprogs usbutils"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali kali-desktop-xfce kali-root-login gtk3-engines-xfce lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev xserver-xorg-input-evdev xserver-xorg-input-synaptics"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc nmap ethtool usbutils"
services="openssh-server apache2"
extras="iceweasel xfce4-terminal wpasupplicant"
# kernel sauces take up space
size=7000 # Size of image in megabytes

# Git commit hash to check out for the kernel
#kernel_commit=20fe468

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armel"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.

if debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali
then
  echo "[*] Boostrap Success"
else
  echo "[*] Boostrap Failure"
  exit 1
fi

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

if LANG=C systemd-nspawn -M rpi -D kali-$architecture /debootstrap/debootstrap --second-stage
then
  echo "[*] Secondary Boostrap Success"
else
  echo "[*] Secondary Boostrap Failure"
  exit 1
fi

cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

# Set hostname
echo "${kaliname}" > kali-$architecture/etc/hostname
# So X doesn't complain, we add kali to hosts
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       ${kaliname}    localhost
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

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/lib/systemd/system/regenerate_ssh_host_keys.service
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

cat << EOF > kali-$architecture/lib/systemd/system/rpiwiggle.service
[Unit]
Description=Resize filesystem
Before=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
ExecStart=/root/scripts/rpi-wiggle.sh
ExecStartPost=/bin/systemctl disable rpiwiggle
[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-$architecture/lib/systemd/system/rpiwiggle.service

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
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Resize FS on first run (hopefully)
systemctl enable rpiwiggle

# Generate SSH host keys on first-ish run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*

rm -f /third-stage
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

chmod +x kali-$architecture/third-stage

if LANG=C systemd-nspawn -M rpi -D kali-$architecture /third-stage
then
  echo "[*] Boostrap Success"
else
  echo "[*] Boostrap Failure"
  exit 1
fi

#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for Raspberry Pi"
dd if=/dev/zero of=${basedir}/kali-linux-$workfile-rpi.img bs=1M count=$size
parted kali-linux-$workfile-rpi.img --script -- mklabel msdos
parted kali-linux-$workfile-rpi.img --script -- mkpart primary fat32 0 64
parted kali-linux-$workfile-rpi.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-linux-$workfile-rpi.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
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

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt100" >> ${basedir}/root/etc/inittab

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/raspberrypi/linux -b rpi-4.4.y ${basedir}/root/usr/src/kernel
git clone --depth 1 https://github.com/raspberrypi/tools ${basedir}/tools

cd ${basedir}/root/usr/src/kernel
git checkout $kernel_commit
echo $kernel_commit > ../kernel-at-commit
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-4.4.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=${basedir}/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/rpi-4.4.config .config
cp ${basedir}/../kernel-configs/rpi-4.4.config ../rpi-4.4.config
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root
git clone --depth 1 https://github.com/raspberrypi/firmware.git rpi-firmware
cp -rf rpi-firmware/boot/* ${basedir}/bootp/
rm -rf rpi-firmware
# Because of device trees being used we need to go back to using mkknlimg :(
#cp arch/arm/boot/zImage ${basedir}/bootp/kernel.img
perl scripts/mkknlimg --dtok arch/arm/boot/zImage ${basedir}/bootp/kernel.img
mkdir -p ${basedir}/bootp/overlays/
cp arch/arm/boot/dts/*.dtb ${basedir}/bootp/
# Not used for now, but here for the future where they will be required.
#cp arch/arm/boot/dts/overlays/*.dtb ${basedir}/bootp/overlays/
rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}/root/usr/src/kernel
make INSTALL_MOD_PATH=${basedir}/root firmware_install
make mrproper
cp ../rpi-4.4.config .config
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

# Create cmdline.txt file
cat << EOF > ${basedir}/bootp/cmdline.txt
dwc_otg.lpm_enable=0 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 elevator=deadline root=/dev/mmcblk0p2 rootfstype=ext4 rootwait net.ifnames=0
EOF

# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
cat << EOF > ${basedir}/root/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc /proc proc nodev,noexec,nosuid 0  0
/dev/mmcblk0p2  / ext4 errors=remount-ro 0 1
# Change this if you add a swap partition or file
#/dev/SWAP none swap sw 0 0
/dev/mmcblk0p1 /boot vfat noauto 0 0
EOF

# rpi-wiggle
mkdir -p ${basedir}/root/root/scripts
wget https://raw.github.com/offensive-security/rpiwiggle/master/rpi-wiggle -O ${basedir}/root/root/scripts/rpi-wiggle.sh
chmod 755 ${basedir}/root/scripts/rpi-wiggle.sh

cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice
losetup -d $loopdevice

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha256sum or to compress the image, since you will be testing it
# soon.
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-linux-$workfile-rpi.img"
pixz ${basedir}/kali-linux-$workfile-rpi.img ${basedir}/kali-linux-$workfile-rpi.img.xz
mv ${basedir}/kali-linux-$workfile-rpi.img.xz ${basedir}/../
rm ${basedir}/kali-linux-$workfile-rpi.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf ${basedir}
