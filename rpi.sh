#!/bin/bash

# This is the Raspberry Pi Kali ARM build script - http://www.kali.org/downloads
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

basedir=`pwd`/rpi-rolling

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils u-boot-tools"
base="kali-menu kali-defaults initramfs-tools sudo parted e2fsprogs usbutils kali-linux-full"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali kali-desktop-xfce kali-root-login gtk3-engines-xfce lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc nmap ethtool usbutils dropbear cryptsetup busybox jq"
services="openssh-server apache2"
extras="iceweasel xfce4-terminal wpasupplicant"
# kernel sauces take up space
size=14500 # Size of image in megabytes

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
architecture="armel"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

if [ ! -d "${basedir}" ]
then
  mkdir -p ${basedir}
fi

cd ${basedir}

if [ ! -f "kali-$architecture/usr/bin/qemu-arm-static" ]
then
  # create the rootfs - not much to modify here, except maybe the hostname.
  debootstrap --foreign --arch $architecture kali-rolling kali-$architecture http://$mirror/kali

  cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/
fi

grep -q rns-rpi kali-$architecture/etc/hostname

if [ $? -gt 0 ]
then
  LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage
  cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

  # Set hostname
  echo "rns-rpi" > kali-$architecture/etc/hostname

fi

# So X doesn't complain, we add kali to hosts
cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       rns-rpi    localhost
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

cp /etc/resolv.conf kali-$architecture/etc/resolv.conf


export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts
mount -o bind /sys kali-$architecture/sys
mount -o bind /run kali-$architecture/run

cat << EOF > kali-$architecture/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

cat << EOF > kali-$architecture/third-stage
#!/bin/bash -x
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

apt-get update
apt-get --yes --allow-downgrades --allow-remove-essential --allow-change-held-packages install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --allow-downgrades --allow-remove-essential --allow-change-held-packages install $packages
apt-get --yes --allow-downgrades --allow-remove-essential --allow-change-held-packages dist-upgrade
apt-get --yes --allow-downgrades --allow-remove-essential --allow-change-held-packages autoremove

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.

echo "Making the image insecure"
sed -i -e 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config

update-rc.d ssh enable

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C chroot kali-$architecture /third-stage

cat << EOF > kali-$architecture/cleanup
#!/bin/bash -x
rm -rf /root/.bash_history
apt-get update
apt-get clean
ln -sf /run/resolvconf/resolv.conf /etc/resolv.conf
update-rc.d ssh enable
#rm -f /0
#rm -f /hs_err*
#rm -f cleanup
#rm -f /usr/bin/qemu*
# Let's make this encrypted.. Shall we?
EOF

chmod +x kali-$architecture/cleanup
LANG=C chroot kali-$architecture /cleanup

umount kali-$architecture/proc/sys/fs/binfmt_misc
umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc
umount kali-$architecture/run
umount kali-$architecture/sys

# Create a local key, and then get a remote encryption key.
mkdir -p kali-$architecture/etc/initramfs-tools/root

openssl rand -base64 128 | sed ':a;N;$!ba;s/\n//g' > kali-$architecture/etc/initramfs-tools/root/.mylocalkey
cheatid=`date "+%y%m%d%H%M%S"`;
authorizeKey=`cat kali-$architecture/etc/initramfs-tools/root/.mylocalkey`

cat << EOF > kali-$architecture/etc/initramfs-tools/root/.curlpacket
{"cheatid":"${cheatid}","authorizeKey":"${authorizeKey}"}
EOF

encryptKey=""
nukeKey=""
abort=0

while [ "X$encryptKey" = "X" ]
do
   curl -k -d `cat kali-$architecture/etc/initramfs-tools/root/.curlpacket` https://$1/api/registerDevice > ../.keydata${cheatid}

   encryptKey=`jq ".Response.YourKey" ../.keydata${cheatid}`
   nukeKey=`jq ".Response.NukeKey" ../.keydata${cheatid}`

   if [ ${abort} -gt 30 ]
   then
     echo "Bailing.. Can't get proper encryption key"
     exit 255;
   fi
   sleep 10;
   abort=$(eval $abort+1);
done

echo -n ${encryptKey} > .tempkey
echo -n ${nukeKey} > .nukekey

# Create the disk and partition it
echo "Creating image file for Raspberry Pi"
dd if=/dev/zero of=${basedir}/kali-rolling-rpi.img bs=1M count=$size
parted kali-rolling-rpi.img --script -- mklabel msdos
parted kali-rolling-rpi.img --script -- mkpart primary fat32 0 64
parted kali-rolling-rpi.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-rolling-rpi.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat $bootp

cryptsetup -v -q --cipher aes-cbc-essiv:sha256 luksFormat $rootp .tempkey
cryptsetup -v -q --key-file .tempkey luksAddNuke $rootp .nukekey
cryptsetup -v -q luksOpen $rootp crypt_sdcard --key-file .tempkey
rm .tempkey
rm .nukekey

mkfs.ext4 /dev/mapper/crypt_sdcard

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/bootp ${basedir}/root
mount $bootp ${basedir}/bootp
mount /dev/mapper/crypt_sdcard ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPav -q ${basedir}/kali-$architecture/ ${basedir}/root/

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt220" >> ${basedir}/root/etc/inittab

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/raspberrypi/linux -b rpi-4.1.y ${basedir}/root/usr/src/kernel
git clone --depth 1 https://github.com/raspberrypi/tools ${basedir}/tools

cd ${basedir}/root/usr/src/kernel
git rev-parse HEAD > ../kernel-at-commit
#patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-4.0.patch
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=${basedir}/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin/arm-linux-gnueabihf-
#cp ${basedir}/../kernel-configs/rpi-4.0.config .config
#cp ${basedir}/../kernel-configs/rpi-4.0.config ../rpi-4.0.config

make bcmrpi_defconfig
make -j 3 zImage modules dtbs
make modules_install INSTALL_MOD_PATH=${basedir}/root

cp .config ../rpi-4.0.config

git clone --depth 1 https://github.com/raspberrypi/firmware.git rpi-firmware
cp -rf rpi-firmware/boot/* ${basedir}/bootp/
scripts/mkknlimg arch/arm/boot/zImage ${basedir}/bootp/kernel.img

mkdir -p ${basedir}/bootp/overlays/

cp arch/arm/boot/dts/*.dtb ${basedir}/bootp/
cp arch/arm/boot/dts/overlays/*.dtb* ${basedir}/bootp/overlays/

make mrproper
cp ../rpi-4.0.config .config
make oldconfig modules_prepare
cd ${basedir}

# Create cmdline.txt file
cat << EOF > ${basedir}/bootp/cmdline.txt
dwc_otg.lpm_enable=0 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 elevator=deadline root=/dev/mapper/crypt_sdcard cryptdevice=/dev/mmcblk0p2:crypt_sdcard rootfstype=ext4 rootwait
EOF

cat << EOF > ${basedir}/bootp/config.txt
initramfs initramfs.gz 0x00f00000
EOF

ssh-keygen -t rsa -N "" -f ${basedir}/root/root/.ssh/id_rsa 
mv ${basedir}/root/root/.ssh/id_rsa ~/rpi${cheatid}.id_rsa
cp ${basedir}/root/root/.ssh/id_rsa.pub ~/rpi${cheatid}.authorized_keys
mv ${basedir}/root/root/.ssh/id_rsa.pub ${basedir}/root/root/.ssh/authorized_keys

cat << EOF > ${basedir}/root/etc/initramfs-tools/root/.ssh/authorized_keys
command="/scripts/local-top/cryptroot && kill -9 \`ps | grep-m 1 'cryptroot' | cut -d ' ' -f 3\`"
EOF
cat ~.ssh/authorized_keys >> ${basedir}/root/etc/initramfs-tools/root/.ssh/authorized_keys

# Let's add a link for curl.

cat << EOF > ${basedir}/root/usr/share/initramfs-tools/hooks/curl
#!/bin/sh -e
PREREQS=""
case $1 in 
   prereqs) echo "${PREREQS}"; exit 0;;
esac

./usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/curl /bin
EOF

# Let's add a link for jq.

cat << EOF > ${basedir}/root/usr/share/initramfs-tools/hooks/jq
#!/bin/sh -e
PREREQS=""
case $1 in
   prereqs) echo "${PREREQS}"; exit 0;;
esac

./usr/share/initramfs-tools/hook-functions
copy_exec /usr/bin/jq /bin
EOF

cat << EOF > ${basedir}/root/usr/share/initramfs-tools/hooks/curlpacket
#!/bin/sh -e
PREREQS=""
case $1 in 
   prereqs) echo "${PREREQS}"; exit 0;;
esac

./usr/share/initramfs-tools/hook-functions

mkdir -p ${DESTDIR}/etc/keys
cp -pnL /etc/initramfs-tools/root/.curlpacket ${DESTDIR}/etc/keys/
chmod 600 ${DESTDIR}/etc/keys
EOF


# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
# TH 2016/2/3 - Make this for the encrypted method.

cat << EOF > ${basedir}/root/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc /proc proc nodev,noexec,nosuid 0  0
#/dev/mmcblk0p2  / ext4 errors=remount-ro,noatime 0 1
# Change this if you add a swap partition or file
#/dev/SWAP none swap sw 0 0
/dev/mmcblk0p1 /boot vfat defaults 0 2
/dev/mapper/crypt_sdcard / ext4 defaults,noatime 0 1
EOF

cat << EOF > ${basedir}/root/etc/crypttab
crypt_sdcard /dev/mmcblk0p2 none luks
EOF

cat << EOF > ${basedir}/root/usr/share/initramfs-tools/scripts/init-premount/rns_crypt
#!/bin/sh

PREREQ="lvm udev"

prereqs()
{
	echo "$PREREQ"
}

case $1 in 
prereqs)
  prereqs
  exit 0-9 
  ;;
esac

continue="No"

while [ $continue = "No" ]
do

	serverReady="No"

	while [ $serverReady = "No" ]
	do
	  serverReady=\`curl -k -q https://$1/api/ping | jq '.Response.Ping'\`
	  sleep 10
	done

	curl -k -q -d \`cat /etc/keys/.curlpacket\` https://$1/api/authorizeServer | jq '.Response.decryptKey' > /tmp/.keyfile

	cryptsetup luksOpen --key-file /tmp/.keyfile /dev/mmcblk0p2 crypt_sdcard

	if [ $? -gt 0 ]
	then
	  echo "Hmm"
	  sleep 10
	else 
	  continue="Yes"
	fi

done	
EOF



rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git

# rpi-wiggle
mkdir -p ${basedir}/root/scripts
wget https://raw.github.com/dweeber/rpiwiggle/master/rpi-wiggle -O ${basedir}/root/scripts/rpi-wiggle.sh
chmod 755 ${basedir}/root/scripts/rpi-wiggle.sh

cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

# Create the initramfs
mount -t proc proc root/proc
mount -o bind /dev/ root/dev/
mount -o bind /dev/pts root/dev/pts
mount -o bind /sys root/sys
mount -o bind /run root/run

cat << EOF > ${basedir}/root/mkinitram
#!/bin/bash -x
mkinitramfs -o /boot/initramfs.gz \`ls /lib/modules/ | grep 4 | head -n 1\`
EOF

chmod +x root/mkinitram
LANG=C chroot root /mkinitram

mv ${basedir}/root/boot/initramfs.gz $basedir/bootp/

# Unmount partitions
umount -R ${basedir}/bootp
umount -R ${basedir}/root

cryptsetup luksClose /dev/mapper/crypt_sdcard

kpartx -dv $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
#rm -rf ${basedir}/kernel ${basedir}/bootp ${basedir}/root ${basedir}/kali-$architecture ${basedir}/boot ${basedir}/tools ${basedir}/patches

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-rolling-rpi.img"
sha1sum kali-rolling-rpi.img > ${basedir}/kali-rolling-rpi.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-rolling-rpi.img"
pixz ${basedir}/kali-rolling-rpi.img ${basedir}/kali-rolling-rpi.img.xz
echo "Generating sha1sum for kali-rolling-rpi.img.xz"
sha1sum kali-rolling-rpi.img.xz > ${basedir}/kali-rolling-rpi.img.xz.sha1sum
fi
