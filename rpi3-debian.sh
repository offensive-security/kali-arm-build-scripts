#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0, and (if you want) a hostname, default is kali"
    exit 0
fi

basedir=`pwd`/rpi3-debian-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-rpi3-debian}
# Size of image in megabytes (Default is 5000=5GB)
size=5000
# Suite to use.
# Valid options are:
# kali-rolling, kali-dev, kali-bleeding-edge, kali-dev-only, kali-experimental, kali-last-snapshot
# A release is done against kali-last-snapshot, but if you're building your own, you'll probably want to build
# kali-rolling.
suite=buster

# Generate a random machine name to be used.
machine=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="apt-transport-https apt-utils console-setup e2fsprogs firmware-linux firmware-realtek firmware-atheros firmware-libertas ifupdown initramfs-tools iw man-db mlocate netcat-traditional net-tools parted psmisc rfkill screen snmpd snmp sudo tftp tmux unrar usbutils vim wget zerofree"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gtk3-engines-xfce network-manager network-manager-gnome lightdm xfce4 xfce4-goodies xfce4-power-manager-plugins xfce4-terminal xserver-xorg-video-fbdev xserver-xorg-input-evdev xserver-xorg-input-synaptics"
tools="aircrack-ng crunch cewl dnsrecon dnsutils ethtool hydra john libnfc-bin medusa mfoc ncrack nmap proxychains recon-ng sqlmap tcpdump tor tshark usbutils whois wireshark"
services="apache2 atftpd openssh-server openvpn tightvncserver"
extras="bluez bluez-firmware firefox-esr i2c-tools python-configobj python-pip python-requests python-rpi.gpio python-smbus triggerhappy wpasupplicant xfce4-terminal xfonts-terminus"

packages="${arm} ${base} ${services} ${extras}"

architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=ftp.us.debian.org

mkdir -p "${basedir}"
cd "${basedir}"

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

# create the rootfs - not much to modify here, except maybe throw in some more packages if you want.
debootstrap --foreign --keyring=/usr/share/keyrings/debian-archive-keyring.gpg --include=debian-archive-keyring --arch ${architecture} ${suite} kali-${architecture} http://${mirror}/debian

LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /debootstrap/debootstrap --second-stage

mkdir -p kali-${architecture}/etc/apt/
cat << EOF > kali-${architecture}/etc/apt/sources.list
deb http://${mirror}/debian ${suite} main contrib non-free
EOF

# Set hostname
echo "${hostname}" > kali-${architecture}/etc/hostname

# So X doesn't complain, we add kali to hosts
cat << EOF > kali-${architecture}/etc/hosts
127.0.0.1       ${hostname}    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

mkdir -p kali-${architecture}/etc/modprobe.d/
cat << EOF > kali-${architecture}/etc/modprobe.d/ipv6.conf
# Don't load ipv6 by default
alias net-pf-10 off
#alias ipv6 off
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

mkdir -p kali-${architecture}/usr/lib/systemd/system/
cat << 'EOF' > kali-${architecture}/usr/lib/systemd/system/regenerate_ssh_host_keys.service
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
chmod 644 kali-${architecture}/usr/lib/systemd/system/regenerate_ssh_host_keys.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/smi-hack.service
[Unit]
Description=shared-mime-info update hack
Before=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c "dpkg-reconfigure shared-mime-info"
ExecStartPost=/bin/systemctl disable smi-hack

[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/smi-hack.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/rpiwiggle.service
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
chmod 644 kali-${architecture}/usr/lib/systemd/system/rpiwiggle.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/enable-ssh.service
[Unit]
Description=Turn on SSH if /boot/ssh is present
ConditionPathExistsGlob=/boot/ssh{,.txt}
After=regenerate_ssh_host_keys.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c "update-rc.d ssh enable && invoke-rc.d ssh start && rm -f /boot/ssh ; rm -f /boot/ssh.txt"

[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/enable-ssh.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/copy-user-wpasupplicant.service
[Unit]
Description=Copy user wpa_supplicant.conf
ConditionPathExists=/boot/wpa_supplicant.conf
Before=dhcpcd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mv /boot/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf
ExecStartPost=/bin/chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf

[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/copy-user-wpasupplicant.service

cat << EOF > "${basedir}"/kali-${architecture}/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

mkdir -p "${basedir}"/kali-${architecture}/usr/bin/
cat << 'EOF' > "${basedir}"/kali-${architecture}/usr/bin/monstart
#!/bin/bash
interface=wlan0mon
echo "Bring up monitor mode interface ${interface}"
iw phy phy0 interface add ${interface} type monitor
ifconfig ${interface} up
if [ $? -eq 0 ]; then
  echo "started monitor interface on ${interface}"
fi
EOF
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/monstart

cat << 'EOF' > "${basedir}"/kali-${architecture}/usr/bin/monstop
#!/bin/bash
interface=wlan0mon
ifconfig ${interface} down
sleep 1
iw dev ${interface} del
EOF
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/monstop

# Bluetooth enabling
mkdir -p "${basedir}"/kali-${architecture}/etc/udev/rules.d
cp "${basedir}"/../misc/pi-bluetooth/99-com.rules "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-com.rules
mkdir -p "${basedir}"/kali-${architecture}/usr/lib/systemd/system/
cp "${basedir}"/../misc/pi-bluetooth/hciuart.service "${basedir}"/kali-${architecture}/usr/lib/systemd/system/hciuart.service
mkdir -p "${basedir}"/kali-${architecture}/usr/bin
cp "${basedir}"/../misc/pi-bluetooth/btuart "${basedir}"/kali-${architecture}/usr/bin/btuart
# Ensure btuart is executable
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/btuart

cat << EOF > "${basedir}"/kali-${architecture}/third-stage
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
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
export DEBIAN_FRONTEND=noninteractive
# This looks weird, but we do it twice because every so often, there's a failure to download from the mirror
# So to workaround it, we attempt to install them twice.
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install

# Install the kernel packages
echo "deb http://http.re4son-kernel.com/re4son kali-pi main" > /etc/apt/sources.list.d/re4son.list
wget -O - https://re4son-kernel.com/keys/http/archive-key.asc | apt-key add -
apt-get update
apt-get install --yes --allow-change-held-packages kalipi-kernel kalipi-bootloader kalipi-re4son-firmware kalipi-kernel-headers

apt-get --yes --allow-change-held-packages autoremove
# libinput seems to fail hard on RaspberryPi devices, so we make sure it's not
# installed here (and we have xserver-xorg-input-evdev and
# xserver-xorg-input-synaptics packages installed above!)
apt-get --yes --allow-change-held-packages purge xserver-xorg-input-libinput

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Regenerated the shared-mime-info database on the first boot
# since it fails to do so properly in a chroot.
systemctl enable smi-hack

systemctl enable rpiwiggle
# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys

# Enable hciuart for bluetooth device
systemctl enable hciuart

# Enable copying of user wpa_supplicant.conf file
systemctl enable copy-user-wpasupplicant

# Enable... enabling ssh by putting ssh or ssh.txt file in /boot
systemctl enable enable-ssh

# Copy over the default bashrc
cp  /etc/skel/.bashrc /root/.bashrc

# Try and make the console a bit nicer
# Set the terminus font for a bit nicer display.
sed -i -e 's/FONTFACE=.*/FONTFACE="Terminus"/' /etc/default/console-setup
sed -i -e 's/FONTSIZE=.*/FONTSIZE="6x12"/' /etc/default/console-setup

# Fix startup time from 5 minutes to 15 secs on raise interface wlan0
sed -i 's/^TimeoutStartSec=5min/TimeoutStartSec=15/g' "/usr/lib/systemd/system/networking.service"
rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
#rm -f /usr/bin/qemu*
EOF

chmod 755 "${basedir}"/kali-${architecture}/third-stage

# rpi-wiggle
mkdir -p "${basedir}"/kali-${architecture}/root/scripts
wget https://raw.githubusercontent.com/steev/rpiwiggle/master/rpi-wiggle -O kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 "${basedir}"/kali-${architecture}/root/scripts/rpi-wiggle.sh

# Copy in the XFCE4 settings
#mkdir -p "${basedir}"/kali-${architecture}/root/.config/xfce4/
#cp -a "${basedir}"/../misc/xfce4/* kali-${architecture}/root/.config/xfce4/

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /third-stage
if [[ $? > 0 ]]; then
  echo "Third stage failed"
  exit 1
fi
rm -rf kali-${architecture}/third-stage

#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Enable login over serial
echo "T0:23:respawn:/sbin/agetty -L ttyAMA0 115200 vt100" >> "${basedir}"/kali-${architecture}/etc/inittab

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Create cmdline.txt file
cd "${basedir}"

cat << EOF > "${basedir}"/kali-${architecture}/boot/cmdline.txt
dwc_otg.fiq_fix_enable=2 console=ttyAMA0,115200 kgdboc=ttyAMA0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 rootwait rootflags=noload net.ifnames=0
EOF

#cat << EOF > "${basedir}"/kali-${architecture}/etc/apt/sources.list
#deb http://http.kali.org/kali kali-rolling main non-free contrib
#deb-src http://http.kali.org/kali kali-rolling main non-free contrib
#EOF

# systemd doesn't seem to be generating the fstab properly for some people, so
# let's create one.
cat << EOF > "${basedir}"/kali-${architecture}/etc/fstab
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    defaults          0       0
/dev/mmcblk0p1  /boot           vfat    defaults          0       2
/dev/mmcblk0p2  /               ext4    defaults,noatime  0       1
EOF

# Copy a default config, with everything commented out so people find it when
# they go to add something when they are following instructions on a website.
cp "${basedir}"/../misc/config.txt "${basedir}"/kali-${architecture}/boot/config.txt

cat << EOF >> "${basedir}"/kali-${architecture}/boot/config.txt

# If you would like to enable USB booting on your Pi, uncomment the following line.
# Boot from microsd card with it, then reboot.
# Don't forget to comment this back out after using, especially if you plan to use
# sdcard with multiple machines!
# NOTE: This ONLY works with the Raspberry Pi 3+
#program_usb_boot_mode=1
EOF

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

# Set a REGDOMAIN.  This needs to be done or wireless doesn't work correctly on the RPi 3B+
sed -i -e 's/REGDOM.*/REGDOMAIN=00/g' "${basedir}"/kali-${architecture}/etc/default/crda

cd "${basedir}"

# Re4son's rpi-tft configurator
wget https://raw.githubusercontent.com/Re4son/RPi-Tweaks/master/kalipi-tft-config/kalipi-tft-config -O "${basedir}"/kali-${architecture}/usr/bin/kalipi-tft-config
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/kalipi-tft-config

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
parted ${imagename}.img --script -- mkpart primary fat32 0 64
parted ${imagename}.img --script -- mkpart primary ext4 64 -1

# Set the partition variables
loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat ${bootp}
mkfs.ext4 ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p "${basedir}"/root/
mount ${rootp} "${basedir}"/root
mkdir -p "${basedir}"/root/boot
mount ${bootp} "${basedir}"/root/boot

echo "Rsyncing rootfs into image file"
rsync -HPavz -q "${basedir}"/kali-${architecture}/ "${basedir}"/root/

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > "${basedir}"/root/etc/resolv.conf
nameserver 8.8.8.8
EOF

# Make sure to enable ssh on the device by default
touch "${basedir}"/root/boot/ssh

sync
# sleep for 10 seconds, to let the cache settle after sync.
sleep 10
umount -l ${bootp}
umount -l ${rootp}
kpartx -dv ${loopdevice}
losetup -d ${loopdevice}

MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing ${imagename}.img"
pixz "${basedir}"/${imagename}.img "${basedir}"/../${imagename}.img.xz
unxz -t ${basedir}/../${imagename}.img.xz || rm ${basedir}/../${imagename}.img.xz &&  pixz ${basedir}/${imagename}.img ${basedir}/../${imagename}.img.xz && unxz -t ${basedir}/../${imagename}.img.xz
rm "${basedir}"/${imagename}.img
fi

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Cleaning up the temporary build files..."
rm -rf "${basedir}"
