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

basedir=`pwd`/usbarmory-$1

hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-usbarmory}
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
base="apt-transport-https apt-utils console-setup e2fsprogs firmware-linux firmware-realtek firmware-atheros firmware-libertas firmware-brcm80211 ifupdown initramfs-tools iw kali-defaults man-db mlocate netcat-traditional net-tools parted psmisc rfkill screen snmpd snmp sudo tftp tmux unrar usbutils vim wget zerofree"
#desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng cewl crunch dnsrecon dnsutils ethtool exploitdb hydra john libnfc-bin medusa metasploit-framework mfoc ncrack nmap passing-the-hash proxychains recon-ng sqlmap tcpdump theharvester tor tshark usbutils whois windows-binaries winexe wpscan"
services="apache2 atftpd haveged openssh-server openvpn tightvncserver"
extras="cryptsetup isc-dhcp-server lvm2 wpasupplicant"

packages="${arm} ${base} ${services} ${extras}"
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

# So X doesn't complain, we add kali to hosts
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

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.

echo "Enabling sshd"
update-rc.d ssh enable

# Enable dhcp server
update-rc.d isc-dhcp-server enable

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
# Not sure why this gets created...
rm -f /0
# If java bombs for some reason...
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

echo "Setting up modules.conf"
# rm the symlink if it exists, and the original files if they exist
rm "${basedir}"/kali-${architecture}/etc/modules
rm "${basedir}"/kali-${architecture}/etc/modules-load.d/modules.conf
cat << EOF > "${basedir}"/kali-${architecture}/etc/modules-load.d/modules.conf
ledtrig_heartbeat
ci_hdrc_imx
g_ether
#g_mass_storage
#g_multi
EOF

echo "Setting up modprobe.d"
cat << EOF > "${basedir}"/kali-${architecture}/etc/modprobe.d/usbarmory.conf
options g_ether use_eem=0 dev_addr=1a:55:89:a2:69:41 host_addr=1a:55:89:a2:69:42
# To use either of the following, you should create the file /disk.img via dd
# "dd if=/dev/zero of=/disk.img bs=1M count=2048" would create a 2GB disk.img file.
#options g_mass_storage file=disk.img
#options g_multi use_eem=0 dev_addr=1a:55:89:a2:69:41 host_addr=1a:55:89:a2:69:42 file=disk.img
EOF

cat << EOF > "${basedir}"/kali-${architecture}/etc/network/interfaces
auto lo
iface lo inet loopback

allow-hotplug usb0
iface usb0 inet static
address 10.0.0.1
netmask 255.255.255.0
gateway 10.0.0.2
EOF

cat << EOF > "${basedir}"/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Debian reads the config from inside /etc/dhcp.
cat << EOF > "${basedir}"/kali-${architecture}/etc/dhcp/dhcpd.conf
#
# Sample configuration file for ISC dhcpd for Debian
#
# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# option definitions common to all supported networks...
#option domain-name "example.org";
#option domain-name-servers ns1.example.org, ns2.example.org;

default-lease-time 600;
max-lease-time 7200;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
#authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
log-facility local7;

# A slightly different configuration for an internal subnet.
subnet 10.0.0.0 netmask 255.255.255.0 {
  range 10.0.0.2 10.0.0.2;
  default-lease-time 600;
  max-lease-time 7200;
}


# No service will be given on this subnet, but declaring it helps the
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
#  default-lease-time 600;
#  max-lease-time 7200;
#}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.fugue.com";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.fugue.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of "foo";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of "foo";
#    range 10.0.29.10 10.0.29.230;
#  }
#}
EOF

# Only listen on usb0
sed -i 's/INTERFACES.*/INTERFACES="usb0"/g' "${basedir}"/kali-${architecture}/etc/default/isc-dhcp-server

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone -b linux-4.14.y --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
git rev-parse HEAD > "${basedir}"/kali-${architecture}/usr/src/kernel-at-commit
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/kali-wifi-injection-4.14.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
#wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/usbarmory_linux-4.14.config -O .config
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-host.dts -O arch/arm/boot/dts/imx53-usbarmory-host.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-gpio.dts -O arch/arm/boot/dts/imx53-usbarmory-gpio.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-spi.dts -O arch/arm/boot/dts/imx53-usbarmory-spi.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-i2c.dts -O arch/arm/boot/dts/imx53-usbarmory-i2c.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-scc2.dts -O arch/arm/boot/dts/imx53-usbarmory-scc2.dts
cp "${basedir}"/../kernel-configs/usbarmory-4.14.config "${basedir}"/kali-${architecture}/usr/src/kernel/.config
cp "${basedir}"/../kernel-configs/usbarmory-4.14.config "${basedir}"/kali-${architecture}/usr/src/usbarmory-4.14.config
make LOADADDR=0x70008000 -j $(grep -c processor /proc/cpuinfo) uImage modules imx53-usbarmory-gpio.dtb imx53-usbarmory-i2c.dtb imx53-usbarmory-spi.dtb imx53-usbarmory.dtb imx53-usbarmory-host.dtb imx53-usbarmory-scc2.dtb
make modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cp arch/arm/boot/zImage "${basedir}"/kali-${architecture}/boot/
cp arch/arm/boot/dts/imx53-usbarmory*.dtb "${basedir}"/kali-${architecture}/boot/
make mrproper
# Since these aren't integrated into the kernel yet, mrproper removes them.
cp "${basedir}"/../kernel-configs/usbarmory-4.14.config "${basedir}"/kali-${architecture}/usr/src/kernel/.config
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-host.dts -O arch/arm/boot/dts/imx53-usbarmory-host.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-gpio.dts -O arch/arm/boot/dts/imx53-usbarmory-gpio.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-spi.dts -O arch/arm/boot/dts/imx53-usbarmory-spi.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-i2c.dts -O arch/arm/boot/dts/imx53-usbarmory-i2c.dts
wget https://raw.githubusercontent.com/inversepath/usbarmory/master/software/kernel_conf/mark-one/imx53-usbarmory-scc2.dts -O arch/arm/boot/dts/imx53-usbarmory-scc2.dts
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

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

cd "${basedir}"
# Create the disk and partition it
echo "Creating image file ${imagename}.img"
dd if=/dev/zero of="${basedir}"/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary ext2 5M 100%

# Set the partition variables
loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
rootp=${device}p1

# Create file systems
mkfs.ext2 ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p "${basedir}"/root
mount ${rootp} "${basedir}"/root

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

echo "Rsyncing rootfs into image file"
rsync -HPavz -q "${basedir}"/kali-${architecture}/ "${basedir}"/root/

# Unmount partitions
sync
umount ${rootp}
kpartx -dv ${loopdevice}

cd "${basedir}"
wget ftp://ftp.denx.de/pub/u-boot/u-boot-2018.05.tar.bz2
tar xvf u-boot-2018.05.tar.bz2 && cd u-boot-2018.05
make distclean
make usbarmory_config
make ARCH=arm
dd if=u-boot.imx of=${loopdevice} bs=512 seek=2 conv=fsync
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
echo "Removing build directory"
rm -rf "${basedir}"
