#!/bin/bash
set -e

# This is the HardKernel ODROID C Kali ARM build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/odroidc-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-odroidc}
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
extras="fbset iceweasel xfce4-terminal wpasupplicant"

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

sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

update-rc.d ssh enable

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

# Serial console settings.
# (No auto login)
echo 'T1:12345:respawn:/sbin/agetty 115200 ttyS0 vt100' >> ${basedir}/kali-${architecture}/etc/inittab

cat << EOF > ${basedir}/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/hardkernel/linux -b odroidc-3.10.y ${basedir}/kali-${architecture}/usr/src/kernel
cd ${basedir}/kali-${architecture}/usr/src/kernel
git rev-parse HEAD > ${basedir}/kali-${architecture}/usr/src/kernel-at-commit
touch .scmversion
export ARCH=arm
# NOTE: 3.8 now works with a 4.8 compiler, 3.4 does not!
export CROSS_COMPILE=arm-linux-gnueabihf-
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/mac80211-backports.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
make odroidc_defconfig
cp .config ../odroidc.config
make -j $(grep -c processor /proc/cpuinfo)
make uImage
make modules_install INSTALL_MOD_PATH=${basedir}/kali-${architecture}
cp arch/arm/boot/uImage ${basedir}/kali-${architecture}/boot/
cp arch/arm/boot/dts/meson8b_odroidc.dtb ${basedir}/kali-${architecture}/boot/
make mrproper
cp ../odroidc.config .config
make modules_prepare
cd ${basedir}

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

# Create a boot.ini file with possible options if people want to change them.
cat << EOF > ${basedir}/kali-${architecture}/boot/boot.ini
ODROIDC-UBOOT-CONFIG

# Possible screen resolutions
# Uncomment only a single Line! The line with setenv written.
# At least one mode must be selected.

# setenv m "vga"                # 640x480
# setenv m "480p"               # 720x480
# setenv m "576p"               # 720x576
# setenv m "800x480p60hz"       # 800x480
# setenv m "800x600p60hz"       # 800x600
# setenv m "1024x600p60hz"      # 1024x600
# setenv m "1024x768p60hz"      # 1024x768
# setenv m "1360x768p60hz"      # 1360x768
# setenv m "1440x900p60hz"      # 1440x900
# setenv m "1600x900p60hz"      # 1600x900
# setenv m "1680x1050p60hz"     # 1680x1050
# setenv m "720p"               # 720p 1280x720
# setenv m "800p"               # 1280x800
# setenv m "sxga"               # 1280x1024
# setenv m "1080i50hz"          # 1080I@50Hz
# setenv m "1080p24hz"          # 1080P@24Hz
# setenv m "1080p50hz"          # 1080P@50Hz
setenv m "1080p"                # 1080P@60Hz
# setenv m "1920x1200"          # 1920x1200

# HDMI DVI Mode Configuration
setenv vout_mode "hdmi"
# setenv vout_mode "dvi"
# setenv vout_mode "vga"

# HDMI BPP Mode
setenv m_bpp "32"
# setenv m_bpp "24"
# setenv m_bpp "16"

# HDMI Hotplug Force (HPD)
# 1 = Enables HOTPlug Detection
# 0 = Disables HOTPlug Detection and force the connected status
setenv hpd "0"

# CEC Enable/Disable (Requires Hardware Modification)
# 1 = Enables HDMI CEC
# 0 = Disables HDMI CEC
setenv cec "0"

# PCM5102 I2S Audio DAC
# PCM5102 is an I2S Audio Dac Addon board for ODROID-C1+
# Uncomment the line below to __ENABLE__ support for this Addon board.
# setenv enabledac "enabledac"

# UHS Card Configuration
# Uncomment the line below to __DISABLE__ UHS-1 MicroSD support
# This might break boot for some brand models of cards.
setenv disableuhs "disableuhs"


# Disable VPU (Video decoding engine, Saves RAM!!!)
# 0 = disabled
# 1 = enabled
setenv vpu "1"

# Disable HDMI Output (Again, saves ram!)
# 0 = disabled
# 1 = enabled
setenv hdmioutput "1"

# Default Console Device Setting
# setenv condev "console=ttyS0,115200n8"        # on serial port
# setenv condev "console=tty0"                    # on display (HDMI)
setenv condev "console=tty0 console=ttyS0,115200n8"   # on both



###########################################

if test "\${hpd}" = "0"; then setenv hdmi_hpd "disablehpd=true"; fi
if test "\${cec}" = "1"; then setenv hdmi_cec "hdmitx=cecf"; fi

# Boot Arguments
setenv bootargs "root=/dev/mmcblk0p2 rootfstype=ext4 quiet rootwait rw \${condev} no_console_suspend vdaccfg=0xa000 logo=osd1,loaded,0x7900000,720p,full dmfc=3 cvbsmode=576cvbs hdmimode=\${m} m_bpp=\${m_bpp} vout=\${vout_mode} \${disableuhs} \${hdmi_hpd} \${hdmi_cec} \${enabledac} net.ifnames=0"

# Booting
fatload mmc 0:1 0x21000000 uImage
fatload mmc 0:1 0x22000000 uInitrd
fatload mmc 0:1 0x21800000 meson8b_odroidc.dtb
fdt addr 21800000

if test "\${vpu}" = "0"; then fdt rm /mesonstream; fdt rm /vdec; fdt rm /ppmgr; fi

if test "\${hdmioutput}" = "0"; then fdt rm /mesonfb; fi

# If you're going to use an initrd, uncomment this line and comment out the bottom line.
#bootm 0x21000000 0x22000000 0x21800000"
bootm 0x21000000 - 0x21800000"
EOF

# Create systemd service to setup display.
cat << EOF > ${basedir}/kali-${architecture}/lib/systemd/system/amlogic.service
[Unit]
Description=AMlogic HDMI Initialization

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/amlogic.sh

[Install]
WantedBy=multi-user.target
EOF

# Create symlink to enable the service...
ln -sf /lib/systemd/system/amlogic.service ${basedir}/kali-${architecture}/etc/systemd/system/multi-user.target.wants/amlogic.service

cat << EOF > ${basedir}/kali-${architecture}/usr/bin/amlogic.sh
#!/bin/sh

for x in \$(cat /proc/cmdline); do
    case \${x} in
        m_bpp=*) export bpp=\${x#*=} ;;
        hdmimode=*) export mode=\${x#*=} ;;
    esac
done

HPD_STATE=/sys/class/amhdmitx/amhdmitx0/hpd_state
DISP_CAP=/sys/class/amhdmitx/amhdmitx0/disp_cap
DISP_MODE=/sys/class/display/mode

hdmi=\`cat \$HPD_STATE\`
if [ \$hdmi -eq 1 ]; then
    echo \$mode > \$DISP_MODE
fi

outputmode=\$mode

common_display_setup() {
    fbset -fb /dev/fb1 -g 32 32 32 32 32
    echo \$outputmode > /sys/class/display/mode
    echo 0 > /sys/class/ppmgr/ppscaler
    echo 0 > /sys/class/graphics/fb0/free_scale
    echo 1 > /sys/class/graphics/fb0/freescale_mode

    case \$outputmode in
            800x480*) M="0 0 799 479" ;;
            vga*)  M="0 0 639 749" ;;
            800x600p60*) M="0 0 799 599" ;;
            1024x600p60h*) M="0 0 1023 599" ;;
            1024x768p60h*) M="0 0 1023 767" ;;
            sxga*) M="0 0 1279 1023" ;;
            1440x900p60*) M="0 0 1439 899" ;;
            480*) M="0 0 719 479" ;;
            576*) M="0 0 719 575" ;;
            720*) M="0 0 1279 719" ;;
            800*) M="0 0 1279 799" ;;
            1080*) M="0 0 1919 1079" ;;
            1920x1200*) M="0 0 1919 1199" ;;
            1680x1050p60*) M="0 0 1679 1049" ;;
        1360x768p60*) M="0 0 1359 767" ;;
        1366x768p60*) M="0 0 1365 767" ;;
        1600x900p60*) M="0 0 1599 899" ;;
    esac

    echo \$M > /sys/class/graphics/fb0/free_scale_axis
    echo \$M > /sys/class/graphics/fb0/window_axis
    echo 0x10001 > /sys/class/graphics/fb0/free_scale
    echo 0 > /sys/class/graphics/fb1/free_scale
}

case \$mode in
    800x480*)           fbset -fb /dev/fb0 -g 800 480 800 960 \$bpp;     common_display_setup ;;
    vga*)               fbset -fb /dev/fb0 -g 640 480 640 960 \$bpp;     common_display_setup ;;
    480*)               fbset -fb /dev/fb0 -g 720 480 720 960 \$bpp;     common_display_setup ;;
    800x600p60*)        fbset -fb /dev/fb0 -g 800 600 800 1200 \$bpp;    common_display_setup ;;
    576*)               fbset -fb /dev/fb0 -g 720 576 720 1152 \$bpp;    common_display_setup ;;
    1024x600p60h*)      fbset -fb /dev/fb0 -g 1024 600 1024 1200 \$bpp;  common_display_setup ;;
    1024x768p60h*)      fbset -fb /dev/fb0 -g 1024 768 1024 1536 \$bpp;  common_display_setup ;;
    720*)               fbset -fb /dev/fb0 -g 1280 720 1280 1440 \$bpp;  common_display_setup ;;
    800*)               fbset -fb /dev/fb0 -g 1280 800 1280 1600 \$bpp;  common_display_setup ;;
    sxga*)              fbset -fb /dev/fb0 -g 1280 1024 1280 2048 \$bpp; common_display_setup ;;
    1440x900p60*)       fbset -fb /dev/fb0 -g 1440 900 1440 1800 \$bpp;  common_display_setup ;;
    1080*)              fbset -fb /dev/fb0 -g 1920 1080 1920 2160 \$bpp; common_display_setup ;;
    1920x1200*)         fbset -fb /dev/fb0 -g 1920 1200 1920 2400 \$bpp; common_display_setup ;;
    1360x768p60*)       fbset -fb /dev/fb0 -g 1360 768 1360 1536 \$bpp;  common_display_setup ;;
    1366x768p60*)       fbset -fb /dev/fb0 -g 1366 768 1366 1536 \$bpp;  common_display_setup ;;
    1600x900p60*)       fbset -fb /dev/fb0 -g 1600 900 1600 1800 \$bpp;  common_display_setup ;;
    1680x1050p60*)      fbset -fb /dev/fb0 -g 1680 1050 1680 2100 \$bpp; common_display_setup ;;
esac


# Console unblack
echo 0 > /sys/class/graphics/fb0/blank
echo 0 > /sys/class/graphics/fb1/blank


# Network Tweaks. Thanks to mlinuxguy
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries
echo 2048 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
echo 7 > /sys/class/net/eth0/queues/rx-0/rps_cpus
echo 7 > /sys/class/net/eth0/queues/tx-0/xps_cpus

# Move IRQ's of ethernet to CPU1/2
echo 1,2 > /proc/irq/40/smp_affinity_list
EOF
chmod 755 ${basedir}/kali-${architecture}/usr/bin/amlogic.sh

cat << EOF > ${basedir}/kali-${architecture}/etc/sysctl.d/99-c1-network.conf
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 514400
net.core.wmem_default = 514400
net.ipv4.tcp_rmem = 10240 87380 26214400
net.ipv4.tcp_wmem = 10240 87380 26214400
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.core.optmem_max = 65535
net.core.netdev_max_backlog = 5000
EOF

cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/kali-${architecture}/etc/init.d/zram
chmod 755 ${basedir}/kali-${architecture}/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/kali-${architecture}/etc/ssh/sshd_config

# Create the disk and partition it
echo "Creating image file for ODROID-C1"
dd if=/dev/zero of=${basedir}/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary fat32 3072s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat ${bootp}
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

# Build the latest u-boot bootloader, and then use the Hardkernel script to fuse
# it to the image.  This is required because of a requirement that the
# bootloader be signed.
git clone --depth 1 https://github.com/hardkernel/u-boot -b odroidc-v2011.03
cd ${basedir}/u-boot
# https://code.google.com/p/chromium/issues/detail?id=213120
sed -i -e "s/soft-float/float-abi=hard -mfpu=vfpv3/g" \
    arch/arm/cpu/armv7/config.mk
make CROSS_COMPILE=arm-linux-gnueabihf- odroidc_config
make CROSS_COMPILE=arm-linux-gnueabihf- -j $(grep -c processor /proc/cpuinfo)

cd sd_fuse
sh sd_fusing.sh ${loopdevice}

cd ${basedir}

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
echo "Clean up the build system"
rm -rf ${basedir}