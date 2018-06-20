#!/bin/bash

# This is the HardKernel ODROID C2 Kali ARM64 build script - http://hardkernel.com/main/main.php
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/odroidc2-$1

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

# cgpt, vboot-utils and vboot-kernel-utils aren't available on arm64 yet.
#arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
arm="abootimg fake-hwclock ntpdate u-boot-tools"
base="e2fsprogs initramfs-tools kali-defaults kali-menu parted sudo usbutils"
desktop="fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev"
tools="aircrack-ng ethtool hydra john libnfc-bin mfoc nmap passing-the-hash sqlmap usbutils winexe wireshark"
services="apache2 openssh-server"
extras="fbset xfce4-terminal xfce4-goodies wpasupplicant"
kali="build-essential debhelper devscripts dput lintian quilt git-buildpackage gitk dh-make sbuild"

packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras} ${kali}"
architecture="arm64"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --keyring=/usr/share/keyrings/kali-archive-keyring.gpg --arch $architecture kali-rolling kali-$architecture http://$mirror/kali

cp /usr/bin/qemu-aarch64-static kali-$architecture/usr/bin/
cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C systemd-nspawn -M odroidc2 -D kali-$architecture /debootstrap/debootstrap --second-stage
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali-rolling main contrib non-free
EOF

echo "kali-arm64" > kali-$architecture/etc/hostname

cat << EOF > kali-$architecture/etc/hosts
127.0.0.1       kali-armhf    localhost
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

#mount -t proc proc kali-$architecture/proc
#mount -o bind /dev/ kali-$architecture/dev/
#mount -o bind /dev/pts kali-$architecture/dev/pts

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

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.

echo "Making the image insecure"
sed -i -e 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

update-rc.d ssh enable

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C systemd-nspawn -M odroidc2 -D kali-$architecture /third-stage

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
LANG=C systemd-nspawn -M odroidc2 -D kali-$architecture /cleanup

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

# Create the disk and partition it
echo "Creating image file for ODROID-C2"
dd if=/dev/zero of=${basedir}/kali-linux-$1-odroidc2.img bs=1M count=7000
parted kali-linux-$1-odroidc2.img --script -- mklabel msdos
parted kali-linux-$1-odroidc2.img --script -- mkpart primary fat32 2048s 264191s
parted kali-linux-$1-odroidc2.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/kali-linux-$1-odroidc2.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat -F 32 -n boot $bootp
mkfs.ext4 -O ^flex_bg -O ^metadata_csum -L rootfs $rootp

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

# Display is... interesting, thanks Amlogic.
mkdir -p /usr/share/lightdm/lightdm.conf.d
cat << EOF > ${basedir}/root/usr/share/lightdm/lightdm.conf.d/10-odroidc2.conf
[SeatDefaults]
display-setup-script=/usr/bin/aml_fix_display
EOF

cat << EOF > ${basedir}/root/usr/bin/aml_fix_display
#!/bin/bash
exit 0
EOF
chmod +x ${basedir}/root/usr/bin/aml_fix_display

# Create systemd service to setup display.
cat << EOF > ${basedir}/root/lib/systemd/system/amlogic.service
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
ln -sf /lib/systemd/system/amlogic.service ${basedir}/root/etc/systemd/system/multi-user.target.wants/amlogic.service

cat << EOF > ${basedir}/root/usr/bin/amlogic.sh
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

echo \$mode > \$DISP_MODE

common_display_setup() {
        M="0 0 \$((\$X - 1)) \$((\$Y - 1))"
        Y_VIRT=\$((\$Y * 2))
        fbset -fb /dev/fb0 -g \$X \$Y \$X \$Y_VIRT \$bpp
        echo \$mode > /sys/class/display/mode
        echo 0 > /sys/class/graphics/fb0/free_scale
        echo 1 > /sys/class/graphics/fb0/freescale_mode
        echo \$M > /sys/class/graphics/fb0/free_scale_axis
        echo \$M > /sys/class/graphics/fb0/window_axis

        echo 0 > /sys/class/graphics/fb1/free_scale
        echo 1 > /sys/class/graphics/fb1/freescale_mode
        if [ "\$bpp" = "32" ]; then
            echo d01068b4 0x7fc0 > /sys/kernel/debug/aml_reg/paddr
        fi
}

case \$mode in
        480*)
            export X=720
            export Y=480
            ;;
        576*)
            export X=720
            export Y=576
            ;;
        720p*)
            export X=1280
            export Y=720
            ;;
        1080*)
            export X=1920
            export Y=1080
            ;;
        2160p*)
            export X=3840
            export Y=2160
            ;;
        smpte24hz*)
            export X=3840
            export Y=2160
            ;;
        640x480p60hz*)
            export X=640
            export Y=480
            ;;
        800x480p60hz*)
            export X=800
            export Y=480
            ;;
        800x600p60hz*)
            export X=800
            export Y=600
            ;;
        1024x600p60hz*)
            export X=1024
            export Y=600
            ;;
        1024x768p60hz*)
            export X=1024
            export Y=768
            ;;
        1280x800p60hz*)
            export X=1280
            export Y=800
            ;;
        1280x1024p60hz*)
            export X=1280
            export Y=1024
            ;;
        1360x768p60hz*)
            export X=1360
            export Y=768
            ;;
        1366x768p60hz*)
            export X=1366
            export Y=768
            ;;
        1440x900p60hz*)
            export X=1440
            export Y=900
            ;;
        1600x900p60hz*)
            export X=1600
            export Y=900
            ;;
        1680x1050p60hz*)
            export X=1680
            export Y=1050
            ;;
        1920x1200p60hz*)
            export X=1920
            export Y=1200
            ;;
        2560x1080p60hz*)
            export X=2560
            export Y=1080
            ;;
        2560x1440p60hz*)
            export X=2560
            export Y=1440
            ;;
        2560x1600p60hz*)
            export X=2560
            export Y=1600
            ;;
esac

common_display_setup

# Console unblack
echo 0 > /sys/class/graphics/fb0/blank
echo 0 > /sys/class/graphics/fb1/blank
EOF
chmod +x ${basedir}/root/usr/bin/amlogic.sh

# And because we need to run c2_init in the initramfs and it calls fbset,
# create a hook for adding /bin/fbset to the initrd as well.
cat << EOF > ${basedir}/root/usr/share/initramfs-tools/hooks/fbset
#!/bin/sh -e
PREREQS=""
case \$1 in
            prereqs) echo "\${PREREQS}"; exit 0;;
        esac
        . /usr/share/initramfs-tools/hook-functions
        copy_exec /bin/fbset /bin
EOF
chmod +x ${basedir}/root/usr/share/initramfs-tools/hooks/fbset

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
# For some reason, building the kernel in the image fails claiming it's run out
# of space - for the moment, let's build the kernel outside of it, but still
# keep the sources around for those who want/need to build external modules.
git clone --depth 1 https://github.com/hardkernel/linux -b odroidc2-3.14.y ${basedir}/root/usr/src/kernel
cd ${basedir}/root/usr/src/kernel
touch .scmversion
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-3.14.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
cp ${basedir}/../kernel-configs/odroid-c2.config .config
cp .config ../odroid-c2.config
cp -a ${basedir}/root/usr/src/kernel ${basedir}/
cd ${basedir}/kernel/
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH=${basedir}/root
cp arch/arm64/boot/Image ${basedir}/bootp/
cp arch/arm64/boot/dts/meson64_odroidc2.dtb ${basedir}/bootp/
cd ${basedir}/root/usr/src/kernel
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

# Create a boot.ini file with possible options if people want to change them.
# Currently on my only nearby 1080p, I get a display that's only 1024x768 in the
# upper left corner, so default to 720p which seems to work great.
cat << EOF > ${basedir}/bootp/boot.ini
ODROIDC2-UBOOT-CONFIG

# Possible screen resolutions
# Uncomment only a single Line! The line with setenv written.
# At least one mode must be selected.

# Custom modeline!
# To use custom modeline you need to disable all the below resolutions
# and setup your own! 
# For more information check our wiki: 
# http://odroid.com/dokuwiki/doku.php?id=en:c2_hdmi_autosetting
# Example below:
# setenv m "custombuilt" 
# setenv modeline "1920,1200,154000,74040,60,1920,1968,2000,2080,1200,1202,1208,1235,1,0,1"

# 480 Lines (720x480)
# setenv m "480i60hz" # Interlaced 60Hz
# setenv m "480i_rpt" # Interlaced for Rear Projection Televisions 60Hz
# setenv m "480p60hz" # 480 Progressive 60Hz
# setenv m "480p_rpt" # 480 Progressive for Rear Projection Televisions 60Hz

# 576 Lines (720x576)
# setenv m "576i50hz" # Interlaced 50Hz
# setenv m "576i_rpt" # Interlaced for Rear Projection Televisions 50Hz
# setenv m "576p50hz" # Progressive 50Hz
# setenv m "576p_rpt" # Progressive for Rear Projection Televisions 50Hz

# 720 Lines (1280x720)
# setenv m "720p50hz" # 50Hz
# setenv m "720p60hz" # 60Hz

# 1080 Lines (1920x1080)
# setenv m "1080i60hz" # Interlaced 60Hz
setenv m "1080p60hz" # Progressive 60Hz
# setenv m "1080i50hz" # Interlaced 50Hz
# setenv m "1080p50hz" # Progressive 50Hz
# setenv m "1080p24hz" # Progressive 24Hz

# 4K (3840x2160)
# setenv m "2160p30hz"    # Progressive 30Hz
# setenv m "2160p25hz"    # Progressive 25Hz
# setenv m "2160p24hz"    # Progressive 24Hz
# setenv m "smpte24hz"    # Progressive 24Hz SMPTE
# setenv m "2160p50hz"    # Progressive 50Hz
# setenv m "2160p60hz"    # Progressive 60Hz
# setenv m "2160p50hz420" # Progressive 50Hz with YCbCr 4:2:0 (Requires TV/Monitor that supports it)
# setenv m "2160p60hz420" # Progressive 60Hz with YCbCr 4:2:0 (Requires TV/Monitor that supports it)

### VESA modes ###
# setenv m "640x480p60hz"
# setenv m "800x480p60hz"
# setenv m "800x600p60hz"
# setenv m "1024x600p60hz"
# setenv m "1024x768p60hz"  
# setenv m "1280x800p60hz"
# setenv m "1280x1024p60hz"
# setenv m "1360x768p60hz"
# setenv m "1440x900p60hz"
# setenv m "1600x900p60hz"
# setenv m "1680x1050p60hz"
# setenv m "1600x1200p60hz"
# setenv m "1920x1200p60hz"
# setenv m "2560x1080p60hz"
# setenv m "2560x1440p60hz"
# setenv m "2560x1600p60hz"
# setenv m "3440x1440p60hz"

# HDMI BPP Mode
setenv m_bpp "32"
# setenv m_bpp "24"
# setenv m_bpp "16"

# HDMI DVI/VGA modes
# Uncomment only a single Line! The line with setenv written.
# At least one mode must be selected.
# setenv vout "dvi"
# setenv vout "vga"

# HDMI HotPlug Detection control
# Allows you to force HDMI thinking that the cable is connected.
# true = HDMI will believe that cable is always connected
# false = will let board/monitor negotiate the connection status
setenv hpd "true"
# setenv hpd "false"

# Default Console Device Setting
setenv condev "console=ttyS0,115200n8 console=tty0"   # on both

# Meson Timer
# 1 - Meson Timer
# 0 - Arch Timer 
# Using meson_timer improves the video playback however it breaks KVM (virtualization).
# Using arch timer allows KVM/Virtualization to work however you'll experience poor video
setenv mesontimer "1"

# Server Mode (aka. No Graphics)
# Setting nographics to 1 will disable all video subsystem
# This mode is ideal of server type usage. (Saves ~300Mb of RAM)
setenv nographics "0"

# CPU Frequency / Cores control
###########################################
### WARNING!!! WARNING!!! WARNING!!!
# Before changing anything here please read the wiki entry: 
# http://odroid.com/dokuwiki/doku.php?id=en:c2_set_cpu_freq
#
# MAX CPU's
# setenv maxcpus "1"
# setenv maxcpus "2"
# setenv maxcpus "3"
setenv maxcpus "4"

# MAX Frequency
# setenv max_freq "2016"  # 2.016GHz
# setenv max_freq "1944"  # 1.944GHz
# setenv max_freq "1944"  # 1.944GHz
# setenv max_freq "1920"  # 1.920GHz
# setenv max_freq "1896"  # 1.896GHz
# setenv max_freq "1752"  # 1.752GHz
# setenv max_freq "1680"  # 1.680GHz
# setenv max_freq "1656"  # 1.656GHz
setenv max_freq "1536"  # 1.536GHz



###########################################

# Boot Arguments
if test "\${m}" = "custombuilt"; then setenv cmode "modeline=\${modeline}"; fi

setenv bootargs "root=/dev/mmcblk0p2 rootwait rw \${condev} no_console_suspend hdmimode=\${m} \${comde} m_bpp=\${m_bpp} vout=\${vout} fsck.repair=yes net.ifnames=0 elevator=noop disablehpd=\${hpd} max_freq=\${max_freq} maxcpus=\${maxcpus}"

# Booting

setenv loadaddr "0x11000000"
setenv dtb_loadaddr "0x1000000"
setenv initrd_loadaddr "0x13000000"

fatload mmc 0:1 \${initrd_loadaddr} uInitrd
fatload mmc 0:1 \${loadaddr} Image
fatload mmc 0:1 \${dtb_loadaddr} meson64_odroidc2.dtb
fdt addr \${dtb_loadaddr}

if test "\${mesontimer}" = "0"; then fdt rm /meson_timer; fdt rm /cpus/cpu@0/timer; fdt rm /cpus/cpu@1/timer; fdt rm /cpus/cpu@2/timer; fdt rm /cpus/cpu@3/timer; fi
if test "\${mesontimer}" = "1"; then fdt rm /timer; fi

if test "\${nographics}" = "1"; then fdt rm /reserved-memory; fdt rm /aocec; fi
if test "\${nographics}" = "1"; then fdt rm /meson-fb; fdt rm /amhdmitx; fdt rm /picdec; fdt rm /ppmgr; fi
if test "\${nographics}" = "1"; then fdt rm /meson-vout; fdt rm /mesonstream; fdt rm /meson-fb; fi
if test "\${nographics}" = "1"; then fdt rm /deinterlace; fdt rm /codec_mm; fi

#booti \${loadaddr} \${initrd_loadaddr} \${dtb_loadaddr}
booti \${loadaddr} - \${dtb_loadaddr}
EOF

cat << EOF > ${basedir}/bootp/mkuinitrd
#!/bin/bash
if [ -a /boot/initrd.img-\$(uname -r) ] ; then
    update-initramfs -u -k \$(uname -r)
else
    update-initramfs -c -k \$(uname -r)
fi
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-\$(uname -r) /boot/uInitrd
EOF


rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/root/etc/init.d/zram
chmod +x ${basedir}/root/etc/init.d/zram

# Now, to get display working properly, we need an initramfs, so we can run the
# c2_init.sh file before we launch X.
# Hack...
mount --bind ${basedir}/bootp ${basedir}/root/boot
cp /usr/bin/qemu-aarch64-static ${basedir}/root/usr/bin
cp /usr/bin/qemu-arm*-static ${basedir}/root/usr/bin
cat << EOF > ${basedir}/root/create-initrd
#!/bin/bash
update-initramfs -c -k 3.14.79
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-3.14.79 /boot/uInitrd
rm -f /create-initrd
rm -f /usr/bin/qemu-*
EOF
chmod +x ${basedir}/root/create-initrd
LANG=C systemd-nspawn -M odroidc2 -D ${basedir}/root /create-initrd
umount ${basedir}/root/boot

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/root/etc/ssh/sshd_config

# Unmount partitions
umount $bootp
umount $rootp
kpartx -dv $loopdevice

# Currently we use pre-built, because (again) Amlogic do some funky stuff.
# The steps for building yourself can be found at:
# http://odroid.com/dokuwiki/doku.php?id=en:c2_building_u-boot
# Because it requires a different toolchain to be downloaded and used, we went
# with the pre-built so as to save people bandwidth, but the steps are here.

#wget https://releases.linaro.org/14.09/components/toolchain/binaries/gcc-linaro-aarch64-none-elf-4.9-2014.09_linux.tar.xz
#mkdir -p /opt/toolchains
#tar xvf gcc-linaro-aarch64-none-elf-4.9-2014.09_linux.tar.xz -C /opt/toolchains/
#export PATH=/opt/toolchains/gcc-linaro-aarch64-none-elf-4.9-2014.09_linux/bin/:$PATH
#git clone --depth 1 https://github.com/hardkernel/u-boot -b odroidc2-v2015.01
#cd ${basedir}/u-boot
#make CROSS_COMPILE=aarch64-linux-gnu- odroidc2_config
#make CROSS_COMPILE=aarch64-linux-gnu- -j $(grep -c processor /proc/cpuinfo)

mkdir -p ${basedir}/u-boot
cd ${basedir}/u-boot
git clone https://github.com/mdrjr/c2_uboot_binaries
cd c2_uboot_binaries
sh sd_fusing.sh $loopdevice
cd ${basedir}

losetup -d $loopdevice

echo "Compressing kali-linux-$1-odroidc2.img"
pixz ${basedir}/kali-linux-$1-odroidc2.img ${basedir}/../kali-linux-$1-odroidc2.img.xz
echo "Deleting kali-linux-$1-odroidc2.img"
rm ${basedir}/kali-linux-$1-odroidc2.img

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Clean up the build system"
rm -rf ${basedir}
