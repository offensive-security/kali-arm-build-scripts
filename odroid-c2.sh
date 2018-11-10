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

basedir=`pwd`/odroidc2-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-odroidc2}
# Size of image in megabytes (Default is 4500=4.5GB)
size=4500
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

# Display is... interesting, thanks Amlogic.
mkdir -p "${basedir}"/kali-${architecture}/usr/share/lightdm/lightdm.conf.d
cat << EOF > "${basedir}"/kali-${architecture}/usr/share/lightdm/lightdm.conf.d/10-odroidc2.conf
[SeatDefaults]
display-setup-script=/usr/bin/aml_fix_display
EOF

cat << EOF > "${basedir}"/kali-${architecture}/usr/bin/aml_fix_display
#!/bin/bash
exit 0
EOF
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/aml_fix_display

# Create systemd service to setup display.
cat << EOF > "${basedir}"/kali-${architecture}/lib/systemd/system/amlogic.service
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
ln -sf /lib/systemd/system/amlogic.service "${basedir}"/kali-${architecture}/etc/systemd/system/multi-user.target.wants/amlogic.service

cat << EOF > "${basedir}"/kali-${architecture}/usr/bin/amlogic.sh
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
chmod 755 "${basedir}"/kali-${architecture}/usr/bin/amlogic.sh

# And because we need to run c2_init in the initramfs and it calls fbset,
# create a hook for adding /bin/fbset to the initrd as well.
cat << EOF > "${basedir}"/kali-${architecture}/usr/share/initramfs-tools/hooks/fbset
#!/bin/sh -e
PREREQS=""
case \$1 in
            prereqs) echo "\${PREREQS}"; exit 0;;
        esac
        . /usr/share/initramfs-tools/hook-functions
        copy_exec /bin/fbset /bin
EOF
chmod 755 "${basedir}"/kali-${architecture}/usr/share/initramfs-tools/hooks/fbset

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://github.com/hardkernel/linux -b odroidc2-v3.16.y "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
touch .scmversion
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/kali-wifi-injection-3.16.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
cp "${basedir}"/../kernel-configs/odroid-c2-3.16.config .config
cp .config "${basedir}"/kali-${architecture}/usr/src/odroid-c2-3.16.config
cd "${basedir}"/kali-${architecture}/usr/src/kernel/
rm -rf "${basedir}"/kali-${architecture}/usr/src/kernel/.git
make -j $(grep -c processor /proc/cpuinfo)
make modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cp arch/arm64/boot/Image "${basedir}"/kali-${architecture}/boot/
cp arch/arm64/boot/dts/meson64_odroidc2.dtb "${basedir}"/kali-${architecture}/boot/
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

# Create a boot.ini file with possible options if people want to change them.
# Currently on my only nearby 1080p, I get a display that's only 1024x768 in the
# upper left corner, so default to 720p which seems to work great.
cat << EOF > "${basedir}"/kali-${architecture}/boot/boot.ini
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

cat << EOF > "${basedir}"/kali-${architecture}/boot/mkuinitrd
#!/bin/bash
if [ -a /boot/initrd.img-\$(uname -r) ] ; then
    update-initramfs -u -k \$(uname -r)
else
    update-initramfs -c -k \$(uname -r)
fi
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-\$(uname -r) /boot/uInitrd
EOF

cd "${basedir}"

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

# Now, to get display working properly, we need an initramfs, so we can run the
# c2_init.sh file before we launch X.
cat << EOF > "${basedir}"/kali-${architecture}/create-initrd
#!/bin/bash
update-initramfs -c -k 3.16.60
mkimage -A arm64 -O linux -T ramdisk -C none -a 0 -e 0 -n "uInitrd" -d /boot/initrd.img-3.16.60 /boot/uInitrd
rm -f /create-initrd
rm -f /usr/bin/qemu-*
EOF
chmod 755 "${basedir}"/kali-${architecture}/create-initrd
LANG=C systemd-nspawn -M ${machine} -D "${basedir}"/kali-${architecture} /create-initrd
sync

# rpi-wiggle
mkdir -p "${basedir}"/kali-${architecture}/root/scripts
wget https://raw.github.com/offensive-security/rpiwiggle/master/rpi-wiggle -O "${basedir}"/kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 "${basedir}"/kali-${architecture}/root/scripts/rpi-wiggle.sh

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

echo "Running du to see how big kali-${architecture} is"
du -sh "${basedir}"/kali-${architecture}
echo "the above is how big the sdcard needs to be"

# Create the disk and partition it
echo "Creating image file ${imagename}.img"
dd if=/dev/zero of="${basedir}"/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary fat32 2048s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat -F 32 -n boot ${bootp}
mkfs.ext4 -O ^flex_bg -O ^metadata_csum -L rootfs ${rootp}

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

# Unmount partitions
# Sync before unmounting to ensure everything is written
sync
umount -l ${bootp}
umount -l ${rootp}
kpartx -dv ${loopdevice}

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
#cd "${basedir}"/u-boot
#make CROSS_COMPILE=aarch64-linux-gnu- odroidc2_config
#make CROSS_COMPILE=aarch64-linux-gnu- -j $(grep -c processor /proc/cpuinfo)

mkdir -p "${basedir}"/u-boot
cd "${basedir}"/u-boot
git clone https://github.com/mdrjr/c2_uboot_binaries
cd c2_uboot_binaries
sh sd_fusing.sh ${loopdevice}
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
