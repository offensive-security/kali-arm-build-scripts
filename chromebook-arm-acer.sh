#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 1.0.1"
    exit 0
fi

basedir=`pwd`/nyan-$1

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
# This will build a minimal Gnome Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use.  You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate vboot-utils vboot-kernel-utils u-boot-tools"
base="kali-menu kali-defaults initramfs-tools usbutils"
desktop="gdm3 gnome-brave-icon-theme kali-desktop-gnome kali-root-login xserver-xorg-video-fbdev"
tools="passing-the-hash winexe aircrack-ng hydra john sqlmap wireshark libnfc-bin mfoc"
services="openssh-server apache2"
extras="wpasupplicant"

export packages="${arm} ${base} ${desktop} ${tools} ${services} ${extras}"
export architecture="armhf"
# If you have your own preferred mirrors, set them here.
# You may want to leave security.kali.org alone, but if you trust your local
# mirror, feel free to change this as well.
# After generating the rootfs, we set the sources.list to the default settings.
#mirror=http.kali.org
#security=security.kali.org
mirror=192.168.11.44
security=192.168.11.44

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign --arch $architecture kali kali-$architecture http://$mirror/kali

cp /usr/bin/qemu-arm-static kali-$architecture/usr/bin/

LANG=C chroot kali-$architecture /debootstrap/debootstrap --second-stage

# Create sources.list
cat << EOF > kali-$architecture/etc/apt/sources.list
deb http://$mirror/kali kali main contrib non-free
deb http://$security/kali-security kali/updates main contrib non-free
EOF

# Set hostname
echo "kali" > kali-$architecture/etc/hostname

# So X doesn't complain, we add kali to hosts
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
EOF

cat << EOF > kali-$architecture/etc/resolv.conf
nameserver 8.8.8.8
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

mount -t proc proc kali-$architecture/proc
mount -o bind /dev/ kali-$architecture/dev/
mount -o bind /dev/pts kali-$architecture/dev/pts

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
apt-get install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
sed -i -e 's/KERNEL\!=\"eth\*|/KERNEL\!=\"/' /lib/udev/rules.d/75-persistent-net-generator.rules
rm -f /etc/udev/rules.d/70-persistent-net.rules
apt-get --yes --force-yes install $packages

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod +x kali-$architecture/third-stage
LANG=C chroot kali-$architecture /third-stage

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
LANG=C chroot kali-$architecture /cleanup

umount kali-$architecture/proc/sys/fs/binfmt_misc
umount kali-$architecture/dev/pts
umount kali-$architecture/dev/
umount kali-$architecture/proc

echo "Creating image file for Acer Chromebook"
dd if=/dev/zero of=${basedir}/kali-$1-acer.img bs=1M count=14000
parted kali-$1-acer.img --script -- mklabel gpt
cgpt create -z kali-$1-acer.img
cgpt create kali-$1-acer.img

cgpt add -i 1 -t kernel -b 8192 -s 32768 -l kernel -S 1 -T 5 -P 10 kali-$1-acer.img
cgpt add -i 2 -t data -b 40960 -s `expr $(cgpt show kali-$1-acer.img | grep 'Sec GPT table' | awk '{ print \$1 }')  - 40960` -l Root kali-$1-acer.img

loopdevice=`losetup -f --show ${basedir}/kali-$1-acer.img`
device=`kpartx -va $loopdevice| sed -E 's/.*(loop[0-9])p.*/\1/g' | head -1`
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

mkfs.ext4 $rootp

mkdir -p ${basedir}/root
mount $rootp ${basedir}/root

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-$architecture/ ${basedir}/root/

cat << EOF > ${basedir}/root/etc/apt/sources.list
deb http://http.kali.org/kali kali main non-free contrib
deb http://security.kali.org/kali-security kali/updates main contrib non-free

deb-src http://http.kali.org/kali kali main non-free contrib
deb-src http://security.kali.org/kali-security kali/updates main contrib non-free
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section.  If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 file:///root/sandbox/mirror/chromebook.git -b chromeos-3.10 ${basedir}/kernel
cd ${basedir}/kernel
# Download the xhci firmware and build it in to the kernel so that USB booting
# will work in case someone generates their own USB booting image.
#wget http://gsdview.appspot.com/chromeos-localmirror/distfiles/xhci-firmware-2015.02.03.00.00.tbz2
wget http://gsdview.appspot.com/chromeos-localmirror/distfiles/xhci-firmware-2015.04.16.00.00.tbz2
tar --strip-components=5 -xf xhci-firmware-2015.04.16.00.00.tbz2 -C firmware
cp ${basedir}/../kernel-configs/chromebook-3.10.config .config
export ARCH=arm
# Edit the CROSS_COMPILE variable as needed.
export CROSS_COMPILE=arm-linux-gnueabihf-
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/mac80211-3.8.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/mwifiex-do-not-create-AP-and-P2P-interfaces-upon-driver-loading-3.8.patch
make WIFIVERSION="-3.8" -j $(grep -c processor /proc/cpuinfo)
make WIFIVERSION="-3.8" dtbs
make WIFIVERSION="-3.8" modules_install INSTALL_MOD_PATH=${basedir}/root
cat << __EOF__ > ${basedir}/kernel/arch/arm/boot/kernel-nyan.its
/dts-v1/;

/ {
    description = "Chrome OS kernel image with one or more FDT blobs";
    #address-cells = <1>;
    images {
        kernel@1{
   description = "kernel";
            data = /incbin/("zImage");
            type = "kernel_noload";
            arch = "arm";
            os = "linux";
            compression = "none";
            load = <0>;
            entry = <0>;
        };
        fdt@1{
            description = "tegra124-nyan-big.dtb";
            data = /incbin/("dts/tegra124-nyan-big.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@2{
            description = "tegra124-nyan-big-rev0_2.dtb";
            data = /incbin/("dts/tegra124-nyan-big-rev0_2.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@3{
            description = "tegra124-nyan-blaze.dtb";
            data = /incbin/("dts/tegra124-nyan-blaze.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@4{
            description = "tegra124-nyan-kitty.dtb";
            data = /incbin/("dts/tegra124-nyan-kitty.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@5{
            description = "tegra124-nyan-rev0.dtb";
            data = /incbin/("dts/tegra124-nyan-rev0.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@6{
            description = "tegra124-nyan-rev1.dtb";
            data = /incbin/("dts/tegra124-nyan-rev1.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
    };
    configurations {
        default = "conf@1";
        conf@1{
            kernel = "kernel@1";
            fdt = "fdt@1";
        };
        conf@2{
            kernel = "kernel@1";
            fdt = "fdt@2";
        };
        conf@3{
            kernel = "kernel@1";
            fdt = "fdt@3";
        };
        conf@4{
            kernel = "kernel@1";
            fdt = "fdt@4";
        };
        conf@5{
            kernel = "kernel@1";
            fdt = "fdt@5";
        };
        conf@6{
            kernel = "kernel@1";
            fdt = "fdt@6";
        };
    };
};
__EOF__
cd ${basedir}/kernel/arch/arm/boot
mkimage -f kernel-nyan.its nyan-big-kernel

# SD Card
echo "noinitrd console=tty1 quiet root=/dev/mmcblk1p2 rootwait rw lsm.module_locking=0 net.ifnames=0 rootfstype=ext4" > cmdline
# USB
#echo "noinitrd console=tty1 quiet root=/dev/sda2 rootwait rw lsm.module_locking=0 net.ifnames=0 rootfstype=ext4" > cmdline

vbutil_kernel --arch arm --pack ${basedir}/kernel.bin --keyblock /usr/share/vboot/devkeys/kernel.keyblock --signprivate /usr/share/vboot/devkeys/kernel_data_key.vbprivk --version 1 --config cmdline --vmlinuz nyan-big-kernel

cd ${basedir}

# Lid switch
cat << EOF > ${basedir}/root/etc/udev/rules.d/99-tegra-lid-switch.rules
ACTION=="remove", GOTO="tegra_lid_switch_end"

SUBSYSTEM=="input", KERNEL=="event*", SUBSYSTEMS=="platform",
KERNELS=="gpio-keys.4", TAG+="power-switch"

LABEL="tegra_lid_switch_end"
EOF

#nvidia device nodes
cat << EOF > ${basedir}/root/lib/udev/rules.d/51-nvrm.rules
KERNEL=="knvmap", GROUP="video", MODE="0660"
KERNEL=="nvhdcp1", GROUP="video", MODE="0660"
KERNEL=="nvhost-as-gpu", GROUP="video", MODE="0660"
KERNEL=="nvhost-ctrl", GROUP="video", MODE="0660"
KERNEL=="nvhost-ctrl-gpu", GROUP="video", MODE="0660"
KERNEL=="nvhost-dbg-gpu", GROUP="video", MODE="0660"
KERNEL=="nvhost-gpu", GROUP="video", MODE="0660"
KERNEL=="nvhost-msenc", GROUP="video", MODE=0660"
KERNEL=="nvhost-prof-gpu", GROUP="video", MODE=0660"
KERNEL=="nvhost-tsec", GROUP="video", MODE="0660"
KERNEL=="nvhost-vic", GROUP="video", MODE="0660"
KERNEL=="nvmap", GROUP="video", MODE="0660"
KERNEL=="tegra_dc_0", GROUP="video", MODE="0660"
KERNEL=="tegra_dc_1", GROUP="video", MODE="0660"
KERNEL=="tegra_dc_ctrl", GROUP="video", MODE="0660"
EOF

cat << EOF > ${basedir}/root/root/nvidia-l4t.sh
#!/bin/sh

L4TURL=http://developer.download.nvidia.com/embedded/L4T/r21_Release_v3.0/Tegra124_Linux_R21.3.0_armhf.tbz2
L4TFILE=Tegra124_Linux_R21.3.0_armhf.tbz2

# Remove it if it pre-exists...
rm -rf /tmp/l4t
mkdir -p /tmp/l4t
cd /tmp/l4t
wget \${L4TURL}
tar -xf \${L4TFILE}
cd Linux_for_Tegra/rootfs
tar -xf ../nv_tegra/nvidia_drivers.tbz2
tar -xf ../nv_tegra/config.tbz2
tar -xf ../nv_tegra/nv_sample_apps/nvgstapps.tbz2

cd usr
rm -rf sbin
cd bin
rm nvgst*-1.0
rm nvidia-bug-report-tegra.sh
cd ..
cd lib/arm-linux-gnueabihf
rm -rf gstreamer-1.0
rm libgstnvegl-1.0.so.0
cd ../../..

cd lib/firmware
cp -a * /lib/firmware

cd ../..
cd usr
cp -a * /usr/

cd /usr/lib/arm-linux-gnueabihf/tegra
ln -sf "libcuda.so.1.1" "libcuda.so"
cd ..
ln -sf "tegra/libcuda.so" "libcuda.so"
ln -sf "tegra/libGL.so.1" "libGL.so"

cd /tmp/l4t/Linux_for_Tegra/rootfs/etc/udev/rules.d
rm 99-nv-wifibt.rules
rm 91-xorg-conf-tegra.rules
cp * /etc/udev/rules.d/
cd ../..
cp enctune.conf /etc/
cd pulse
cp -a * /etc/pulse/
cd ..
cd X11
cp xorg.conf /etc/X11/xorg.conf.d/20-nvidia.conf
mv /etc/X11/xorg.conf.d/20-armsoc.conf /root/
mv /etc/X11/xorg.conf /root/
cd ..
echo "/usr/lib/arm-linux-gnueabihf/tegra" >> ld.so.conf.d/nvidia-tegra.conf
echo "/usr/lib/arm-linux-gnueabihf/tegra-egl" >> ld.so.conf.d/nvidia-tegra.conf
cp ld.so.conf.d/nvidia-tegra.conf /etc/ld.so.conf.d/
ldconfig

cd /etc/pulse
mv default.pa default.pa.dist
ln -sf default.pa.orig default.pa

echo "Done with everything! Please reboot!"
EOF
chmod +x ${basedir}/root/root/nvidia-l4t.sh

# Touchpad configuration
mkdir -p ${basedir}/root/etc/X11/xorg.conf.d
cat << EOF > ${basedir}/root/etc/X11/xorg.conf.d/10-synaptics-chromebook.conf
Section "InputClass"
	Identifier		"touchpad"
	MatchIsTouchpad		"on"
	Driver			"synaptics"
	Option			"TapButton1"	"1"
	Option			"TapButton2"	"3"
	Option			"TapButton3"	"2"
	Option			"FingerLow"	"15"
	Option			"FingerHigh"	"20"
	Option			"FingerPress"	"256"
EndSection
EOF
# Turn off DPMS, this is supposed to help with fbdev/armsoc blanking.
# Doesn't really seem to affect fbdev, but marked improvement with armsoc.
cat << EOF > ${basedir}/root/etc/X11/xorg.conf
Section "ServerFlags"
    Option     "NoTrapSignals" "true"
    Option     "DontZap" "false"

    # Disable DPMS timeouts.
    Option     "StandbyTime" "0"
    Option     "SuspendTime" "0"
    Option     "OffTime" "0"

    # Disable screen saver timeout.
    Option     "BlankTime" "0"
EndSection

Section "Monitor"
    Identifier "DefaultMonitor"
EndSection

Section "Device"
    Identifier "DefaultDevice"
    Option     "monitor-LVDS1" "DefaultMonitor"
EndSection

Section "Screen"
    Identifier "DefaultScreen"
    Monitor    "DefaultMonitor"
    Device     "DefaultDevice"
EndSection

Section "ServerLayout"
    Identifier "DefaultLayout"
    Screen     "DefaultScreen"
EndSection
EOF

# At the moment we use fbdev, but in the future, we will switch to the armsoc
# driver provided by ChromiumOS.
cat << EOF > ${basedir}/root/etc/X11/xorg.conf.d/20-armsoc.conf
Section "Device"
        Identifier      "Mali FBDEV"
#       Driver          "armsoc"
	Driver		"fbdev"
        Option          "fbdev"                 "/dev/fb0"
        Option          "Fimg2DExa"             "false"
        Option          "DRI2"                  "true"
        Option          "DRI2_PAGE_FLIP"        "false"
        Option          "DRI2_WAIT_VSYNC"       "true"
#       Option          "Fimg2DExaSolid"        "false"
#       Option          "Fimg2DExaCopy"         "false"
#       Option          "Fimg2DExaComposite"    "false"
        Option          "SWcursorLCD"           "false"
EndSection

Section "Screen"
        Identifier      "DefaultScreen"
        Device          "Mali FBDEV"
        DefaultDepth    24
EndSection
EOF

rm -rf ${basedir}/root/lib/firmware
cd ${basedir}/root/lib
git clone file:///root/sandbox/mirror/linux-firmware.git firmware
rm -rf ${basedir}/root/lib/firmware/.git
cd ${basedir}

# lp0 resume firmware...
git clone https://chromium.googlesource.com/chromiumos/third_party/coreboot
cd ${basedir}/coreboot
git checkout bf6110a05506d888b3e4452896e19e1f71f49afe
make -C src/soc/nvidia/tegra124/lp0 GCC_PREFIX=arm-linux-gnueabihf-
mkdir -p ${basedir}/root/lib/firmware/tegra12x/
cp src/soc/nvidia/tegra124/lp0/tegra_lp0_resume.fw ${basedir}/root/lib/firmware/tegra12x/
cd ${basedir}

# Touchpad config/firmware from ChromeOS.
cat << EOF > ${basedir}/root/lib/firmware/maxtouch-ts.cfg
OBP_RAW V1
a2 00 20 ab 20 34 21
969531
c652a4
0044 0000 0049 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0026 0000 0040 02 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0047 0000 00A8 00 3C 1E B0 00 00 00 00 00 00 03 01 00 C8 AF 00 00 00 00 00 FF 01 1E B0 00 00 00 00 00 00 03 01 00 FF FF 00 00 00 00 00 FF 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0007 0000 0004 1E FF DC 40
0008 0000 000A 74 00 14 14 00 00 FF 01 1E 00
0009 0000 002F 8F 00 00 20 34 00 5F 28 02 03 19 01 01 40 0A 14 14 05 FF 02 55 05 08 09 07 05 8E 1D 88 11 19 0F 31 32 00 00 45 E6 28 00 00 00 00 00 00 00 00
0009 0001 002F 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000F 0000 000B 00 00 00 00 00 00 00 00 00 00 00
0012 0000 0002 40 00
0013 0000 0006 00 00 00 00 00 00
0018 0000 0013 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0018 0001 0013 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0019 0000 0015 03 00 D0 67 30 58 00 00 00 00 00 00 00 00 C8 A0 0F 00 00 00 00
001B 0000 0007 00 00 00 00 00 00 00
001B 0001 0007 00 00 00 00 00 00 00
0028 0000 0005 00 00 00 00 00
0028 0001 0005 00 00 00 00 00
002A 0000 000D 01 28 32 2C 50 00 00 00 00 00 46 03 28
002A 0001 000D 00 00 00 00 00 00 00 00 00 00 00 00 00
002B 0000 000C 8C 00 90 00 00 01 14 00 00 00 00 6C
002E 0000 000B 29 00 10 10 00 00 01 00 00 00 10
002F 0000 001C 00 00 08 10 00 00 00 00 00 0F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
002F 0001 001C 00 00 00 00 00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0037 0000 0007 00 00 00 00 00 00 00
0037 0001 0007 00 00 00 00 00 00 00
0038 0000 0033 01 00 00 46 13 13 13 13 12 12 12 12 12 12 12 11 11 11 11 11 11 11 10 11 10 10 10 10 10 10 0F 0F 0F 0F 0F 0F 00 00 01 02 14 04 00 00 00 00 00 00 00 00 00
0039 0000 0003 E2 00 00
0039 0001 0003 00 00 00
003D 0000 0005 03 00 00 C8 AF
003D 0001 0005 03 00 00 FF FF
003D 0002 0005 00 00 00 00 00
003D 0003 0005 00 00 00 00 00
003E 0000 004A 7D 0A 00 12 08 00 20 00 2D 00 05 2D 1E 0F 05 00 0A 05 05 5A 1E 1E 14 0F 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
003F 0000 0019 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
003F 0001 0019 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0041 0000 0011 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0042 0000 0003 00 00 00
0046 0000 000A 00 00 00 00 00 00 00 00 00 00
0046 0001 000A 00 00 00 00 00 00 00 00 00 00
0046 0002 000A 00 00 00 00 00 00 00 00 00 00
0046 0003 000A 00 00 00 00 00 00 00 00 00 00
0046 0004 000A 00 00 00 00 00 00 00 00 00 00
0046 0005 000A 00 00 00 00 00 00 00 00 00 00
0046 0006 000A 00 00 00 00 00 00 00 00 00 00
0046 0007 000A 00 00 00 00 00 00 00 00 00 00
0046 0008 000A 00 00 00 00 00 00 00 00 00 00
0046 0009 000A 00 00 00 00 00 00 00 00 00 00
0046 000A 000A 00 00 00 00 00 00 00 00 00 00
0046 000B 000A 00 00 00 00 00 00 00 00 00 00
0049 0000 0006 00 00 00 00 00 00
0049 0001 0006 00 00 00 00 00 00
004D 0000 0004 00 00 00 00
004F 0000 0003 00 00 00
EOF

# Unmount partitions
umount $rootp

dd if=${basedir}/kernel.bin of=$bootp

kpartx -dv $loopdevice
losetup -d $loopdevice

# Clean up all the temporary build stuff and remove the directories.
# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Removing temporary build files"
rm -rf ${basedir}/coreboot ${basedir}/kernel ${basedir}/kernel.bin ${basedir}/root ${basedir}/kali-$architecture ${basedir}/patches

# If you're building an image for yourself, comment all of this out, as you
# don't need the sha1sum or to compress the image, since you will be testing it
# soon.
echo "Generating sha1sum for kali-$1-acer.img"
sha1sum kali-$1-acer.img > ${basedir}/kali-$1-acer.img.sha1sum
# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing kali-$1-acer.img"
pixz ${basedir}/kali-$1-acer.img ${basedir}/kali-$1-acer.img.xz
rm ${basedir}/kali-$1-acer.img
echo "Generating sha1sum for kali-$1-acer.img.xz"
sha1sum kali-$1-acer.img.xz > ${basedir}/kali-$1-acer.img.xz.sha1sum
fi
