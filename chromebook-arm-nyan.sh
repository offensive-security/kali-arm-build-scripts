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

basedir=`pwd`/nyan-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-nyan}
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
# This will build a minimal Gnome Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use.  You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="apt-transport-https apt-utils console-setup e2fsprogs firmware-linux firmware-realtek firmware-atheros firmware-libertas firmware-brcm80211 ifupdown initramfs-tools iw kali-defaults man-db mlocate netcat-traditional net-tools parted psmisc rfkill screen snmpd snmp sudo tftp tmux unrar usbutils vim wget zerofree"
desktop="kali-menu fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev xserver-xorg-input-synaptics xserver-xorg-input-all xserver-xorg-input-libinput"
tools="aircrack-ng crunch cewl dnsrecon dnsutils ethtool exploitdb hydra john libnfc-bin medusa metasploit-framework mfoc ncrack nmap passing-the-hash proxychains recon-ng sqlmap tcpdump theharvester tor tshark usbutils whois windows-binaries winexe wpscan wireshark"
services="apache2 atftpd openssh-server openvpn tightvncserver"
extras="bluez bluez-firmware firefox-esr xfce4-goodies xfce4-terminal wpasupplicant xfonts-terminus"

packages="${arm} ${base} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

kernel_release="R69-10895.B-chromeos-3.10"

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:3142/"

mkdir -p "${basedir}"
cd "${basedir}"

# create the rootfs - not much to modify here, except maybe throw in some more packages if you want.
debootstrap --foreign --keyring=/usr/share/keyrings/kali-archive-keyring.gpg --include=kali-archive-keyring --arch ${architecture} ${suite} kali-${architecture} http://${mirror}/kali

cp /usr/bin/qemu-arm-static kali-${architecture}/usr/bin/

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
apt-get -y install git-core binutils ca-certificates cryptsetup-bin initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove


# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

# Copy over the default bashrc
cp  /etc/skel/.bashrc /root/.bashrc

# Try and make the console a bit nicer
# Set the terminus font for a bit nicer display.
sed -i -e 's/FONTFACE=.*/FONTFACE="Terminus"/' /etc/default/console-setup
sed -i -e 's/FONTSIZE=.*/FONTSIZE="6x12"/' /etc/default/console-setup

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
deb http://http.kali.org/kali kali-rolling main contrib non-free
deb-src http://http.kali.org/kali kali-rolling main contrib non-free
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Pull in the gcc 5.3 cross compiler to build the kernel.
# Debian uses a 7.3 based kernel, and the chromebook kernel doesn't support
# that.
cd "${basedir}"
git clone https://github.com/offensive-security/gcc-arm-linux-gnueabihf-4.7

# Kernel section.  If you want to use a custom kernel, or configuration, replace
# them in this section.
cd "${basedir}"
git clone --depth 1 https://chromium.googlesource.com/chromiumos/third_party/kernel -b release-${kernel_release} "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
mkdir -p "${basedir}"/kali-${architecture}/usr/src/kernel/firmware/nvidia/tegra124/
cp "${basedir}"/kali-${architecture}/lib/firmware/nvidia/tegra124/xusb.bin firmware/nvidia/tegra124/
cp "${basedir}"/../kernel-configs/chromebook-3.10.config .config
cp "${basedir}"/../kernel-configs/chromebook-3.10.config "${basedir}"/kali-${architecture}/usr/src/nyan.config
git rev-parse HEAD > "${basedir}"/kali-${architecture}/usr/src/kernel-at-commit
export ARCH=arm
# Edit the CROSS_COMPILE variable as needed.
export CROSS_COMPILE="${basedir}"/gcc-arm-linux-gnueabihf-4.7/bin/arm-linux-gnueabihf-
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/mac80211-3.8.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-mwifiex-do-not-create-AP-and-P2P-interfaces-upon-dri-3.8.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-Comment-out-a-pr_debug-print.patch
make WIFIVERSION="-3.8" oldconfig || die "Kernel config options added"
make WIFIVERSION="-3.8" -j $(grep -c processor /proc/cpuinfo)
make WIFIVERSION="-3.8" dtbs
make WIFIVERSION="-3.8" modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cat << __EOF__ > "${basedir}"/kali-${architecture}/usr/src/kernel/arch/arm/boot/kernel-nyan.its
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
            description = "tegra124-nyan-big-rev0_2.dtb";
            data = /incbin/("dts/tegra124-nyan-big-rev0_2.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@2{
            description = "tegra124-nyan-big-rev3_7.dtb";
            data = /incbin/("dts/tegra124-nyan-big-rev3_7.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@3{
            description = "tegra124-nyan-big-rev8_9.dtb";
            data = /incbin/("dts/tegra124-nyan-big-rev8_9.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@4{
            description = "tegra124-nyan-blaze.dtb";
            data = /incbin/("dts/tegra124-nyan-blaze.dtb");
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
        fdt@7{
            description = "tegra124-nyan-kitty-rev0_3.dtb";
            data = /incbin/("dts/tegra124-nyan-kitty-rev0_3.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@8{
            description = "tegra124-nyan-kitty-rev8.dtb";
            data = /incbin/("dts/tegra124-nyan-kitty-rev8.dtb");
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
        conf@7{
            kernel = "kernel@1";
            fdt = "fdt@7";
        };
        conf@8{
            kernel = "kernel@1";
            fdt = "fdt@8";
        };
    };
};
__EOF__
cd "${basedir}"/kali-${architecture}/usr/src/kernel/arch/arm/boot
mkimage -f kernel-nyan.its nyan-big-kernel

# BEHOLD THE POWER OF PARTUUID/PARTNROFF
echo "noinitrd console=tty1 quiet root=PARTUUID=%U/PARTNROFF=1 rootwait rw lsm.module_locking=0 net.ifnames=0 rootfstype=ext4" > cmdline

# Pulled from ChromeOS, this is exactly what they do because there's no
# # bootloader in the kernel partition on ARM.
dd if=/dev/zero of=bootloader.bin bs=512 count=1

vbutil_kernel --arch arm --pack "${basedir}"/kernel.bin --keyblock /usr/share/vboot/devkeys/kernel.keyblock --signprivate /usr/share/vboot/devkeys/kernel_data_key.vbprivk --version 1 --config cmdline --bootloader bootloader.bin --vmlinuz nyan-big-kernel

cd "${basedir}"/kali-${architecture}/usr/src/kernel
# Clean up our build of the kernel, then copy the config and run make
# modules_prepare so that users can more easily build kernel modules...
make WIFIVERSION="-3.8"  mrproper
cp ../nyan.config .config
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

# Lid switch
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-tegra-lid-switch.rules
ACTION=="remove", GOTO="tegra_lid_switch_end"
SUBSYSTEM=="input", KERNEL=="event*", SUBSYSTEMS=="platform", KERNELS=="gpio-keys.4", TAG+="power-switch"
LABEL="tegra_lid_switch_end"
EOF

# Bit of a hack, this is so the eMMC doesn't show up on the desktop
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-hide-emmc-partitions.rules
KERNEL=="mmcblk0*", ENV{UDISKS_IGNORE}="1"
EOF

# Disable uap0 and p2p0 interfaces in NetworkManager
printf '\n[keyfile]\nunmanaged-devices=interface-name:p2p0\n' >> "${basedir}"/kali-${architecture}/etc/NetworkManager/NetworkManager.conf

#nvidia device nodes
cat << EOF > "${basedir}"/kali-${architecture}/lib/udev/rules.d/51-nvrm.rules
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

# Touchpad configuration
mkdir -p "${basedir}"/kali-${architecture}/etc/X11/xorg.conf.d
cat << EOF > "${basedir}"/kali-${architecture}/etc/X11/xorg.conf.d/10-synaptics-chromebook.conf
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

# lp0 resume firmware...
# Check https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/sys-kernel/tegra_lp0_resume/
# to find the lastest commit to use (note: CROS_WORKON_COMMIT )
cd "${basedir}"
git clone https://chromium.googlesource.com/chromiumos/third_party/coreboot
cd "${basedir}"/coreboot
git checkout fb840ee4195f9c365375e8914e243ce2f5e4f7bf
make -C src/soc/nvidia/tegra124/lp0 GCC_PREFIX=arm-linux-gnueabihf-
mkdir -p "${basedir}"/kali-${architecture}/lib/firmware/tegra12x/
cp src/soc/nvidia/tegra124/lp0/tegra_lp0_resume.fw "${basedir}"/kali-${architecture}/lib/firmware/tegra12x/
cd "${basedir}"

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

echo "Creating image file for ${imagename}.img"
dd if=/dev/zero of="${basedir}"/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel gpt
cgpt create -z ${imagename}.img
cgpt create ${imagename}.img

cgpt add -i 1 -t kernel -b 8192 -s 32768 -l kernel -S 1 -T 5 -P 10 ${imagename}.img
cgpt add -i 2 -t data -b 40960 -s `expr $(cgpt show ${imagename}.img | grep 'Sec GPT table' | awk '{ print \$1 }')  - 40960` -l Root ${imagename}.img

loopdevice=`losetup -f --show "${basedir}"/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

mkfs.ext4 -O ^flex_bg -O ^metadata_csum -L rootfs ${rootp}

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

dd if="${basedir}"/kernel.bin of=${bootp}

cgpt repair ${loopdevice}

kpartx -dv ${loopdevice}
losetup -d ${loopdevice}


# If you're building an image for yourself, comment all of this out, as you
# don't need to compress the image, since you will be testing it
# soon.
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
echo "Removing temporary build files"
rm -rf "${basedir}"
