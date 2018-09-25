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

basedir=`pwd`/veyron-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-veyron}
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
# This will build a minimal Kali system with XFCE and a few tools.
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
extras="bluez bluez-firmware florence firefox-esr xfce4-goodies xfce4-terminal xfonts-terminus xinput wpasupplicant"

packages="${arm} ${base} ${services} ${extras}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Unused currently, but can be used to point at a specific release.
kernel_release="R67-10575.B-chromeos-3.14"

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

mkdir -p mkdir -p kali-${architecture}/etc/network/
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
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
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

cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

#umount kali-$architecture/proc/sys/fs/binfmt_misc
#umount kali-$architecture/dev/pts
#umount kali-$architecture/dev/
#umount kali-$architecture/proc

cat << EOF > "${basedir}"/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main contrib non-free
deb-src http://http.kali.org/kali kali-rolling main contrib non-free
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# The kernel doesn't like GCC 8, so we use an older cross compiler.
# Really need to look into getting the mainline kernel working :(
cd "${basedir}"
git clone https://github.com/offensive-security/gcc-arm-linux-gnueabihf-4.7

# Kernel section.  If you want to use a custom kernel, or configuration, replace
# them in this section.
git clone --depth 1 https://chromium.googlesource.com/chromiumos/third_party/kernel -b chromeos-3.14 "${basedir}"/kali-${architecture}/usr/src/kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
cp "${basedir}"/../kernel-configs/chromebook-3.14_wireless-3.8.config .config
cp .config "${basedir}"/kali-${architecture}/usr/src/veyron.config
export ARCH=arm
# Edit the CROSS_COMPILE variable as needed.
export CROSS_COMPILE="${basedir}"/gcc-arm-linux-gnueabihf-4.7/bin/arm-linux-gnueabihf-
# This allows us to patch the kernel without it adding -dirty to the kernel version.
touch .scmversion
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/mac80211-3.8.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0002-mwifiex-do-not-create-AP-and-P2P-interfaces-upon-dri.patch
# Commented out as it causes issues, but if you want to use the usb port as a
# serial port, you can uncomment this and build an image with it enabled.
#patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0003-UPSTREAM-soc-rockchip-add-handler-for-usb-uart-funct.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0004-fix-brcmfmac-oops-and-race-condition.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/0001-Update-carl9170-in-wireless-3.8-for-3.14-s-changes.patch
# Backported patch to support building the kernel with GCC newer than 5.
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/3711edaf01a01818f2aed9f21efe29b9818134b9.patch
patch -p1 --no-backup-if-mismatch < "${basedir}"/../patches/615829a03dc729e78372d40d95ba40e2ad51783b.patch
make WIFIVERSION="-3.8" oldconfig || die "Kernel config options added"
make WIFIVERSION="-3.8" -j$(grep -c processor /proc/cpuinfo)
make WIFIVERSION="-3.8" dtbs
make WIFIVERSION="-3.8" modules_install INSTALL_MOD_PATH="${basedir}"/kali-${architecture}
cat << __EOF__ > "${basedir}"/kali-${architecture}/usr/src/kernel/arch/arm/boot/kernel-veyron.its
/dts-v1/;
 
/ {
    description = "Chrome OS kernel image with one or more FDT blobs";
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
            description = "rk3288-brain-rev0.dtb";
            data = /incbin/("dts/rk3288-brain-rev0.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@2{
            description = "rk3288-danger-rev0.dtb";
            data = /incbin/("dts/rk3288-danger-rev0.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@3{
            description = "rk3288-danger-rev1.dtb";
            data = /incbin/("dts/rk3288-danger-rev1.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@4{
            description = "rk3288-emile-rev0.dtb";
            data = /incbin/("dts/rk3288-emile-rev0.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@5{
            description = "rk3288-evb-act8846.dtb";
            data = /incbin/("dts/rk3288-evb-act8846.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@6{
	    description = "rk3288-evb-rk808.dtb";
	    data = /incbin/("dts/rk3288-evb-rk808.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@7{
	    description = "rk3288-fievel-rev0.dtb";
	    data = /incbin/("dts/rk3288-fievel-rev0.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@8{
	    description = "rk3288-gus-rev1.dtb";
	    data = /incbin/("dts/rk3288-gus-rev1.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@9{
	    description = "rk3288-jaq-rev1.dtb";
	    data = /incbin/("dts/rk3288-jaq-rev1.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@10{
	    description = "rk3288-jerry-rev10.dtb";
	    data = /incbin/("dts/rk3288-jerry-rev10.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@11{
	    description = "rk3288-jerry-rev2.dtb";
	    data = /incbin/("dts/rk3288-jerry-rev2.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@12{
	    description = "rk3288-jerry-rev3.dtb";
	    data = /incbin/("dts/rk3288-jerry-rev3.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@13{
	    description = "rk3288-mickey-rev0.dtb";
	    data = /incbin/("dts/rk3288-mickey-rev0.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@14{
	    description = "rk3288-mighty-rev1.dtb";
	    data = /incbin/("dts/rk3288-mighty-rev1.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@15{
	    description = "rk3288-minnie-rev0.dtb";
	    data = /incbin/("dts/rk3288-minnie-rev0.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@16{
	    description = "rk3288-nicky-rev0.dtb";
	    data = /incbin/("dts/rk3288-nicky-rev0.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@17{
	    description = "rk3288-rialto-rev0.dtb";
	    data = /incbin/("dts/rk3288-rialto-rev0.dtb");
	    type = "flat_dt";
	    arch = "arm";
	    compression = "none";
	    hash@1{
		algo = "sha1";
	    };
	};
        fdt@18{
        description = "rk3288-rialto-rev1.dtb";
        data = /incbin/("dts/rk3288-rialto-rev1.dtb");
        type = "flat_dt";
        arch = "arm";
        compression = "none";
        hash@1{
        algo = "sha1";
        };
    };
        fdt@19{
            description = "rk3288-speedy.dtb";
            data = /incbin/("dts/rk3288-speedy.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@20{
            description = "rk3288-speedy-rev1.dtb";
            data = /incbin/("dts/rk3288-speedy-rev1.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@21{
            description = "rk3288-thea-rev0.dtb";
            data = /incbin/("dts/rk3288-thea-rev0.dtb");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
            hash@1{
                algo = "sha1";
            };
        };
        fdt@22{
            description = "rk3288-tiger-rev0.dtb";
            data = /incbin/("dts/rk3288-tiger-rev0.dtb");
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
	    conf@9{
	        kernel = "kernel@1";
	        fdt = "fdt@9";
	    };
	    conf@10{
	        kernel = "kernel@1";
	        fdt = "fdt@10";
	    };
	    conf@11{
	        kernel = "kernel@1";
	        fdt = "fdt@11";
	    };
	    conf@12{
	        kernel = "kernel@1";
	        fdt = "fdt@12";
	    };
	    conf@13{
	        kernel = "kernel@1:";
	        fdt = "fdt@13";
	    };
	    conf@14{
	        kernel = "kernel@1";
	        fdt = "fdt@14";
	    };
	    conf@15{
	        kernel = "kernel@1";
	        fdt = "fdt@15";
	    };
	    conf@16{
	        kernel = "kernel@1";
	        fdt = "fdt@16";
	    };
	    conf@17{
	        kernel = "kernel@1";
	        fdt = "fdt@17";
	    };
        conf@18{
            kernel = "kernel@1";
            fdt = "fdt@18";
        };
        conf@19{
            kernel = "kernel@1";
            fdt = "fdt@19";
        };
        conf@20{
            kernel = "kernel@1";
            fdt = "fdt@20";
        };
        conf@21{
            kernel = "kernel@1";
            fdt = "fdt@21";
        };
        conf@22{
            kernel = "kernel@1";
            fdt = "fdt@22";
        };
    };
};
__EOF__
cd "${basedir}"/kali-${architecture}/usr/src/kernel/arch/arm/boot
mkimage -D "-I dts -O dtb -p 2048" -f kernel-veyron.its veyron-kernel

# BEHOLD THE MAGIC OF PARTUUID/PARTNROFF
echo 'noinitrd console=tty1 quiet root=PARTUUID=%U/PARTNROFF=1 rootwait rw lsm.module_locking=0 net.ifnames=0 rootfstype=ext4' > cmdline

# Pulled from ChromeOS, this is exactly what they do because there's no
# bootloader in the kernel partition on ARM.
dd if=/dev/zero of=bootloader.bin bs=512 count=1

vbutil_kernel --arch arm --pack "${basedir}"/kernel.bin --keyblock /usr/share/vboot/devkeys/kernel.keyblock --signprivate /usr/share/vboot/devkeys/kernel_data_key.vbprivk --version 1 --config cmdline --bootloader bootloader.bin --vmlinuz veyron-kernel
cd "${basedir}"/kali-${architecture}/usr/src/kernel
make WIFIVERSION="-3.8" mrproper
cp "${basedir}"/../kernel-configs/chromebook-3.14_wireless-3.8.config .config
make WIFIVERSION="-3.8" modules_prepare
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

# Bit of a hack to hide the emmc partitions from XFCE
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-hide-emmc-partitions.rules
KERNEL=="mmcblk0*", ENV{UDISKS_IGNORE}="1"
EOF

# Disable uap0 and p2p0 interfaces in NetworkManager
echo -e '\n[keyfile]\nunmanaged-devices=interface-name:p2p0\n' >> "${basedir}"/kali-${architecture}/etc/NetworkManager/NetworkManager.conf

# Create these if they don't exist, to make sure we have proper audio with pulse
mkdir -p "${basedir}"/kali-${architecture}/var/lib/alsa/
cat << EOF > "${basedir}"/kali-${architecture}/var/lib/alsa/asound.state
state.ROCKCHIPI2S {
    control.1 {
        iface MIXER
        name 'MIC Bias VCM Bandgap'
        value 'High Performance'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'Low Power'
            item.1 'High Performance'
        }
    }
    control.2 {
        iface MIXER
        name 'DMIC MIC Comp Filter Config'
        value 6
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
        }
    }
    control.3 {
        iface MIXER
        name 'MIC1 Boost Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 2'
            dbmin 0
            dbmax 3000
            dbvalue.0 0
        }
    }
    control.4 {
        iface MIXER
        name 'MIC2 Boost Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 2'
            dbmin 0
            dbmax 3000
            dbvalue.0 0
        }
    }
    control.5 {
        iface MIXER
        name 'MIC1 Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 20'
            dbmin 0
            dbmax 2000
            dbvalue.0 0
        }
    }
    control.6 {
        iface MIXER
        name 'MIC2 Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 20'
            dbmin 0
            dbmax 2000
            dbvalue.0 0
        }
    }
    control.7 {
        iface MIXER
        name 'LINEA Single Ended Volume'
        value 1
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 1'
            dbmin -600
            dbmax 0
            dbvalue.0 0
        }
    }
    control.8 {
        iface MIXER
        name 'LINEB Single Ended Volume'
        value 1
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 1'
            dbmin -600
            dbmax 0
            dbvalue.0 0
        }
    }
    control.9 {
        iface MIXER
        name 'LINEA Volume'
        value 2
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 5'
            dbmin -600
            dbmax 2000
            dbvalue.0 0
        }
    }
    control.10 {
        iface MIXER
        name 'LINEB Volume'
        value 2
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 5'
            dbmin -600
            dbmax 2000
            dbvalue.0 0
        }
    }
    control.11 {
        iface MIXER
        name 'LINEA Ext Resistor Gain Mode'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.12 {
        iface MIXER
        name 'LINEB Ext Resistor Gain Mode'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.13 {
        iface MIXER
        name 'ADCL Boost Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 7'
            dbmin 0
            dbmax 4200
            dbvalue.0 0
        }
    }
    control.14 {
        iface MIXER
        name 'ADCR Boost Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 7'
            dbmin 0
            dbmax 4200
            dbvalue.0 0
        }
    }
    control.15 {
        iface MIXER
        name 'ADCL Volume'
        value 12
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
            dbmin -1200
            dbmax 300
            dbvalue.0 0
        }
    }
    control.16 {
        iface MIXER
        name 'ADCR Volume'
        value 12
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
            dbmin -1200
            dbmax 300
            dbvalue.0 0
        }
    }
    control.17 {
        iface MIXER
        name 'ADC Oversampling Rate'
        value '128*fs'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 '64*fs'
            item.1 '128*fs'
        }
    }
    control.18 {
        iface MIXER
        name 'ADC Quantizer Dither'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.19 {
        iface MIXER
        name 'ADC High Performance Mode'
        value 'High Performance'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'Low Power'
            item.1 'High Performance'
        }
    }
    control.20 {
        iface MIXER
        name 'DAC Mono Mode'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.21 {
        iface MIXER
        name 'SDIN Mode'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.22 {
        iface MIXER
        name 'SDOUT Mode'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.23 {
        iface MIXER
        name 'SDOUT Hi-Z Mode'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.24 {
        iface MIXER
        name 'Filter Mode'
        value Music
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Voice
            item.1 Music
        }
    }
    control.25 {
        iface MIXER
        name 'Record Path DC Blocking'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.26 {
        iface MIXER
        name 'Playback Path DC Blocking'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.27 {
        iface MIXER
        name 'Digital BQ Volume'
        value 15
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
            dbmin -1500
            dbmax 0
            dbvalue.0 0
        }
    }
    control.28 {
        iface MIXER
        name 'Digital Sidetone Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 30'
            dbmin 0
            dbmax 3000
            dbvalue.0 0
        }
    }
    control.29 {
        iface MIXER
        name 'Digital Coarse Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin 0
            dbmax 1800
            dbvalue.0 0
        }
    }
    control.30 {
        iface MIXER
        name 'Digital Volume'
        value 15
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
            dbmin -1500
            dbmax 0
            dbvalue.0 0
        }
    }
    control.31 {
        iface MIXER
        name 'EQ Coefficients'
        value '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        comment {
            access 'read write'
            type BYTES
            count 105
        }
    }
    control.32 {
        iface MIXER
        name 'Digital EQ 3 Band Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.33 {
        iface MIXER
        name 'Digital EQ 5 Band Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.34 {
        iface MIXER
        name 'Digital EQ 7 Band Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.35 {
        iface MIXER
        name 'Digital EQ Clipping Detection'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.36 {
        iface MIXER
        name 'Digital EQ Volume'
        value 15
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 15'
            dbmin -1500
            dbmax 0
            dbvalue.0 0
        }
    }
    control.37 {
        iface MIXER
        name 'ALC Enable'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.38 {
        iface MIXER
        name 'ALC Attack Time'
        value '0.5ms'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 '0.5ms'
            item.1 '1ms'
            item.2 '5ms'
            item.3 '10ms'
            item.4 '25ms'
            item.5 '50ms'
            item.6 '100ms'
            item.7 '200ms'
        }
    }
    control.39 {
        iface MIXER
        name 'ALC Release Time'
        value '8s'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 '8s'
            item.1 '4s'
            item.2 '2s'
            item.3 '1s'
            item.4 '0.5s'
            item.5 '0.25s'
            item.6 '0.125s'
            item.7 '0.0625s'
        }
    }
    control.40 {
        iface MIXER
        name 'ALC Make Up Volume'
        value 0
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 12'
            dbmin 0
            dbmax 1200
            dbvalue.0 0
        }
    }
    control.41 {
        iface MIXER
        name 'ALC Compression Ratio'
        value '1:1'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 '1:1'
            item.1 '1:1.5'
            item.2 '1:2'
            item.3 '1:4'
            item.4 '1:INF'
        }
    }
    control.42 {
        iface MIXER
        name 'ALC Expansion Ratio'
        value '1:1'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 '1:1'
            item.1 '2:1'
            item.2 '3:1'
        }
    }
    control.43 {
        iface MIXER
        name 'ALC Compression Threshold Volume'
        value 31
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 31'
            dbmin -3100
            dbmax 0
            dbvalue.0 0
        }
    }
    control.44 {
        iface MIXER
        name 'ALC Expansion Threshold Volume'
        value 31
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 31'
            dbmin -6600
            dbmax -3500
            dbvalue.0 -3500
        }
    }
    control.45 {
        iface MIXER
        name 'DAC HP Playback Performance Mode'
        value 'High Performance'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'High Performance'
            item.1 'Low Power'
        }
    }
    control.46 {
        iface MIXER
        name 'DAC High Performance Mode'
        value 'High Performance'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'Low Power'
            item.1 'High Performance'
        }
    }
    control.47 {
        iface MIXER
        name 'Headphone Left Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.48 {
        iface MIXER
        name 'Headphone Right Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.49 {
        iface MIXER
        name 'Speaker Left Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.50 {
        iface MIXER
        name 'Speaker Right Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.51 {
        iface MIXER
        name 'Receiver Left Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.52 {
        iface MIXER
        name 'Receiver Right Mixer Volume'
        value 3
        comment {
            access 'read write'
            type INTEGER
            count 1
            range '0 - 3'
            dbmin -1200
            dbmax 0
            dbvalue.0 0
        }
    }
    control.53 {
        iface MIXER
        name 'Headphone Volume'
        value.0 0
        value.1 0
        comment {
            access 'read write'
            type INTEGER
            count 2
            range '0 - 31'
            dbmin -6700
            dbmax 300
            dbvalue.0 -6700
            dbvalue.1 -6700
        }
    }
    control.54 {
        iface MIXER
        name 'Speaker Volume'
        value.0 39
        value.1 39
        comment {
            access 'read write'
            type INTEGER
            count 2
            range '0 - 39'
            dbmin -4800
            dbmax 1400
            dbvalue.0 1400
            dbvalue.1 1400
        }
    }
    control.55 {
        iface MIXER
        name 'Receiver Volume'
        value.0 21
        value.1 21
        comment {
            access 'read write'
            type INTEGER
            count 2
            range '0 - 31'
            dbmin -6200
            dbmax 800
            dbvalue.0 0
            dbvalue.1 0
        }
    }
    control.56 {
        iface MIXER
        name 'Headphone Left Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.57 {
        iface MIXER
        name 'Headphone Right Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.58 {
        iface MIXER
        name 'Speaker Left Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.59 {
        iface MIXER
        name 'Speaker Right Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.60 {
        iface MIXER
        name 'Receiver Left Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.61 {
        iface MIXER
        name 'Receiver Right Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.62 {
        iface MIXER
        name 'Zero-Crossing Detection'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.63 {
        iface MIXER
        name 'Enhanced Vol Smoothing'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.64 {
        iface MIXER
        name 'Volume Adjustment Smoothing'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.65 {
        iface MIXER
        name 'Biquad Coefficients'
        value '000000000000000000000000000000'
        comment {
            access 'read write'
            type BYTES
            count 15
        }
    }
    control.66 {
        iface MIXER
        name 'Biquad Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.67 {
        iface MIXER
        name 'Headphone Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.68 {
        iface MIXER
        name 'Headset Mic Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.69 {
        iface MIXER
        name 'Int Mic Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.70 {
        iface MIXER
        name 'Speaker Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.71 {
        iface MIXER
        name 'MIXHPRSEL Mux'
        value 'DAC Only'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'DAC Only'
            item.1 'HP Mixer'
        }
    }
    control.72 {
        iface MIXER
        name 'MIXHPLSEL Mux'
        value 'DAC Only'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'DAC Only'
            item.1 'HP Mixer'
        }
    }
    control.73 {
        iface MIXER
        name 'LINMOD Mux'
        value 'Left Only'
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 'Left Only'
            item.1 'Left and Right'
        }
    }
    control.74 {
        iface MIXER
        name 'Right Receiver Mixer Left DAC Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.75 {
        iface MIXER
        name 'Right Receiver Mixer Right DAC Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.76 {
        iface MIXER
        name 'Right Receiver Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.77 {
        iface MIXER
        name 'Right Receiver Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.78 {
        iface MIXER
        name 'Right Receiver Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.79 {
        iface MIXER
        name 'Right Receiver Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.80 {
        iface MIXER
        name 'Left Receiver Mixer Left DAC Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.81 {
        iface MIXER
        name 'Left Receiver Mixer Right DAC Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.82 {
        iface MIXER
        name 'Left Receiver Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.83 {
        iface MIXER
        name 'Left Receiver Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.84 {
        iface MIXER
        name 'Left Receiver Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.85 {
        iface MIXER
        name 'Left Receiver Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.86 {
        iface MIXER
        name 'Right Speaker Mixer Left DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.87 {
        iface MIXER
        name 'Right Speaker Mixer Right DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.88 {
        iface MIXER
        name 'Right Speaker Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.89 {
        iface MIXER
        name 'Right Speaker Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.90 {
        iface MIXER
        name 'Right Speaker Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.91 {
        iface MIXER
        name 'Right Speaker Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.92 {
        iface MIXER
        name 'Left Speaker Mixer Left DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.93 {
        iface MIXER
        name 'Left Speaker Mixer Right DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.94 {
        iface MIXER
        name 'Left Speaker Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.95 {
        iface MIXER
        name 'Left Speaker Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.96 {
        iface MIXER
        name 'Left Speaker Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.97 {
        iface MIXER
        name 'Left Speaker Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.98 {
        iface MIXER
        name 'Right Headphone Mixer Left DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.99 {
        iface MIXER
        name 'Right Headphone Mixer Right DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.100 {
        iface MIXER
        name 'Right Headphone Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.101 {
        iface MIXER
        name 'Right Headphone Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.102 {
        iface MIXER
        name 'Right Headphone Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.103 {
        iface MIXER
        name 'Right Headphone Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.104 {
        iface MIXER
        name 'Left Headphone Mixer Left DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.105 {
        iface MIXER
        name 'Left Headphone Mixer Right DAC Switch'
        value true
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.106 {
        iface MIXER
        name 'Left Headphone Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.107 {
        iface MIXER
        name 'Left Headphone Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.108 {
        iface MIXER
        name 'Left Headphone Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.109 {
        iface MIXER
        name 'Left Headphone Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.110 {
        iface MIXER
        name 'STENR Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 'Sidetone Right'
        }
    }
    control.111 {
        iface MIXER
        name 'STENL Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 'Sidetone Left'
        }
    }
    control.112 {
        iface MIXER
        name 'LTENR Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 Loopthrough
        }
    }
    control.113 {
        iface MIXER
        name 'LTENL Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 Loopthrough
        }
    }
    control.114 {
        iface MIXER
        name 'LBENR Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 Loopback
        }
    }
    control.115 {
        iface MIXER
        name 'LBENL Mux'
        value Normal
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 Normal
            item.1 Loopback
        }
    }
    control.116 {
        iface MIXER
        name 'Right ADC Mixer IN12 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.117 {
        iface MIXER
        name 'Right ADC Mixer IN34 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.118 {
        iface MIXER
        name 'Right ADC Mixer IN56 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.119 {
        iface MIXER
        name 'Right ADC Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.120 {
        iface MIXER
        name 'Right ADC Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.121 {
        iface MIXER
        name 'Right ADC Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.122 {
        iface MIXER
        name 'Right ADC Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.123 {
        iface MIXER
        name 'Left ADC Mixer IN12 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.124 {
        iface MIXER
        name 'Left ADC Mixer IN34 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.125 {
        iface MIXER
        name 'Left ADC Mixer IN56 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.126 {
        iface MIXER
        name 'Left ADC Mixer LINEA Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.127 {
        iface MIXER
        name 'Left ADC Mixer LINEB Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.128 {
        iface MIXER
        name 'Left ADC Mixer MIC1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.129 {
        iface MIXER
        name 'Left ADC Mixer MIC2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.130 {
        iface MIXER
        name 'LINEB Mixer IN2 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.131 {
        iface MIXER
        name 'LINEB Mixer IN4 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.132 {
        iface MIXER
        name 'LINEB Mixer IN6 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.133 {
        iface MIXER
        name 'LINEB Mixer IN56 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.134 {
        iface MIXER
        name 'LINEA Mixer IN1 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.135 {
        iface MIXER
        name 'LINEA Mixer IN3 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.136 {
        iface MIXER
        name 'LINEA Mixer IN5 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.137 {
        iface MIXER
        name 'LINEA Mixer IN34 Switch'
        value false
        comment {
            access 'read write'
            type BOOLEAN
            count 1
        }
    }
    control.138 {
        iface MIXER
        name 'DMIC Mux'
        value ADC
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 ADC
            item.1 DMIC
        }
    }
    control.139 {
        iface MIXER
        name 'MIC2 Mux'
        value IN34
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 IN34
            item.1 IN56
        }
    }
    control.140 {
        iface MIXER
        name 'MIC1 Mux'
        value IN12
        comment {
            access 'read write'
            type ENUMERATED
            count 1
            item.0 IN12
            item.1 IN56
        }
    }
}
state.RockchipHDMI {
    control {
    }
}
EOF

cat << EOF > "${basedir}"/kali-${architecture}/etc/pulse/default.pa
#!/usr/bin/pulseaudio -nF
#
# This file is part of PulseAudio.
#
# PulseAudio is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# PulseAudio is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.

# This startup script is used only if PulseAudio is started per-user
# (i.e. not in system mode)

.nofail

### Load something into the sample cache
#load-sample-lazy x11-bell /usr/share/sounds/freedesktop/stereo/bell.oga
#load-sample-lazy pulse-hotplug /usr/share/sounds/freedesktop/stereo/device-added.oga
#load-sample-lazy pulse-coldplug /usr/share/sounds/freedesktop/stereo/device-added.oga
#load-sample-lazy pulse-access /usr/share/sounds/freedesktop/stereo/message.oga

.fail

### Automatically restore the volume of streams and devices
load-module module-device-restore
load-module module-stream-restore
load-module module-card-restore

### Automatically augment property information from .desktop files
### stored in /usr/share/application
load-module module-augment-properties

### Should be after module-*-restore but before module-*-detect
load-module module-switch-on-port-available

### Load audio drivers statically
### (it's probably better to not load these drivers manually, but instead
### use module-udev-detect -- see below -- for doing this automatically)
load-module module-alsa-sink device=plughw:0,0
#load-module module-alsa-source device=hw:1,0
#load-module module-oss device="/dev/dsp" sink_name=output source_name=input
#load-module module-oss-mmap device="/dev/dsp" sink_name=output source_name=input
#load-module module-null-sink
#load-module module-pipe-sink

### Automatically load driver modules depending on the hardware available
.ifexists module-udev-detect.so
load-module module-udev-detect
.else
### Use the static hardware detection module (for systems that lack udev support)
load-module module-detect
.endif

### Automatically connect sink and source if JACK server is present
.ifexists module-jackdbus-detect.so
.nofail
load-module module-jackdbus-detect channels=2
.fail
.endif

### Automatically load driver modules for Bluetooth hardware
.ifexists module-bluetooth-policy.so
load-module module-bluetooth-policy
.endif

.ifexists module-bluetooth-discover.so
load-module module-bluetooth-discover
.endif

### Load several protocols
.ifexists module-esound-protocol-unix.so
load-module module-esound-protocol-unix
.endif
load-module module-native-protocol-unix

### Network access (may be configured with paprefs, so leave this commented
### here if you plan to use paprefs)
#load-module module-esound-protocol-tcp
#load-module module-native-protocol-tcp
#load-module module-zeroconf-publish

### Load the RTP receiver module (also configured via paprefs, see above)
#load-module module-rtp-recv

### Load the RTP sender module (also configured via paprefs, see above)
#load-module module-null-sink sink_name=rtp format=s16be channels=2 rate=44100 sink_properties="device.description='RTP Multicast Sink'"
#load-module module-rtp-send source=rtp.monitor

### Load additional modules from GConf settings. This can be configured with the paprefs tool.
### Please keep in mind that the modules configured by paprefs might conflict with manually
### loaded modules.
.ifexists module-gconf.so
.nofail
load-module module-gconf
.fail
.endif

### Automatically restore the default sink/source when changed by the user
### during runtime
### NOTE: This should be loaded as early as possible so that subsequent modules
### that look up the default sink/source get the right value
load-module module-default-device-restore

### Automatically move streams to the default sink if the sink they are
### connected to dies, similar for sources
load-module module-rescue-streams

### Make sure we always have a sink around, even if it is a null sink.
load-module module-always-sink

### Honour intended role device property
load-module module-intended-roles

### Automatically suspend sinks/sources that become idle for too long
load-module module-suspend-on-idle

### If autoexit on idle is enabled we want to make sure we only quit
### when no local session needs us anymore.
.ifexists module-console-kit.so
load-module module-console-kit
.endif
.ifexists module-systemd-login.so
load-module module-systemd-login
.endif

### Enable positioned event sounds
load-module module-position-event-sounds

### Cork music/video streams when a phone stream is active
load-module module-role-cork

### Modules to allow autoloading of filters (such as echo cancellation)
### on demand. module-filter-heuristics tries to determine what filters
### make sense, and module-filter-apply does the heavy-lifting of
### loading modules and rerouting streams.
load-module module-filter-heuristics
load-module module-filter-apply

# X11 modules should not be started from default.pa so that one daemon
# can be shared by multiple sessions.

### Load X11 bell module
#load-module module-x11-bell sample=x11-bell

### Register ourselves in the X11 session manager
#load-module module-x11-xsmp

### Publish connection data in the X11 root window
#.ifexists module-x11-publish.so
#.nofail
#load-module module-x11-publish
#.fail
#.endif

### Make some devices default
set-default-sink 0
#set-default-source input
EOF

# mali rules so users can access the mali0 driver...
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/50-mali.rules
KERNEL=="mali0", MODE="0660", GROUP="video"
EOF

# Video rules aka media-rules package in ChromeOS
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/50-media.rules
ATTR{name}=="s5p-mfc-dec", SYMLINK+="video-dec"
ATTR{name}=="s5p-mfc-enc", SYMLINK+="video-enc"
ATTR{name}=="s5p-jpeg-dec", SYMLINK+="jpeg-dec"
ATTR{name}=="exynos-gsc.0*", SYMLINK+="image-proc0"
ATTR{name}=="exynos-gsc.1*", SYMLINK+="image-proc1"
ATTR{name}=="exynos-gsc.2*", SYMLINK+="image-proc2"
ATTR{name}=="exynos-gsc.3*", SYMLINK+="image-proc3"
ATTR{name}=="rk3288-vpu-dec", SYMLINK+="video-dec"
ATTR{name}=="rk3288-vpu-enc", SYMLINK+="video-enc"
ATTR{name}=="go2001-dec", SYMLINK+="video-dec"
ATTR{name}=="go2001-enc", SYMLINK+="video-enc"
ATTR{name}=="mt81xx-vcodec-dec", SYMLINK+="video-dec"
ATTR{name}=="mt81xx-vcodec-enc", SYMLINK+="video-enc"
ATTR{name}=="mt81xx-image-proc", SYMLINK+="image-proc0"
EOF

# EHCI is apparently quirky.
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-rk3288-ehci-persist.rules
ACTION=="add|change", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ENV{ID_MODEL}!="EHCI_Host_Controller", DRIVERS=="ehci-platform", ATTR{power/persist}="1"
EOF

# Avoid gpio charger wakeup system
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/99-rk3288-gpio-charger.rules
ACTION=="add|change", SUBSYSTEM=="platform", ENV{DRIVER}=="gpio-charger", ATTR{power/wakeup}="disabled"
EOF

# disable btdsio
mkdir -p "${basedir}"/kali-${architecture}/etc/modprobe.d/
cat << EOF > "${basedir}"/kali-${architecture}/etc/modprobe.d/blacklist-btsdio.conf
blacklist btsdio
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

cp "${basedir}"/../misc/zram "${basedir}"/kali-${architecture}/etc/init.d/zram
chmod 755 "${basedir}"/kali-${architecture}/etc/init.d/zram

# Copy the broadcom firmware files in (for now) - once sources are released,
# will be able to do this without having a local copy.
mkdir -p "${basedir}"/kali-${architecture}/lib/firmware/brcm/
cp "${basedir}"/../misc/brcm/* "${basedir}"/kali-${architecture}/lib/firmware/brcm/
# Copy in the touchpad firmwares - same as above.
cp "${basedir}"/../misc/elan* "${basedir}"/kali-${architecture}/lib/firmware/
cp "${basedir}"/../misc/max* "${basedir}"/kali-${architecture}/lib/firmware/
cd "${basedir}"

# We need to kick start the sdio chip to get bluetooth/wifi going.  This is ugly
# but bear with me.
cp "${basedir}"/../misc/bins/* "${basedir}"/kali-${architecture}/usr/sbin/
# And now we activate via udev rule
cat << EOF > "${basedir}"/kali-${architecture}/etc/udev/rules.d/80-brcm-sdio-added.rules
ACTION=="add", SUBSYSTEM=="sdio", ENV{SDIO_CLASS}=="02", ENV{SDIO_ID}=="02D0:4354", RUN+="/usr/sbin/brcm_patchram_plus -d --patchram /lib/firmware/brcm/BCM4354_003.001.012.0306.0659.hcd --no2bytes --enable_hci --enable_lpm --scopcm=1,2,0,1,1,0,0,0,0,0 --baudrate 3000000 --use_baudrate_for_download --tosleep=50000 /dev/ttyS0"
EOF

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' "${basedir}"/kali-${architecture}/etc/ssh/sshd_config

echo "Creating image file for Veyron Chromebooks"
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
