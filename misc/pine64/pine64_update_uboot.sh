#!/bin/sh
#
# Based on https://raw.githubusercontent.com/longsleep/build-pine64-image/master/simpleimage/platform-scripts/pine64_update_uboot.sh

set -e

URL="https://www.stdin.xyz/downloads/people/longsleep/pine64-images/simpleimage-pine64-latest.img.xz"
PUBKEY="https://www.stdin.xyz/downloads/people/longsleep/longsleep.asc"
TEMP=$(mktemp -d -p /var/tmp)
FILENAME=$TEMP/$(basename ${URL})
cleanup() {
	if [ -d "$TEMP" ]; then
		rm -rf "$TEMP"
	fi
}
trap cleanup EXIT INT

downloadAndApply() {
	echo "Downloading U-Boot image ..."
	curl "${URL}" -f --progress-bar --output "${FILENAME}"
	echo "Downloading signature ..."
	curl "${URL}.asc" -f --progress-bar --output "${FILENAME}.asc"
	echo "Downloading public key ..."
	curl "${PUBKEY}" -f --progress-bar --output "${TEMP}/pub.asc"

	echo "Verifying signature ..."
	gpg --homedir "${TEMP}" --yes -o "${TEMP}/pub.gpg" --dearmor "${TEMP}/pub.asc"
	gpg --homedir "${TEMP}" --status-fd 1 --no-default-keyring --keyring "${TEMP}/pub.gpg" --trust-model always --verify "${FILENAME}.asc" 2>/dev/null

	local boot0_position=8     # KiB
	local boot0_size=64        # KiB
	local uboot_position=19096 # KiB
	local uboot_size=1384      # KiB
	echo "Processing ..."
	xz -d -c "${FILENAME}" >"${TEMP}/simpleimage.img"
	dd if="${TEMP}/simpleimage.img" status=none bs=1k skip=$boot0_position count=$boot0_size of="${TEMP}/boot0.img"
	dd if="${TEMP}/simpleimage.img" status=none bs=1k skip=$uboot_position count=$uboot_size of="${TEMP}/uboot.img"
	echo "Flashing boot0 ..."
	dd if="${TEMP}/boot0.img" conv=notrunc bs=1k seek=$boot0_position oflag=sync of="${DEVICE}"
	echo "Flashing U-Boot ..."
	dd if="${TEMP}/uboot.img" conv=notrunc bs=1k seek=$uboot_position oflag=sync of="${DEVICE}"
}

if [ -n "$1" ]; then
	DEVICE="$1"
else
    echo "no image file specified.  bailing out."
    exit 1
fi

if [ "$(id -u)" -ne "0" ]; then
	echo "This script requires root."
	exit 1
fi

downloadAndApply
sync

echo "Done"

