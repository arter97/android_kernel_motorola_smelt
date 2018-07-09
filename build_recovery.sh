#!/bin/bash
export KERNELDIR=`readlink -f .`
export RAMFS_SOURCE=`readlink -f $KERNELDIR/recovery`

echo "kerneldir = $KERNELDIR"
echo "ramfs_source = $RAMFS_SOURCE"

RAMFS_TMP="/tmp/arter97-smelt-recovery"

echo "ramfs_tmp = $RAMFS_TMP"
cd $KERNELDIR

if [ "${1}" = "skip" ] ; then
	echo "Skipping Compilation"
else
	echo "Compiling kernel"
	cp defconfig .config
	make "$@" || exit 1
fi

echo "Building new ramdisk"
#remove previous ramfs files
rm -rf '$RAMFS_TMP'*
rm -rf $RAMFS_TMP
rm -rf $RAMFS_TMP.cpio
#copy ramfs files to tmp directory
cp -ax $RAMFS_SOURCE $RAMFS_TMP
cd $RAMFS_TMP

#clear git repositories in ramfs
find . -name .git -exec rm -rf {} \;
find . -name EMPTY_DIRECTORY -exec rm -rf {} \;

find . -name '*.sh' -exec chmod 755 {} \;
$KERNELDIR/ramdisk_fix_permissions.sh 2>/dev/null

cd $KERNELDIR
rm -rf $RAMFS_TMP/tmp/*

cd $RAMFS_TMP
find . | fakeroot cpio -H newc -o | gzip -9 > $RAMFS_TMP.cpio.gz
ls -lh $RAMFS_TMP.cpio.gz
cd $KERNELDIR

echo "Making new boot image"
gcc -w -s -pipe -O2 -Itools/libmincrypt -o tools/mkbootimg/mkbootimg tools/libmincrypt/*.c tools/mkbootimg/mkbootimg.c
tools/mkbootimg/mkbootimg --kernel $KERNELDIR/arch/arm/boot/zImage-dtb --ramdisk $RAMFS_TMP.cpio.gz --cmdline 'console=ttyHSL0,115200,n8 androidboot.console=ttyHSL0 androidboot.hardware=carp utags.blkdev=/dev/block/platform/msm_sdcc.1/by-name/utags utags.backup=/dev/block/platform/msm_sdcc.1/by-name/utagsBackup user_debug=31 msm_rtb.filter=0x3 buildvariant=user androidboot.selinux=permissive' --base 0x00000000 --pagesize 2048 --kernel_offset 0x00008000 --ramdisk_offset 0x02000000 --tags_offset 0x01e00000 --second_offset 0x00f00000 -o $KERNELDIR/recovery.img

echo "done"
ls -al recovery.img
echo ""
