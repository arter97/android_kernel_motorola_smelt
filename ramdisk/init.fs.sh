#!/system/bin/sh

busybox mount --bind /data/bind/system/app /system/app
busybox mount --bind /data/bind/system/framework /system/framework
busybox mount --bind /data/bind/system/priv-app /system/priv-app

# Setup swap here to avoid memory allocation errors
# 512 MB
echo $((512 * 1048576)) > /sys/devices/virtual/block/vnswap0/disksize
echo 180 > /proc/sys/vm/swappiness
busybox mkswap /dev/block/vnswap0
busybox swapon /dev/block/vnswap0

touch /fstab.ready

busybox fstrim -v /data
