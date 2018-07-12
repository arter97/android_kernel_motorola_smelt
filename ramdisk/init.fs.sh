#!/system/bin/sh

busybox mount --bind /data/bind/system/app /system/app
busybox mount --bind /data/bind/system/framework /system/framework
busybox mount --bind /data/bind/system/priv-app /system/priv-app

touch /fstab.ready

busybox fstrim -v /data
