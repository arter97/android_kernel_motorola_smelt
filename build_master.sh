#!/bin/bash
if [ ! "${1}" = "skip" ] ; then
	./build_clean.sh
	./build_kernel.sh "$@" || exit 1
fi

if [ -e boot.img ] ; then
	rm arter97-kernel.zip 2>/dev/null
	cp boot.img kernelzip/boot.img
	cd kernelzip/
	7z a -mx9 arter97-kernel-tmp.zip *
	zipalign -v 4 arter97-kernel-tmp.zip ../arter97-kernel-"$(date +%F | sed s@-@@g)".zip
	rm arter97-kernel-tmp.zip
	cd ..
	ls -al arter97-kernel-"$(date +%F | sed s@-@@g)".zip
	rm kernelzip/boot.img
fi
