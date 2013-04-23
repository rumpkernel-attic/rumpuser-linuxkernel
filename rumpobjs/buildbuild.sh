#!/bin/sh

echo -n 'ld -r -m elf_i386 -T /home/pooka/buildrump.sh/src/sys/rump/ldscript.rump  --build-id  -o /home/pooka/rumpkern/rumpkern.ko /home/pooka/rumpkern/rumpkern.o /home/pooka/rumpkern/rumpkern.mod.o' > build.sh
for x in *.o ; do
	echo ' \' >> build.sh
	echo -n `pwd`/$x >> build.sh
done
echo >> build.sh
echo sync >> build.sh
