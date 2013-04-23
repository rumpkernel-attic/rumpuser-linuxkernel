#!/bin/sh
cp -p ~/buildrump.sh/obj/lib/librump/*.o .

cp -p ~/buildrump.sh/obj/lib/librumpnet/*.o .
cp -p ~/buildrump.sh/obj/sys/rump/net/lib/libnet/*.o .
mv component.o component2.o
cp -p ~/buildrump.sh/obj/sys/rump/net/lib/libnetinet/*.o .
mv component.o component3.o
cp -p ~/buildrump.sh/obj/sys/rump/net/lib/libvirtif/if_virt.o .
cp -p ~/buildrump.sh/obj/sys/rump/net/lib/libvirtif/component.o .
mv component.o component4.o
cp -p ~/buildrump.sh/obj/sys/rump/dev/lib/libbpf/*.o .
mv component.o component5.o
cp -p ~/buildrump.sh/obj/brlib/libnetconfig/*.o .

#cp ~/buildrump.sh/obj/lib/librumpvfs/*.o .
#cp ~/buildrump.sh/obj/sys/rump/fs/lib/libkernfs/*.o .
