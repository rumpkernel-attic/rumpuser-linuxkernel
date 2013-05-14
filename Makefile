obj-m += rumpkern.o
ccflags-y := -I/home/pooka/rump/include -DLIBRUMPUSER -I/home/pooka/buildrump.sh/src/sys/rump/net/lib/libvirtif -g
basesrc= main.o stubs.o hypervisor.o hypervisor-synch.o

# choose your line, choose your fate
# (this comment brought to you by the dungeon master fanclub)
#rumpkern-y := ${basesrc} demo-fs.o
rumpkern-y := ${basesrc} hypervisor-virtif.o demo-net.o

all:
	make KBUILD_VERBOSE=1 -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

