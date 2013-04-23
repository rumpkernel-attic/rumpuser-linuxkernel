/*
 * Mount the kernfs file system inside the rump kernel and read
 * version info from it.  It should be the same as the one displayed
 * as part of a verbose boot.
 */

#include <linux/kernel.h>
#include <linux/bug.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

void rumpkern_demo(void);

void
rumpkern_demo(void)
{
	char buf[256];
	ssize_t nn;
	int fd, rv;

	printk(KERN_INFO "reading rump kernel version from kernfs/version:\n");
	rv = rump_sys_mkdir("/mnt", 0777);
	BUG_ON(rv == -1);

	rv = rump_sys_mount("kernfs", "/mnt", 0, NULL, 0);
	BUG_ON(rv == -1);

	fd = rump_sys_open("/mnt/version", RUMP_O_RDONLY, 0);
	BUG_ON(rv == -1);

	nn = rump_sys_read(fd, buf, sizeof(buf));
	BUG_ON(nn < 1);
	buf[nn] = '\0';

	printk(KERN_INFO "%s", buf);
}
