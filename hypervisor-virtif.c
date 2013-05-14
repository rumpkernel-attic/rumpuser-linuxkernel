/*
 * Copyright (c) 2013 Antti Kantee
 *
 * See LICENSE.
 *
 * This module implements hypercalls private to the virtual network
 * interface (if_virt).  Now, of course I *could* implement this as
 * a networking interface which plugs into the rest of the kernel on
 * the interface level, but it's just much much less code to implement
 * this just like we would do in userspace: by opening tap and doing
 * read/write on it.  A hack?  Maybe.  But it works and I got to have
 * a long lunch and dinner.  If it annoys you, send patches.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <rump/rumpuser.h>

#include "hypervisor.h"

struct virtif_user {
	struct file *tapfile;
};

int
rumpcomp_virtif_create(int num, struct virtif_user **vup)
{
	struct virtif_user *vu;
	struct file *filp;
	struct ifreq ifr;
	mm_segment_t oseg;
	int error;

	filp = filp_open("/dev/net/tun", O_RDWR, 0);
	if (IS_ERR(filp))
		panic("virtif failed to open tap device");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	sprintf(ifr.ifr_name, "tun%d", num);

	oseg = get_fs();
	set_fs(get_ds());
	error = filp->f_op->unlocked_ioctl(filp,
	    TUNSETIFF, (unsigned long)&ifr);
	set_fs(oseg);
	if (error)
		panic("TUNSETIFF failed: %d", error);

	vu = kmalloc(sizeof(*vu), GFP_KERNEL);
	vu->tapfile = filp;
	*vup = vu;

	return 0;
}

void
rumpcomp_virtif_send(struct virtif_user *vu, struct iovec *iov, size_t niov)
{
	mm_segment_t oseg;
	loff_t off = 0;
	ssize_t nn;

	oseg = get_fs();
	set_fs(get_ds());
	/* something is written, rest (if any) is dropped */
	KLOCK_WRAP(nn = vfs_writev(vu->tapfile, iov, niov, &off));
	set_fs(oseg);
}

int
rumpcomp_virtif_recv(struct virtif_user *vu, void *buf, size_t buflen,
	size_t *recvd)
{
	mm_segment_t oseg;
	loff_t off = 0;
	ssize_t nn;

	oseg = get_fs();
	set_fs(get_ds());
	KLOCK_WRAP(nn = vfs_read(vu->tapfile, buf, buflen, &off));
	set_fs(oseg);

	if (nn < 0)
		return (int)(-nn);
	*recvd = (size_t)nn;

	return 0;
}
