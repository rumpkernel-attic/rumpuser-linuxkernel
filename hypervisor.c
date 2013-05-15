/*
 * Copyright (c) 2013 Antti Kantee
 *
 * See LICENSE
 *
 * This module contains the very basic hypercalls you need to
 * run a rump kernel.
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <rump/rumpuser.h>

#include "hypervisor.h"

struct rumpuser_hyperup rumpuser__hyp;
static struct mutex printmtx;

int
rumpuser_init(int version, const struct rumpuser_hyperup *hyp)
{

	if (version != 17)
		return 1; /* EKERNELMISMATCH */

	mutex_init(&printmtx);

	rumpuser__thrinit();
	rumpuser__hyp = *hyp;

	return 0;
}

void
rumpuser_putchar(int ch)
{
	static char buf[1024];
	static unsigned int bufptr = 0;

	mutex_lock(&printmtx);
	if (ch != '\n' && bufptr != sizeof(buf)-1) {
		buf[bufptr++] = (char)ch;
	} else {
		buf[bufptr] = '\0';
		printk(KERN_INFO "%s\n", buf);
		bufptr = 0;
	}
	mutex_unlock(&printmtx);
}

void
rumpuser_dprintf(const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vprintk(fmt, ap);
	va_end(ap);
}

int
rumpuser_malloc(size_t len, int alignment, void **retval)
{
	void *rv;

	/*
	 * Yea, uh, should allocate with proper alignment, not hope
	 * that we get some.  is there an allocator in the linux kernel
	 * which takes alignment as a parameter?
	 */
	rv = kmalloc(len, GFP_KERNEL);
	BUG_ON(alignment && ((uintptr_t)rv & (uintptr_t)(alignment-1)));

	*retval = rv;
	return rv ? 0 : ENOMEM;
}

void
rumpuser_free(void *addr, size_t len)
{

	kfree(addr);
}

void
rumpuser_exit(int how)
{

	dump_stack();

	/* sleep forever, sometimes prevents hangs before debugging */
	printk(KERN_INFO "elvis has NOT left the building!\n");
	set_current_state(TASK_INTERRUPTIBLE);
	for (;;)
		schedule_timeout(MAX_SCHEDULE_TIMEOUT);
}

/* the environment is a bit more hardcoded than in a userspace hypervisor */
static struct {
	const char *name;
	const char *value;
} envtab[] = {
	{ RUMPUSER_PARAM_NCPU, "4" }, /* default to 4 CPUs ... just for fun */
	{ RUMPUSER_PARAM_HOSTNAME, "rump-in-the-kernel" },
	{ "RUMP_VERBOSE", "1" },
	{ NULL, NULL },
};

int
rumpuser_getparam(const char *name, void *buf, size_t blen)
{
	int i;

	for (i = 0; envtab[i].name; i++) {
		if (strcmp(name, envtab[i].name) == 0) {
			if (blen < strlen(envtab[i].value)+1) {
				return 11;
			} else {
				strcpy(buf, envtab[i].value);
				return 0;
			}
		}
	}

        return 37;
}

int
rumpuser_clock_gettime(int enum_rumpclock, int64_t *sec, long *nsec)
{
	struct timespec ts;

	ts = current_kernel_time();
	*sec = ts.tv_sec;
	*nsec = ts.tv_nsec;

	return 0;
}

/* hmm, is there an absolute sleep in the linux kernel? */
int
rumpuser_clock_sleep(int enum_rumpclock, int64_t sec, long nsec)
{
	enum rumpclock clk = enum_rumpclock;
	struct timespec rqt;
	struct timespec ctime, delta;
	unsigned long timo;

	rqt.tv_sec = sec;
	rqt.tv_nsec = nsec;

	switch (clk) {
	case RUMPUSER_CLOCK_RELWALL:
		timo = timespec_to_jiffies(&rqt);
		break;
	case RUMPUSER_CLOCK_ABSMONO:
		ctime = current_kernel_time();
		delta = timespec_sub(rqt, ctime);
		if (!timespec_valid(&delta))
			goto out;
		timo = timespec_to_jiffies(&delta);
		break;
	default:	
		panic("unreachable");
	}

	set_current_state(TASK_UNINTERRUPTIBLE);
	KLOCK_WRAP(schedule_timeout(timo));

 out:
	return 0;
}

int
rumpuser_getrandom(void *buf, size_t buflen, int flags, size_t *retval)
{

	/* XXX: flags not handled */
	get_random_bytes(buf, buflen);
	*retval = buflen;

	return 0;
}
