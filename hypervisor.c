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
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <rump/rumpuser.h>

int
rumpuser_getversion(void)
{

	return RUMPUSER_VERSION;
}

int
rumpuser_putchar(int ch, int *error)
{
	/* i am not an atomic playboy */
	static char buf[1024];
	static unsigned int bufptr = 0;

	if (ch != '\n') {
		buf[bufptr++] = (char)ch;
	} else {
		buf[bufptr] = '\0';
		printk(KERN_INFO "%s\n", buf);
		bufptr = 0;
	}

	*error = 0;
	return 0;
}

int
rumpuser_dprintf(const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vprintk(fmt, ap);
	va_end(ap);

	return rv;
}

void *
rumpuser_malloc(size_t len, int alignment)
{
	void *rv;

	/*
	 * Yea, uh, should allocate with proper alignment, not hope
	 * that we get some.  is there an allocator in the linux kernel
	 * which takes alignment as a parameter?
	 */
	rv = kmalloc(len, GFP_KERNEL);
	BUG_ON(alignment && ((uintptr_t)rv & (uintptr_t)(alignment-1)));
	return rv;
}

void
rumpuser_free(void *addr)
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
	{ "RUMP_VERBOSE", "1" },
	{ "RUMP_NCPU", "4" }, /* default to 4 CPUs ... just for fun */
	{ NULL, NULL },
};

int
rumpuser_getenv(const char *name, char *buf, size_t blen, int *error)
{
	int i;

	for (i = 0; envtab[i].name; i++) {
		if (strcmp(name, envtab[i].name) == 0) {
			if (blen < strlen(envtab[i].value)+1) {
				*error = 11;
				return -1;
			} else {
				strcpy(buf, envtab[i].value);
				*error = 0;
				return 0;
			}
		}
	}

	*error = 375; /* yes, perfect error number */
        return -1;
}

int
rumpuser_getnhostcpu(void)
{

	/* this works better than "0" in my original version ... ;) */
	return 1;
}

int
rumpuser_gethostname(char *name, size_t namelen, int *error)
{

	snprintf(name, namelen, "rump-in-the-kernel");
	*error = 0;
	return 0;
}

int
rumpuser_gettime(uint64_t *sec, uint64_t *nsec, int *error)
{
	struct timespec ts;

	ts = current_kernel_time();
	*sec = ts.tv_sec;
	*nsec = ts.tv_nsec;
	*error = 0;

	return 0;
}

uint32_t
rumpuser_arc4random(void)
{
	uint32_t r;

	get_random_bytes(&r, sizeof(r));
	return r;
}

/* the kernel is statically linked, so no dynlibs tricks necessary here */
void
rumpuser_dl_bootstrap(rump_modinit_fn domodinit,
	rump_symload_fn symload, rump_compload_fn compload)
{
	extern void *__start_link_set_rump_components;
	extern void *__stop_link_set_rump_components;
	void **rc = &__start_link_set_rump_components;
	void **rc_end = &__stop_link_set_rump_components;

	for (; rc < rc_end; rc++)
		compload(*rc);
}
