#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>

#include <rump/rump.h>

void rumpkern_demo(struct work_struct *);

/* demo might block, so run it in another context */
static struct work_struct demowrk;

int
init_module(void)
{

	printk(KERN_INFO "initiating rump kernel bootstrap\n");
	rump_init();
	printk(KERN_INFO "rump kernel bootstrap complete, scheduling demo\n");

	INIT_WORK(&demowrk, rumpkern_demo);
	schedule_work(&demowrk);

	return 0;
}

void
clenup_module(void)
{

	/*
	 * So, normally a kernel goes away when the host gets reset.
	 * The same is true for a rump kernel.  This is easy for a
	 * userspace process, but slightly more convoluted when running
	 * in the kernel.  Of course, it would be possible to make a
	 * rump kernel release all resources to be unloadable ... but
	 * ... not today.
	 */
	panic("cannot unload me, sorry");
}
