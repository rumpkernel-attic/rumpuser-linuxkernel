/* stubs required by linkage, but ones we don't care about functionally */
#include <linux/kernel.h>

int donothing(void); int donothing(void) {return 0;}
int dopanic(void); int dopanic(void)
{panic("you've reached an invalid hypercall.  please hold for a panic.");}

#define NOTHINGALIAS(name) \
int name(void) __attribute__((alias("donothing")));
#define PANICALIAS(name) \
int name(void) __attribute__((alias("dopanic")));

/* terminate the kernel?  yea, but no */
NOTHINGALIAS(rumpuser_kill);

/* needs some sort of tls */
NOTHINGALIAS(rumpuser_seterrno);

/* backgrounding in the kernel?  dunno */
NOTHINGALIAS(rumpuser_daemonize_begin);
NOTHINGALIAS(rumpuser_daemonize_done);

/* not needed with static linking */
NOTHINGALIAS(rumpuser_dl_bootstrap);
NOTHINGALIAS(rumpuser_dl_globalsym);

/* no sysproxy */
NOTHINGALIAS(rumpuser_sp_anonmmap);
NOTHINGALIAS(rumpuser_sp_copyin);
NOTHINGALIAS(rumpuser_sp_copyinstr);
NOTHINGALIAS(rumpuser_sp_copyout);
NOTHINGALIAS(rumpuser_sp_copyoutstr);
NOTHINGALIAS(rumpuser_sp_fini);
NOTHINGALIAS(rumpuser_sp_init);
NOTHINGALIAS(rumpuser_sp_raise);

/* for host I/O, we don't use it */
NOTHINGALIAS(rumpuser_open);
NOTHINGALIAS(rumpuser_close);
NOTHINGALIAS(rumpuser_bio);
NOTHINGALIAS(rumpuser_iovread);
NOTHINGALIAS(rumpuser_iovwrite);
NOTHINGALIAS(rumpuser_getfileinfo);

/* must succeed *if* called (we make it so that they aren't called) */
PANICALIAS(rumpuser_anonmmap);
PANICALIAS(rumpuser_unmap);
PANICALIAS(rumpcomp_virtif_dying);
PANICALIAS(rumpcomp_virtif_destroy);
PANICALIAS(rumpuser_thread_exit);
PANICALIAS(rumpuser_thread_join);
