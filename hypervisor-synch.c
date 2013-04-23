/*
 * Copyright (c) 2013 Antti Kantee.
 *
 * See LICENSE.
 *
 * This module contains hypercalls related to multithreading and
 * synchronization.
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/time.h>

#include <rump/rumpuser.h>

#include "hypervisor.h"

struct rumpuser_mtx {
	struct mutex lkmtx;
	struct lwp *owner;
	int iskmutex;
};

#define RURW_AMWRITER(rw) (rw->writer == rumpuser_get_curlwp()		\
				&& atomic_read(&rw->readers) == -1)
#define RURW_HASREAD(rw)  (atomic_read(&rw->readers) > 0)

#define RURW_SETWRITE(rw)						\
do {									\
	BUG_ON(atomic_read(&rw->readers) != 0);				\
	rw->writer = rumpuser_get_curlwp();				\
	atomic_set(&rw->readers, -1);					\
} while (/*CONSTCOND*/0)
#define RURW_CLRWRITE(rw)						\
do {									\
	BUG_ON(!(atomic_read(&rw->readers) == -1 && RURW_AMWRITER(rw)));\
	atomic_set(&rw->readers, 0);					\
} while (/*CONSTCOND*/0)
#define RURW_INCREAD(rw)						\
do {									\
	BUG_ON(atomic_read(&rw->readers) < 0);				\
	atomic_inc(&rw->readers);					\
} while (/*CONSTCOND*/0)
#define RURW_DECREAD(rw)						\
do {									\
	BUG_ON(atomic_read(&rw->readers) <= 0);				\
	atomic_dec(&rw->readers);					\
} while (/*CONSTCOND*/0)

struct rumpuser_rw {
	rwlock_t lkrw;
	atomic_t readers;
	struct lwp *writer;
};

kernel_lockfn	rumpuser__klock;
kernel_unlockfn	rumpuser__kunlock;
int		rumpuser__wantthreads;

static struct mutex curlwpmtx;

void
rumpuser_thrinit(kernel_lockfn lockfn, kernel_unlockfn unlockfn, int threads)
{

	rumpuser__klock = lockfn;
	rumpuser__kunlock = unlockfn;
	rumpuser__wantthreads = threads;

	mutex_init(&curlwpmtx);
}

int
rumpuser_thread_create(void *(*f)(void *), void *arg, const char *thrname,
	int joinable, void **ptcookie)
{
	struct task_struct *newtsk;

	/* cast ok, we don't care about rv (at least not for now) */
	newtsk = kthread_run((int (*)(void *))f, arg, thrname);
	if (newtsk == ERR_PTR(-ENOMEM))
		return ENOMEM;
	if (joinable) {
		BUG_ON(!ptcookie);
		*ptcookie = newtsk;
	}

	return 0;
}

void
rumpuser_mutex_init(struct rumpuser_mtx **mtxp)
{
	struct rumpuser_mtx *mtx;

	mtx = kmalloc(sizeof(struct rumpuser_mtx), GFP_KERNEL);

	mutex_init(&mtx->lkmtx);
	mtx->owner = NULL;
	mtx->iskmutex = 0;
	*mtxp = mtx;
}

void
rumpuser_mutex_init_kmutex(struct rumpuser_mtx **mtx)
{

	rumpuser_mutex_init(mtx);
	(*mtx)->iskmutex = 1;
}

static void
mtxenter(struct rumpuser_mtx *mtx)
{

	if (!mtx->iskmutex)
		return;

	BUG_ON(mtx->owner);
	mtx->owner = rumpuser_get_curlwp();
}

static void
mtxexit(struct rumpuser_mtx *mtx)
{

	if (!mtx->iskmutex)
		return;

	BUG_ON(!mtx->owner);
	mtx->owner = NULL;
}

void
rumpuser_mutex_enter(struct rumpuser_mtx *mtx)
{

	if (mutex_trylock(&mtx->lkmtx) == 0)
		KLOCK_WRAP(mutex_lock(&mtx->lkmtx));
	mtxenter(mtx);
}

void
rumpuser_mutex_enter_nowrap(struct rumpuser_mtx *mtx)
{

	mutex_lock(&mtx->lkmtx);
	mtxenter(mtx);
}

int
rumpuser_mutex_tryenter(struct rumpuser_mtx *mtx)
{
	int rv;

	rv = mutex_trylock(&mtx->lkmtx);
	if (rv) {
		mtxenter(mtx);
	}

	return rv != 0;
}

void
rumpuser_mutex_exit(struct rumpuser_mtx *mtx)
{

	mtxexit(mtx);
	mutex_unlock(&mtx->lkmtx);
}

void
rumpuser_mutex_destroy(struct rumpuser_mtx *mtx)
{

	mutex_destroy(&mtx->lkmtx);
	kfree(mtx);
}

struct lwp *
rumpuser_mutex_owner(struct rumpuser_mtx *mtx)
{

	BUG_ON(!mtx->iskmutex);
	return mtx->owner;
}

void
rumpuser_rw_init(struct rumpuser_rw **rw)
{

	*rw = kmalloc(sizeof(struct rumpuser_rw), GFP_KERNEL);
	rwlock_init(&((*rw)->lkrw));
	atomic_set(&(*rw)->readers, 0);
	(*rw)->writer = NULL;
}

void
rumpuser_rw_enter(struct rumpuser_rw *rw, int iswrite)
{

	if (iswrite) {
		if (!write_trylock(&rw->lkrw))
			KLOCK_WRAP(write_lock(&rw->lkrw));
		RURW_SETWRITE(rw);
	} else {
		if (!read_trylock(&rw->lkrw))
			KLOCK_WRAP(read_lock(&rw->lkrw));
		RURW_INCREAD(rw);
	}
}

int
rumpuser_rw_tryenter(struct rumpuser_rw *rw, int iswrite)
{
	int rv;

	if (iswrite) {
		rv = write_trylock(&rw->lkrw);
		if (rv)
			RURW_SETWRITE(rw);
	} else {
		rv = read_trylock(&rw->lkrw);
		if (rv)
			RURW_INCREAD(rw);
	}

	return rv;
}

void
rumpuser_rw_exit(struct rumpuser_rw *rw)
{

	/* i wonder why the underlying lock doesn't know this ... */
	if (RURW_HASREAD(rw)) {
		RURW_DECREAD(rw);
		read_unlock(&rw->lkrw);
	} else {
		RURW_CLRWRITE(rw);
		write_unlock(&rw->lkrw);
	}
}

void
rumpuser_rw_destroy(struct rumpuser_rw *rw)
{

	/* what's the opposite of rwlock_init() ? */
	//rwlock_destroy(&rw->lkrw);
	kfree(rw);
}

int
rumpuser_rw_held(struct rumpuser_rw *rw)
{

	return atomic_read(&rw->readers) != 0;
}

int
rumpuser_rw_rdheld(struct rumpuser_rw *rw)
{

	return RURW_HASREAD(rw);
}

int
rumpuser_rw_wrheld(struct rumpuser_rw *rw)
{

	return RURW_AMWRITER(rw);
}

/*
 * Ok, condvar hypercall.  As far as I've been able to figure out
 * in a few hours, Linux does not offer condition variables.  It offers
 * completions, but they're conveniently just a little different.  The wait
 * side of a completion doesn't take an interlock (por que?!?), so to
 * make up for this, the object itself has memory.  So instead of being
 * able to get away with something readily chewed, we emulate standard
 * condition variables with a song and dance of waits and queues.
 * We _almost_ get away with using completitions, but using them leads
 * to races with the timedwait variant... duh.
 *
 * NOTE:
 * At least in the theory the caller is supposed to hold the interlock
 * both when calling wait and wakeup, but on the wait side we cannot
 * assert that the lock is held.  I have a nagging feeling that not all
 * callers actually hold the interlock, but let's use the "pipo silmille
 * ja meno-x" approach to development for now.
 */
struct waitobj {
	struct list_head entry;
	wait_queue_head_t wq;
	bool wakeupdone;
};

struct rumpuser_cv {
	struct list_head waiters;
	int nwaiters;
};

static void
addwaiter(struct rumpuser_cv *cv, struct waitobj *wo)
{

	init_waitqueue_head(&wo->wq);
	wo->wakeupdone = false;
	cv->nwaiters++;
	list_add_tail(&wo->entry, &cv->waiters);
}

/*
 * Remove waiter for waitee list.
 * 
 * NOTE: this _must_ be called before wake_up() since the rump kernel
 * interlock will not protect the waiter from going back to sleep [forever]
 * if the waiter happens to be scheduled between wake_up() and rmwaiter().
 */
static void
rmwaiter(struct rumpuser_cv *cv, struct waitobj *wo)
{

	if (!wo->wakeupdone) {
		list_del(&wo->entry);
		cv->nwaiters--;
		wo->wakeupdone = true;
	}
}

void
rumpuser_cv_init(struct rumpuser_cv **cvp)
{
	struct rumpuser_cv *cv;
	
	cv = kmalloc(sizeof(struct rumpuser_cv), GFP_KERNEL);
	INIT_LIST_HEAD(&cv->waiters);
	cv->nwaiters = 0;
	*cvp = cv;
}

int
rumpuser_cv_has_waiters(struct rumpuser_cv *cv)
{

	return cv->nwaiters;
}

void
rumpuser_cv_destroy(struct rumpuser_cv *cv)
{

	BUG_ON(cv->nwaiters);
	kfree(cv);
}

void
rumpuser_cv_wait(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx)
{
	struct waitobj wo;
	int nlocks;

	rumpuser__kunlock(0, &nlocks, mtx);
	addwaiter(cv, &wo);
	rumpuser_mutex_exit(mtx);
	wait_event(wo.wq, wo.wakeupdone);
	rumpuser_mutex_enter_nowrap(mtx);
	BUG_ON(!wo.wakeupdone);
	rumpuser__klock(nlocks, mtx);
}

void
rumpuser_cv_wait_nowrap(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx)
{
	struct waitobj wo;

	addwaiter(cv, &wo);
	rumpuser_mutex_exit(mtx);
	wait_event(wo.wq, wo.wakeupdone);
	rumpuser_mutex_enter_nowrap(mtx);
	BUG_ON(!wo.wakeupdone);
}

int
rumpuser_cv_timedwait(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx,
	int64_t sec, int64_t nsec)
{
	struct waitobj wo;
	struct timespec ts, tss, tsd;
	unsigned long timo;
	int rv, nlocks;

	rumpuser__kunlock(0, &nlocks, mtx);
	addwaiter(cv, &wo);
	rumpuser_mutex_exit(mtx);

	tss = current_kernel_time();
	ts.tv_sec = sec; ts.tv_nsec = nsec;
	tsd = timespec_sub(ts, tss);
	if (tsd.tv_sec < 0)
		timo = 0;
	else
		timo = timespec_to_jiffies(&tsd);

	rv = wait_event_timeout(wo.wq, wo.wakeupdone, timo);
	rumpuser_mutex_enter_nowrap(mtx);
	rmwaiter(cv, &wo);
	rumpuser__klock(nlocks, mtx);

	return rv == 0;
}

void
rumpuser_cv_signal(struct rumpuser_cv *cv)
{
	struct waitobj *wo;

	if (!list_empty(&cv->waiters)) {
		BUG_ON(cv->nwaiters < 1);
	    	wo = list_first_entry(&cv->waiters, struct waitobj, entry);
		rmwaiter(cv, wo);
		wake_up(&wo->wq);
	}
}

void
rumpuser_cv_broadcast(struct rumpuser_cv *cv)
{
	struct waitobj *wo;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &cv->waiters) {
		BUG_ON(cv->nwaiters < 1);
		wo = list_entry(pos, struct waitobj, entry);
		rmwaiter(cv, wo);
		wake_up(&wo->wq);
	}
}

/*
 * We don't do bio, so just prevent this thread for exiting.
 * I'd have to spend a minute implementing rumpuser_thread_exit() ...
 */
void __dead
rumpuser_biothread(void *arg)
{
        int nlocks;

        rumpuser__kunlock(0, &nlocks, NULL);
	set_current_state(TASK_INTERRUPTIBLE);
	for (;;)
		schedule_timeout(MAX_SCHEDULE_TIMEOUT);
}

/*
 * curlwp.  No thread specific data in linux?  seriously??
 * alrighty then, we emulate it by "hashing".  and by "hashing"
 * I mean a O(n) lookup.  in reality this routine would need to
 * be [very] fast --  in demoality, not so such.  Notably, this
 * approach, as opposed to real thread specific data, changes one
 * rule: the client is not allowed to bind a rump kernel context
 * and then exit.  I'm not sure we care about that "drawback".
 */

/* yea, i said "hashing" ;) */
#define MAXTASK 64
static struct {
	struct task_struct *tsk;
	struct lwp *tsklwp;
} lwps[MAXTASK];

static struct lwp *
curlwp_l(void)
{
	struct task_struct *tsk = current;
	int i;

	for (i = 0; i < MAXTASK; i++) {
		if (lwps[i].tsk == tsk) {
			return lwps[i].tsklwp;
		}
	}
	return NULL;
}

/*
 * l != NULL: set current task (must not be set)
 * l == NULL: unset current task (must be set)
 */
void
rumpuser_set_curlwp(struct lwp *l)
{
	struct task_struct *cmp, *set;
	int i;

	cmp = l ? NULL : current;
	set = l ? current : NULL;

	mutex_lock(&curlwpmtx);
	BUG_ON(curlwp_l() != NULL && l != NULL);
	BUG_ON(curlwp_l() == NULL && l == NULL);
	for (i = 0; i < MAXTASK; i++) {
		if (lwps[i].tsk == cmp) {
			lwps[i].tsk = set;
			lwps[i].tsklwp = l;
			break;
		}
	}
	mutex_unlock(&curlwpmtx);
	BUG_ON(i == MAXTASK);
}

struct lwp *
rumpuser_get_curlwp(void)
{
	struct lwp *l = NULL;

	mutex_lock(&curlwpmtx);
	l = curlwp_l();
	mutex_unlock(&curlwpmtx);

	return l;
}

int
rumpuser_nanosleep(uint64_t *sec, uint64_t *nsec, int *error)
{
	struct timespec rqt;
	unsigned long timo;

	rqt.tv_sec = *sec;
	rqt.tv_nsec = *nsec;
	timo = timespec_to_jiffies(&rqt);

	set_current_state(TASK_UNINTERRUPTIBLE);
	KLOCK_WRAP(schedule_timeout(timo));

	/* weeeeell ... */
	*sec = 0;
	*nsec = 0;

	*error = 0;
	return 0;
}
