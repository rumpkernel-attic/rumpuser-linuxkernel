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
	int flags;
};

#define RURW_AMWRITER(rw) (rw->writer == rumpuser_curlwp()		\
				&& atomic_read(&rw->readers) == -1)
#define RURW_HASREAD(rw)  (atomic_read(&rw->readers) > 0)

#define RURW_SETWRITE(rw)						\
do {									\
	BUG_ON(atomic_read(&rw->readers) != 0);				\
	rw->writer = rumpuser_curlwp();				\
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

static struct mutex curlwpmtx;

void
rumpuser__thrinit(void)
{

	mutex_init(&curlwpmtx);
}

int
rumpuser_thread_create(void *(*f)(void *), void *arg, const char *thrname,
	int joinable, int priority, int cpuidx, void **ptcookie)
{
	struct task_struct *newtsk;
	char thrbuf[128];

	/* put thread into their own namespace to avoid collisions */
	snprintf(thrbuf, sizeof(thrbuf), "rump-%s", thrname);

	/* cast ok, we don't care about rv (at least not for now) */
	newtsk = kthread_run((int (*)(void *))f, arg, thrbuf);
	if (newtsk == ERR_PTR(-ENOMEM))
		return ENOMEM;
	if (joinable) {
		BUG_ON(!ptcookie);
		*ptcookie = newtsk;
	}

	return 0;
}

void
rumpuser_mutex_init(struct rumpuser_mtx **mtxp, int flags)
{
	struct rumpuser_mtx *mtx;

	mtx = kmalloc(sizeof(struct rumpuser_mtx), GFP_KERNEL);
	BUG_ON(!mtx);	

	mutex_init(&mtx->lkmtx);
	mtx->owner = NULL;
	mtx->flags = flags;

	*mtxp = mtx;
}

static void
mtxenter(struct rumpuser_mtx *mtx)
{

	if (!(mtx->flags & RUMPUSER_MTX_KMUTEX))
		return;

	BUG_ON(mtx->owner);
	mtx->owner = rumpuser_curlwp();
}

static void
mtxexit(struct rumpuser_mtx *mtx)
{

	if (!(mtx->flags & RUMPUSER_MTX_KMUTEX))
		return;

	BUG_ON(!mtx->owner);
	mtx->owner = NULL;
}

void
rumpuser_mutex_enter(struct rumpuser_mtx *mtx)
{

	if (mtx->flags & RUMPUSER_MTX_SPIN) {
		rumpuser_mutex_enter_nowrap(mtx);
		return;
	}

	if (mutex_trylock(&mtx->lkmtx) == 0)
		KLOCK_WRAP(mutex_lock(&mtx->lkmtx));
	mtxenter(mtx);
}

void
rumpuser_mutex_enter_nowrap(struct rumpuser_mtx *mtx)
{

	BUG_ON(!(mtx->flags & RUMPUSER_MTX_SPIN));
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

	return rv ? 0 : EBUSY;
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

void
rumpuser_mutex_owner(struct rumpuser_mtx *mtx, struct lwp **owner)
{

	BUG_ON(!(mtx->flags & RUMPUSER_MTX_KMUTEX));
	*owner = mtx->owner;
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
rumpuser_rw_enter(struct rumpuser_rw *rw, const enum rumprwlock lk)
{

	switch (lk) {
	case RUMPUSER_RW_WRITER:
		if (!write_trylock(&rw->lkrw))
			KLOCK_WRAP(write_lock(&rw->lkrw));
		RURW_SETWRITE(rw);
		break;

	case RUMPUSER_RW_READER:
		if (!read_trylock(&rw->lkrw))
			KLOCK_WRAP(read_lock(&rw->lkrw));
		RURW_INCREAD(rw);
		break;
	}
}

int
rumpuser_rw_tryenter(struct rumpuser_rw *rw, const enum rumprwlock lk)
{
	int rv = 0;

	switch (lk) {
	case RUMPUSER_RW_WRITER:
		rv = write_trylock(&rw->lkrw);
		if (rv)
			RURW_SETWRITE(rw);
		break;
	case RUMPUSER_RW_READER:
		rv = read_trylock(&rw->lkrw);
		if (rv)
			RURW_INCREAD(rw);
		break;
	}

	return rv ? 0 : EBUSY;
}

int
rumpuser_rw_tryupgrade(struct rumpuser_rw *rw)
{

	return EBUSY;
}

void
rumpuser_rw_downgrade(struct rumpuser_rw *rw)
{

	/*
	 * XXX: wrong, but it'll do for now.  see hypervisor in NetBSD
	 * for how to emulate this properly.
	 */
	rumpuser_rw_exit(rw);
	KLOCK_WRAP(rumpuser_rw_enter(rw, RUMPUSER_RW_READER));
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

void
rumpuser_rw_held(struct rumpuser_rw *rw, const enum rumprwlock lk, int *rv)
{

	switch (lk) {
	case RUMPUSER_RW_WRITER:
		*rv = RURW_AMWRITER(rw);
		break;
	case RUMPUSER_RW_READER:
		*rv = RURW_HASREAD(rw);
		break;
	}
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
 */
struct waitobj {
	struct list_head entry;
	wait_queue_head_t wq;
	bool wakeupdone;
};

struct rumpuser_cv {
	spinlock_t slock;
	struct list_head waiters;
	int nwaiters;
};

static void
addwaiter(struct rumpuser_cv *cv, struct waitobj *wo)
{

	init_waitqueue_head(&wo->wq);
	wo->wakeupdone = false;
	cv->nwaiters++;
	spin_lock(&cv->slock);
	list_add_tail(&wo->entry, &cv->waiters);
	spin_unlock(&cv->slock);
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

	spin_lock(&cv->slock);
	if (!wo->wakeupdone) {
		list_del(&wo->entry);
		cv->nwaiters--;
		wo->wakeupdone = true;
	}
	spin_unlock(&cv->slock);
}

void
rumpuser_cv_init(struct rumpuser_cv **cvp)
{
	struct rumpuser_cv *cv;
	
	cv = kmalloc(sizeof(struct rumpuser_cv), GFP_KERNEL);
	INIT_LIST_HEAD(&cv->waiters);
	cv->nwaiters = 0;
	spin_lock_init(&cv->slock);
	*cvp = cv;
}

void
rumpuser_cv_has_waiters(struct rumpuser_cv *cv, int *rv)
{

	*rv = cv->nwaiters;
}

void
rumpuser_cv_destroy(struct rumpuser_cv *cv)
{

	BUG_ON(cv->nwaiters);
	kfree(cv);
}

static void
cv_resched(struct rumpuser_mtx *mtx, int nlocks)
{

	/*
	 * uuh.  I guess another mutex flag to make this more obvious.
	 * See the verbose comment in NetBSD lib/librumpuser for more info
	 */
	if ((mtx->flags & (RUMPUSER_MTX_KMUTEX | RUMPUSER_MTX_SPIN)) ==
	    (RUMPUSER_MTX_KMUTEX | RUMPUSER_MTX_SPIN)) {
		rumpkern_sched(nlocks, mtx);
		rumpuser_mutex_enter_nowrap(mtx);
	} else {
		mutex_lock(&mtx->lkmtx);
		mtxenter(mtx);
		rumpkern_sched(nlocks, mtx);
	}
}

void
rumpuser_cv_wait(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx)
{
	struct waitobj wo;
	int nlocks;

	rumpkern_unsched(&nlocks, mtx);
	addwaiter(cv, &wo);
	rumpuser_mutex_exit(mtx);
	wait_event(wo.wq, wo.wakeupdone);
	cv_resched(mtx, nlocks);
	BUG_ON(!wo.wakeupdone);
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
	struct timespec ts;
	unsigned long timo;
	int rv, nlocks;

	rumpkern_unsched(&nlocks, mtx);
	addwaiter(cv, &wo);
	rumpuser_mutex_exit(mtx);

	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	timo = timespec_to_jiffies(&ts);

	rv = wait_event_timeout(wo.wq, wo.wakeupdone, timo);
	cv_resched(mtx, nlocks);
	rmwaiter(cv, &wo);

	return rv == 0 ? EWOULDBLOCK : 0;
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

        rumpkern_unsched(&nlocks, NULL);
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
#define MAXTASK 256
static struct tasklwp {
	struct task_struct *tsk;
	struct lwp *tsklwp;
} lwps[MAXTASK];

/*
 * l != NULL: set current task (must not be set)
 * l == NULL: unset current task (must be set)
 */
void
rumpuser_curlwpop(enum rumplwpop op, struct lwp *l)
{
	struct task_struct *cur;
	struct tasklwp *t;
	int i;

	switch (op) {
	case RUMPUSER_LWP_CREATE:
		mutex_lock(&curlwpmtx);
		for (i = 0; i < MAXTASK; i++) {
			BUG_ON(lwps[i].tsklwp == l); /* half-way assert ... */
			if (lwps[i].tsklwp == NULL) {
				lwps[i].tsklwp = l;
				break;
			}
		}
		if (i == MAXTASK)
			panic("i can't do it captain, i need more tasks!");
		mutex_unlock(&curlwpmtx);
		break;
	case RUMPUSER_LWP_DESTROY:
		mutex_lock(&curlwpmtx);
		for (i = 0; i < MAXTASK; i++) {
			if (lwps[i].tsklwp == l)
				break;
		}
		BUG_ON(i == MAXTASK);
		lwps[i].tsklwp = NULL;
		mutex_unlock(&curlwpmtx);
		break;
	case RUMPUSER_LWP_SET:
		/* no need to lock, current & l are guaranteed to be stable */
		t = NULL;
		cur = current;
		if (l) {
			for (i = 0; i < MAXTASK; i++) {
				if (lwps[i].tsklwp == l) {
					t = &lwps[i];
					break;
				}
			}
			BUG_ON(!t);
			BUG_ON(t->tsk != NULL);
			t->tsk = cur;
		} else {
			for (i = 0; i < MAXTASK; i++) {
				if (lwps[i].tsk == cur) {
					t = &lwps[i];
					break;
				}
			}
			BUG_ON(!t);
			BUG_ON(t->tsk == NULL);
			t->tsk = NULL;
		}
		break;
	}
}

struct lwp *
rumpuser_curlwp(void)
{
	struct task_struct *cur = current;
	int i;

	/* no need to lock, tsk is stable here */
	for (i = 0; i < MAXTASK; i++) {
		if (lwps[i].tsk == cur) {
			return lwps[i].tsklwp;
		}
	}
	return NULL;
}
