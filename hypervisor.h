#define KLOCK_WRAP(a)                                                   \
do {                                                                    \
        int nlocks;                                                     \
        rumpuser__kunlock(0, &nlocks, NULL);                            \
        a;                                                              \
        rumpuser__klock(nlocks, NULL);                                  \
} while (/*CONSTCOND*/0)

extern kernel_lockfn	rumpuser__klock;
extern kernel_unlockfn	rumpuser__kunlock;
extern int		rumpuser__wantthreads;
