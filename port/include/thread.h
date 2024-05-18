#ifndef _IN_THREAD_H
#define _IN_THREAD_H

#include <PR/ultratypes.h>
#include "platform.h"

// TODO: backends
#ifndef PLATFORM_USE_PTHREAD
#error "No available thread backend."
#endif

#include <pthread.h>

#define SYSMUTEX_STATIC_INIT PTHREAD_MUTEX_INITIALIZER

typedef pthread_t systhread;
typedef pthread_mutex_t sysmutex;

typedef void *(*systhreadfn)(void *);

s32 sysThreadCreate(systhread *thread, systhreadfn func, void *arg);
s32 sysThreadJoin(systhread *thread, void **result);

void sysMutexLock(sysmutex *mtx);
void sysMutexUnlock(sysmutex *mtx);

#endif // _IN_THREAD_H
