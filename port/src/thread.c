#include "thread.h"

#ifndef PLATFORM_USE_PTHREAD
#error "No available thread backend."
#endif

#include <pthread.h>

s32 sysThreadCreate(systhread *thread, systhreadfn func, void *arg)
{
	return pthread_create(thread, NULL, func, arg);
}

s32 sysThreadJoin(systhread *thread, void **result)
{
	return pthread_join(*thread, result);
}

void sysMutexLock(sysmutex *mtx)
{
	pthread_mutex_lock(mtx);
}

void sysMutexUnlock(sysmutex *mtx)
{
	pthread_mutex_unlock(mtx);
}
