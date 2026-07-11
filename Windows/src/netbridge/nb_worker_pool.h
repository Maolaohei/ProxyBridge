#ifndef NB_WORKER_POOL_H
#define NB_WORKER_POOL_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef DWORD (WINAPI *NbWorkFn)(LPVOID arg);

BOOL nb_worker_pool_init(DWORD worker_count);
void nb_worker_pool_shutdown(void);
/* Queue work item. Returns FALSE if queue full / not running. */
BOOL nb_worker_pool_submit(NbWorkFn fn, LPVOID arg);

#ifdef __cplusplus
}
#endif

#endif
