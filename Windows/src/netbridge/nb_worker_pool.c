#include "netbridge/nb_worker_pool.h"

#include <stdlib.h>

#define NB_WQ_CAP 4096

typedef struct {
    NbWorkFn fn;
    LPVOID arg;
} NbWorkItem;

static NbWorkItem g_q[NB_WQ_CAP];
static volatile LONG g_q_head;
static volatile LONG g_q_tail;
static volatile LONG g_q_count;
static HANDLE g_sem;
static HANDLE *g_threads;
static DWORD g_thread_count;
static volatile BOOL g_running;
static CRITICAL_SECTION g_cs;

static DWORD WINAPI worker_main(LPVOID arg)
{
    (void)arg;
    while (g_running) {
        if (WaitForSingleObject(g_sem, 200) != WAIT_OBJECT_0)
            continue;

        NbWorkItem item = {0};
        EnterCriticalSection(&g_cs);
        if (g_q_count > 0) {
            item = g_q[g_q_head];
            g_q_head = (g_q_head + 1) % NB_WQ_CAP;
            g_q_count--;
        }
        LeaveCriticalSection(&g_cs);

        if (item.fn)
            item.fn(item.arg);
    }
    return 0;
}

BOOL nb_worker_pool_init(DWORD worker_count)
{
    if (g_running) return TRUE;
    if (worker_count == 0) worker_count = 8;
    if (worker_count > 64) worker_count = 64;

    InitializeCriticalSection(&g_cs);
    g_sem = CreateSemaphoreW(NULL, 0, NB_WQ_CAP, NULL);
    if (!g_sem) return FALSE;

    g_threads = (HANDLE*)calloc(worker_count, sizeof(HANDLE));
    if (!g_threads) {
        CloseHandle(g_sem); g_sem = NULL;
        return FALSE;
    }
    g_thread_count = worker_count;
    g_q_head = g_q_tail = g_q_count = 0;
    g_running = TRUE;

    for (DWORD i = 0; i < worker_count; i++) {
        g_threads[i] = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
        if (!g_threads[i]) {
            g_running = FALSE;
            return FALSE;
        }
    }
    return TRUE;
}

void nb_worker_pool_shutdown(void)
{
    if (!g_running && !g_threads) return;
    g_running = FALSE;
    if (g_sem) {
        for (DWORD i = 0; i < g_thread_count; i++)
            ReleaseSemaphore(g_sem, 1, NULL);
    }
    if (g_threads) {
        WaitForMultipleObjects(g_thread_count, g_threads, TRUE, 3000);
        for (DWORD i = 0; i < g_thread_count; i++) {
            if (g_threads[i]) CloseHandle(g_threads[i]);
        }
        free(g_threads);
        g_threads = NULL;
    }
    if (g_sem) { CloseHandle(g_sem); g_sem = NULL; }
    DeleteCriticalSection(&g_cs);
    g_thread_count = 0;
    g_q_head = g_q_tail = g_q_count = 0;
}

BOOL nb_worker_pool_submit(NbWorkFn fn, LPVOID arg)
{
    if (!g_running || !fn) return FALSE;
    EnterCriticalSection(&g_cs);
    if (g_q_count >= NB_WQ_CAP) {
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }
    g_q[g_q_tail].fn = fn;
    g_q[g_q_tail].arg = arg;
    g_q_tail = (g_q_tail + 1) % NB_WQ_CAP;
    g_q_count++;
    LeaveCriticalSection(&g_cs);
    ReleaseSemaphore(g_sem, 1, NULL);
    return TRUE;
}
