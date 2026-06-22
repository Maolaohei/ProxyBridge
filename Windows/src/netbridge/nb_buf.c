#include "nb_buf.h"
#include <stdlib.h>

/* Each pooled buffer is a SLIST_ENTRY header followed by the usable data. */
#define NB_BUF_HEADER_SIZE  (sizeof(SLIST_ENTRY))

static NbBufPool g_pools[NB_POOL_COUNT];
static BOOL g_initialized = FALSE;

void nb_buf_init(void)
{
    if (g_initialized) return;

    static const UINT32 sizes[NB_POOL_COUNT] = {
        NB_BUF_SMALL, NB_BUF_MEDIUM, NB_BUF_LARGE
    };

    for (int i = 0; i < NB_POOL_COUNT; i++) {
        InitializeSListHead(&g_pools[i].free_list);
        InterlockedExchange(&g_pools[i].count, 0);
        g_pools[i].buf_size = sizes[i];
    }
    g_initialized = TRUE;
}

void *nb_buf_acquire_pool(NbPoolId pool_id)
{
    if (!g_initialized) nb_buf_init();
    if (pool_id >= NB_POOL_COUNT) return NULL;

    NbBufPool *pool = &g_pools[pool_id];

    /* Try the free list first (lock-free pop) */
    SLIST_ENTRY *entry = InterlockedPopEntrySList(&pool->free_list);
    if (entry) {
        InterlockedDecrement(&pool->count);
        return (void *)((uint8_t *)entry + NB_BUF_HEADER_SIZE);
    }

    /* Pool empty — allocate fresh */
    void *raw = malloc(NB_BUF_HEADER_SIZE + pool->buf_size);
    return raw ? (void *)((uint8_t *)raw + NB_BUF_HEADER_SIZE) : NULL;
}

void nb_buf_release_pool(void *buf, NbPoolId pool_id)
{
    if (!buf || !g_initialized || pool_id >= NB_POOL_COUNT) return;

    NbBufPool *pool = &g_pools[pool_id];

    /* Check pool depth to prevent unbounded growth */
    if (pool->count < NB_BUF_POOL_MAX) {
        SLIST_ENTRY *entry = (SLIST_ENTRY *)((uint8_t *)buf - NB_BUF_HEADER_SIZE);
        InterlockedIncrement(&pool->count);
        InterlockedPushEntrySList(&pool->free_list, entry);
    } else {
        free((uint8_t *)buf - NB_BUF_HEADER_SIZE);
    }
}

void nb_buf_shutdown(void)
{
    if (!g_initialized) return;

    for (int i = 0; i < NB_POOL_COUNT; i++) {
        SLIST_ENTRY *entry;
        while ((entry = InterlockedPopEntrySList(&g_pools[i].free_list)) != NULL) {
            free(entry);
        }
        InterlockedExchange(&g_pools[i].count, 0);
    }
    g_initialized = FALSE;
}
