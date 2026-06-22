#ifndef NB_BUF_H
#define NB_BUF_H

#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

/*
 * Thread-safe buffer pool for zero-copy forwarding.
 *
 * Replaces per-packet malloc/free with pooled buffers to reduce
 * heap pressure and allocation overhead. Uses Windows InterlockedSList
 * (lock-free) for the free lists.
 *
 * Size classes:
 *   NB_BUF_SMALL   2048 bytes   - UDP relay headers, small payloads
 *   NB_BUF_MEDIUM  65535 bytes  - max UDP packet
 *   NB_BUF_LARGE   131072 bytes - TCP relay buffers (128 KB)
 */

#define NB_BUF_SMALL   2048
#define NB_BUF_MEDIUM  65535
#define NB_BUF_LARGE   131072

#define NB_BUF_POOL_MAX 64

typedef struct {
    SLIST_HEADER free_list;
    volatile LONG count;
    UINT32        buf_size;
} NbBufPool;

/* Pool index for release identification */
typedef enum {
    NB_POOL_SMALL  = 0,
    NB_POOL_MEDIUM = 1,
    NB_POOL_LARGE  = 2,
    NB_POOL_COUNT  = 3
} NbPoolId;

/* Initialize all buffer pools. Call once at startup. */
void nb_buf_init(void);

/* Acquire a buffer of the given pool. Returns NULL on OOM. */
void *nb_buf_acquire_pool(NbPoolId pool_id);

/* Return a buffer to its pool. */
void nb_buf_release_pool(void *buf, NbPoolId pool_id);

/* Shutdown: free all pooled buffers. */
void nb_buf_shutdown(void);

#endif /* NB_BUF_H */
