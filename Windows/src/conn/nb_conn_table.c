#include "conn/nb_conn_table.h"

#include <stdlib.h>
#include <string.h>

#define CONN_STALE_MS  60000ull
#define CONN_POOL_MAX  1024

typedef struct CONNECTION_INFO {
    UINT16 src_port;
    UINT32 src_ip;
    UINT32 orig_dest_ip;
    UINT16 orig_dest_port;
    BOOL   is_tracked;
    ULONGLONG last_activity;
    UINT32 proxy_config_id;
    BOOL   is_ipv6;
    UINT8  src_ip6[16];
    UINT8  orig_dest_ip6[16];
    struct CONNECTION_INFO *pool_next;
} CONNECTION_INFO;

/* Direct port map: source port is unique in our model (one flow decision per local port). */
static CONNECTION_INFO *g_by_port[65536];
static CONNECTION_INFO *g_pool_free = NULL;
static volatile LONG g_pool_free_count = 0;
static SRWLOCK g_lock;
static volatile LONG g_inited;
static volatile LONG g_count;

static CONNECTION_INFO *conn_alloc(void)
{
    CONNECTION_INFO *c = NULL;
    if (g_pool_free) {
        c = g_pool_free;
        g_pool_free = c->pool_next;
        InterlockedDecrement(&g_pool_free_count);
        ZeroMemory(c, sizeof(*c));
        return c;
    }
    c = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (c) ZeroMemory(c, sizeof(*c));
    return c;
}

static void conn_free(CONNECTION_INFO *c)
{
    if (!c) return;
    if (g_pool_free_count < CONN_POOL_MAX) {
        c->pool_next = g_pool_free;
        g_pool_free = c;
        InterlockedIncrement(&g_pool_free_count);
        return;
    }
    free(c);
}

void nb_conn_init(void)
{
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0)
        return;
    InitializeSRWLock(&g_lock);
    ZeroMemory(g_by_port, sizeof(g_by_port));
    g_pool_free = NULL;
    InterlockedExchange(&g_pool_free_count, 0);
    InterlockedExchange(&g_count, 0);
}

void nb_conn_clear_all(void)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < 65536; i++) {
        if (g_by_port[i]) {
            conn_free(g_by_port[i]);
            g_by_port[i] = NULL;
        }
    }
    InterlockedExchange(&g_count, 0);
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    CONNECTION_INFO *existing = g_by_port[src_port];
    if (existing) {
        existing->src_ip = src_ip;
        existing->orig_dest_ip = dest_ip;
        existing->orig_dest_port = dest_port;
        existing->proxy_config_id = proxy_config_id;
        existing->is_tracked = TRUE;
        existing->is_ipv6 = FALSE;
        existing->last_activity = GetTickCount64();
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    CONNECTION_INFO *conn = conn_alloc();
    if (!conn) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();
    g_by_port[src_port] = conn;
    InterlockedIncrement(&g_count);
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add_v6(UINT16 src_port, const UINT8 src_ip6[16], const UINT8 dest_ip6[16], UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    CONNECTION_INFO *existing = g_by_port[src_port];
    if (existing) {
        existing->is_ipv6 = TRUE;
        memcpy(existing->src_ip6, src_ip6, 16);
        memcpy(existing->orig_dest_ip6, dest_ip6, 16);
        existing->orig_dest_port = dest_port;
        existing->proxy_config_id = proxy_config_id;
        existing->is_tracked = TRUE;
        existing->last_activity = GetTickCount64();
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    CONNECTION_INFO *conn = conn_alloc();
    if (!conn) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    conn->src_port = src_port;
    conn->is_ipv6 = TRUE;
    memcpy(conn->src_ip6, src_ip6, 16);
    memcpy(conn->orig_dest_ip6, dest_ip6, 16);
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();
    g_by_port[src_port] = conn;
    InterlockedIncrement(&g_count);
    ReleaseSRWLockExclusive(&g_lock);
}

BOOL nb_conn_get_full_v6(UINT16 src_port, UINT8 dest_ip6[16], UINT16 *dest_port, UINT32 *proxy_config_id)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    CONNECTION_INFO *conn = g_by_port[src_port];
    if (conn && conn->is_ipv6) {
        memcpy(dest_ip6, conn->orig_dest_ip6, 16);
        *dest_port = conn->orig_dest_port;
        if (proxy_config_id) *proxy_config_id = conn->proxy_config_id;
        InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
        found = TRUE;
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_find_v6_udp_sender(const UINT8 orig_dest_ip6[16], UINT16 orig_dest_port, UINT8 src_ip6[16], UINT16 *src_port)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    for (int p = 0; p < 65536; p++) {
        CONNECTION_INFO *conn = g_by_port[p];
        if (!conn || !conn->is_ipv6 || !conn->is_tracked) continue;
        if (conn->orig_dest_port == orig_dest_port &&
            memcmp(conn->orig_dest_ip6, orig_dest_ip6, 16) == 0) {
            memcpy(src_ip6, conn->src_ip6, 16);
            *src_port = conn->src_port;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_find_v4_udp_sender(UINT32 orig_dest_ip, UINT16 orig_dest_port, UINT32 *src_ip, UINT16 *src_port)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    for (int p = 0; p < 65536; p++) {
        CONNECTION_INFO *conn = g_by_port[p];
        if (!conn || conn->is_ipv6 || !conn->is_tracked) continue;
        if (conn->orig_dest_port == orig_dest_port &&
            conn->orig_dest_ip == orig_dest_ip) {
            *src_ip = conn->src_ip;
            *src_port = conn->src_port;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_get(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port)
{
    return nb_conn_get_full(src_port, dest_ip, dest_port, NULL);
}

BOOL nb_conn_get_full(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    CONNECTION_INFO *conn = g_by_port[src_port];
    if (conn && !conn->is_ipv6) {
        *dest_ip = conn->orig_dest_ip;
        *dest_port = conn->orig_dest_port;
        if (proxy_config_id) *proxy_config_id = conn->proxy_config_id;
        InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
        found = TRUE;
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

UINT32 nb_conn_get_proxy_id(UINT16 src_port)
{
    if (!g_inited) return 0;
    UINT32 id = 0;
    AcquireSRWLockShared(&g_lock);
    CONNECTION_INFO *conn = g_by_port[src_port];
    if (conn) id = conn->proxy_config_id;
    ReleaseSRWLockShared(&g_lock);
    return id;
}

BOOL nb_conn_is_tracked(UINT16 src_port)
{
    if (!g_inited) return FALSE;
    BOOL tracked = FALSE;
    AcquireSRWLockShared(&g_lock);
    CONNECTION_INFO *conn = g_by_port[src_port];
    if (conn) tracked = conn->is_tracked;
    ReleaseSRWLockShared(&g_lock);
    return tracked;
}

void nb_conn_remove(UINT16 src_port)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    CONNECTION_INFO *conn = g_by_port[src_port];
    if (conn) {
        g_by_port[src_port] = NULL;
        InterlockedDecrement(&g_count);
        conn_free(conn);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_cleanup_stale(void)
{
    if (!g_inited) return;
    ULONGLONG now = GetTickCount64();
    AcquireSRWLockExclusive(&g_lock);
    for (int p = 0; p < 65536; p++) {
        CONNECTION_INFO *conn = g_by_port[p];
        if (!conn) continue;
        if ((now - conn->last_activity) > CONN_STALE_MS) {
            g_by_port[p] = NULL;
            InterlockedDecrement(&g_count);
            conn_free(conn);
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

UINT32 nb_conn_count(void)
{
    return (UINT32)InterlockedCompareExchange(&g_count, 0, 0);
}
