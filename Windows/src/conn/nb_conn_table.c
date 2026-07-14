#include "conn/nb_conn_table.h"

#include <stdlib.h>
#include <string.h>

#define CONN_STALE_MS  60000ull
#define CONN_POOL_MAX  1024
#define REV_TABLE_SIZE 8192u
#define REV_PROBE      8u

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

/* Direct port map: primary key remains local src_port (WinDivert SYN path).
 * Callers overwrite on rebind; reverse index keeps UDP reply path O(1)-ish. */
static CONNECTION_INFO *g_by_port[65536];

typedef struct {
    UINT8  used;
    UINT8  is_ipv6;
    UINT16 src_port;
    UINT16 dest_port;
    UINT32 dest_ip;
    UINT8  dest_ip6[16];
} RevEntry;

static RevEntry g_rev[REV_TABLE_SIZE];
static CONNECTION_INFO *g_pool_free = NULL;
static volatile LONG g_pool_free_count = 0;
static SRWLOCK g_lock;
static volatile LONG g_inited;
static volatile LONG g_count;

static UINT32 mix32(UINT32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static UINT32 rev_hash_v4(UINT32 dip, UINT16 dport)
{
    return mix32(dip ^ ((UINT32)dport << 16)) % REV_TABLE_SIZE;
}

static UINT32 rev_hash_v6(const UINT8 dip6[16], UINT16 dport)
{
    UINT32 h = 2166136261u;
    for (int i = 0; i < 16; i++) { h ^= dip6[i]; h *= 16777619u; }
    h ^= dport;
    return h % REV_TABLE_SIZE;
}

static void rev_clear_slot_matching(UINT16 src_port, BOOL is_ipv6,
                                    UINT32 dest_ip, const UINT8 dest_ip6[16], UINT16 dest_port)
{
    UINT32 idx = is_ipv6 ? rev_hash_v6(dest_ip6, dest_port) : rev_hash_v4(dest_ip, dest_port);
    for (UINT32 p = 0; p < REV_PROBE; p++) {
        RevEntry *e = &g_rev[(idx + p) % REV_TABLE_SIZE];
        if (!e->used) continue;
        if (e->src_port != src_port || e->is_ipv6 != (is_ipv6 ? 1 : 0) || e->dest_port != dest_port)
            continue;
        if (is_ipv6) {
            if (memcmp(e->dest_ip6, dest_ip6, 16) == 0) {
                e->used = 0;
                return;
            }
        } else if (e->dest_ip == dest_ip) {
            e->used = 0;
            return;
        }
    }
}

static void rev_put(UINT16 src_port, BOOL is_ipv6,
                    UINT32 dest_ip, const UINT8 dest_ip6[16], UINT16 dest_port)
{
    UINT32 idx = is_ipv6 ? rev_hash_v6(dest_ip6, dest_port) : rev_hash_v4(dest_ip, dest_port);
    for (UINT32 p = 0; p < REV_PROBE; p++) {
        RevEntry *e = &g_rev[(idx + p) % REV_TABLE_SIZE];
        if (!e->used ||
            (e->src_port == src_port && e->is_ipv6 == (is_ipv6 ? 1 : 0) && e->dest_port == dest_port &&
             ((!is_ipv6 && e->dest_ip == dest_ip) ||
              (is_ipv6 && memcmp(e->dest_ip6, dest_ip6, 16) == 0)))) {
            e->used = 1;
            e->is_ipv6 = is_ipv6 ? 1 : 0;
            e->src_port = src_port;
            e->dest_port = dest_port;
            e->dest_ip = dest_ip;
            if (is_ipv6 && dest_ip6)
                memcpy(e->dest_ip6, dest_ip6, 16);
            else
                ZeroMemory(e->dest_ip6, 16);
            return;
        }
    }
    /* Crowded: overwrite first slot */
    RevEntry *e = &g_rev[idx];
    e->used = 1;
    e->is_ipv6 = is_ipv6 ? 1 : 0;
    e->src_port = src_port;
    e->dest_port = dest_port;
    e->dest_ip = dest_ip;
    if (is_ipv6 && dest_ip6)
        memcpy(e->dest_ip6, dest_ip6, 16);
    else
        ZeroMemory(e->dest_ip6, 16);
}

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

static void conn_unlink_locked(CONNECTION_INFO *conn)
{
    if (!conn) return;
    if (conn->is_ipv6)
        rev_clear_slot_matching(conn->src_port, TRUE, 0, conn->orig_dest_ip6, conn->orig_dest_port);
    else
        rev_clear_slot_matching(conn->src_port, FALSE, conn->orig_dest_ip, NULL, conn->orig_dest_port);
}

void nb_conn_init(void)
{
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0)
        return;
    InitializeSRWLock(&g_lock);
    ZeroMemory(g_by_port, sizeof(g_by_port));
    ZeroMemory(g_rev, sizeof(g_rev));
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
    ZeroMemory(g_rev, sizeof(g_rev));
    InterlockedExchange(&g_count, 0);
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    CONNECTION_INFO *existing = g_by_port[src_port];
    if (existing) {
        conn_unlink_locked(existing);
        existing->src_ip = src_ip;
        existing->orig_dest_ip = dest_ip;
        existing->orig_dest_port = dest_port;
        existing->proxy_config_id = proxy_config_id;
        existing->is_tracked = TRUE;
        existing->is_ipv6 = FALSE;
        existing->last_activity = GetTickCount64();
        rev_put(src_port, FALSE, dest_ip, NULL, dest_port);
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
    rev_put(src_port, FALSE, dest_ip, NULL, dest_port);
    InterlockedIncrement(&g_count);
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add_v6(UINT16 src_port, const UINT8 src_ip6[16], const UINT8 dest_ip6[16], UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    CONNECTION_INFO *existing = g_by_port[src_port];
    if (existing) {
        conn_unlink_locked(existing);
        existing->is_ipv6 = TRUE;
        memcpy(existing->src_ip6, src_ip6, 16);
        memcpy(existing->orig_dest_ip6, dest_ip6, 16);
        existing->orig_dest_port = dest_port;
        existing->proxy_config_id = proxy_config_id;
        existing->is_tracked = TRUE;
        existing->last_activity = GetTickCount64();
        rev_put(src_port, TRUE, 0, dest_ip6, dest_port);
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
    rev_put(src_port, TRUE, 0, dest_ip6, dest_port);
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
    UINT32 idx = rev_hash_v6(orig_dest_ip6, orig_dest_port);
    for (UINT32 p = 0; p < REV_PROBE; p++) {
        RevEntry *e = &g_rev[(idx + p) % REV_TABLE_SIZE];
        if (!e->used || !e->is_ipv6 || e->dest_port != orig_dest_port)
            continue;
        if (memcmp(e->dest_ip6, orig_dest_ip6, 16) != 0)
            continue;
        CONNECTION_INFO *conn = g_by_port[e->src_port];
        if (!conn || !conn->is_ipv6 || !conn->is_tracked)
            continue;
        if (conn->orig_dest_port == orig_dest_port &&
            memcmp(conn->orig_dest_ip6, orig_dest_ip6, 16) == 0) {
            memcpy(src_ip6, conn->src_ip6, 16);
            *src_port = conn->src_port;
            found = TRUE;
            break;
        }
    }
    /* Fallback scan if reverse index missed (crowded overwrite). */
    if (!found) {
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
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_find_v4_udp_sender(UINT32 orig_dest_ip, UINT16 orig_dest_port, UINT32 *src_ip, UINT16 *src_port)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    UINT32 idx = rev_hash_v4(orig_dest_ip, orig_dest_port);
    for (UINT32 p = 0; p < REV_PROBE; p++) {
        RevEntry *e = &g_rev[(idx + p) % REV_TABLE_SIZE];
        if (!e->used || e->is_ipv6 || e->dest_port != orig_dest_port || e->dest_ip != orig_dest_ip)
            continue;
        CONNECTION_INFO *conn = g_by_port[e->src_port];
        if (!conn || conn->is_ipv6 || !conn->is_tracked) continue;
        if (conn->orig_dest_port == orig_dest_port && conn->orig_dest_ip == orig_dest_ip) {
            *src_ip = conn->src_ip;
            *src_port = conn->src_port;
            found = TRUE;
            break;
        }
    }
    if (!found) {
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
        conn_unlink_locked(conn);
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
            conn_unlink_locked(conn);
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
