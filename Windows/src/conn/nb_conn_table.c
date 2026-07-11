#include "conn/nb_conn_table.h"

#include <stdlib.h>
#include <string.h>

#define CONNECTION_HASH_SIZE 4096
#define CONN_STALE_MS        60000ull

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
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

static CONNECTION_INFO *g_table[CONNECTION_HASH_SIZE];
static SRWLOCK g_lock;
static volatile LONG g_inited;

void nb_conn_init(void)
{
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0)
        return;
    InitializeSRWLock(&g_lock);
    ZeroMemory(g_table, sizeof(g_table));
}

void nb_conn_clear_all(void)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++) {
        while (g_table[i] != NULL) {
            CONNECTION_INFO *to_free = g_table[i];
            g_table[i] = g_table[i]->next;
            free(to_free);
        }
    }
    ZeroMemory(g_table, sizeof(g_table));
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = g_table[hash];
    while (existing != NULL) {
        if (existing->src_port == src_port) {
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
        existing = existing->next;
    }
    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    ZeroMemory(conn, sizeof(*conn));
    conn->src_port = src_port;
    conn->src_ip = src_ip;
    conn->orig_dest_ip = dest_ip;
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();
    conn->next = g_table[hash];
    g_table[hash] = conn;
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_add_v6(UINT16 src_port, const UINT8 src_ip6[16], const UINT8 dest_ip6[16], UINT16 dest_port, UINT32 proxy_config_id)
{
    if (!g_inited) nb_conn_init();
    AcquireSRWLockExclusive(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *existing = g_table[hash];
    while (existing != NULL) {
        if (existing->src_port == src_port) {
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
        existing = existing->next;
    }
    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    ZeroMemory(conn, sizeof(*conn));
    conn->src_port = src_port;
    conn->is_ipv6 = TRUE;
    memcpy(conn->src_ip6, src_ip6, 16);
    memcpy(conn->orig_dest_ip6, dest_ip6, 16);
    conn->orig_dest_port = dest_port;
    conn->proxy_config_id = proxy_config_id;
    conn->is_tracked = TRUE;
    conn->last_activity = GetTickCount64();
    conn->next = g_table[hash];
    g_table[hash] = conn;
    ReleaseSRWLockExclusive(&g_lock);
}

BOOL nb_conn_get_full_v6(UINT16 src_port, UINT8 dest_ip6[16], UINT16 *dest_port, UINT32 *proxy_config_id)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = g_table[hash];
    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_ipv6) {
            memcpy(dest_ip6, conn->orig_dest_ip6, 16);
            *dest_port = conn->orig_dest_port;
            if (proxy_config_id != NULL) *proxy_config_id = conn->proxy_config_id;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_find_v6_udp_sender(const UINT8 orig_dest_ip6[16], UINT16 orig_dest_port, UINT8 src_ip6[16], UINT16 *src_port)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    ULONGLONG best = 0;
    AcquireSRWLockShared(&g_lock);
    for (int b = 0; b < CONNECTION_HASH_SIZE; b++) {
        CONNECTION_INFO *conn = g_table[b];
        while (conn != NULL) {
            if (conn->is_ipv6 && conn->orig_dest_port == orig_dest_port &&
                memcmp(conn->orig_dest_ip6, orig_dest_ip6, 16) == 0) {
                if (!found || conn->last_activity > best) {
                    memcpy(src_ip6, conn->src_ip6, 16);
                    *src_port = conn->src_port;
                    best = conn->last_activity;
                    found = TRUE;
                }
            }
            conn = conn->next;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_find_v4_udp_sender(UINT32 orig_dest_ip, UINT16 orig_dest_port, UINT32 *src_ip, UINT16 *src_port)
{
    if (!g_inited) return FALSE;
    BOOL found = FALSE;
    ULONGLONG best = 0;
    AcquireSRWLockShared(&g_lock);
    for (int b = 0; b < CONNECTION_HASH_SIZE; b++) {
        CONNECTION_INFO *conn = g_table[b];
        while (conn != NULL) {
            if (!conn->is_ipv6 && conn->orig_dest_ip == orig_dest_ip && conn->orig_dest_port == orig_dest_port) {
                if (!found || conn->last_activity > best) {
                    *src_ip = conn->src_ip;
                    *src_port = conn->src_port;
                    best = conn->last_activity;
                    found = TRUE;
                }
            }
            conn = conn->next;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

BOOL nb_conn_is_tracked(UINT16 src_port)
{
    if (!g_inited) return FALSE;
    BOOL tracked = FALSE;
    AcquireSRWLockShared(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = g_table[hash];
    while (conn != NULL) {
        if (conn->src_port == src_port && conn->is_tracked) {
            tracked = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&g_lock);
    return tracked;
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
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = g_table[hash];
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            *dest_ip = conn->orig_dest_ip;
            *dest_port = conn->orig_dest_port;
            if (proxy_config_id != NULL) *proxy_config_id = conn->proxy_config_id;
            InterlockedExchange64((LONGLONG volatile*)&conn->last_activity, (LONGLONG)GetTickCount64());
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

UINT32 nb_conn_get_proxy_id(UINT16 src_port)
{
    UINT32 proxy_config_id = 0;
    if (!g_inited) return 0;
    AcquireSRWLockShared(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO *conn = g_table[hash];
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            proxy_config_id = conn->proxy_config_id;
            break;
        }
        conn = conn->next;
    }
    ReleaseSRWLockShared(&g_lock);
    return proxy_config_id;
}

void nb_conn_remove(UINT16 src_port)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    int hash = src_port % CONNECTION_HASH_SIZE;
    CONNECTION_INFO **conn_ptr = &g_table[hash];
    while (*conn_ptr != NULL) {
        if ((*conn_ptr)->src_port == src_port) {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_conn_cleanup_stale(void)
{
    if (!g_inited) return;
    ULONGLONG now = GetTickCount64();
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++) {
        AcquireSRWLockExclusive(&g_lock);
        CONNECTION_INFO **conn_ptr = &g_table[i];
        while (*conn_ptr != NULL) {
            if (now - (*conn_ptr)->last_activity > CONN_STALE_MS) {
                CONNECTION_INFO *to_free = *conn_ptr;
                *conn_ptr = (*conn_ptr)->next;
                ReleaseSRWLockExclusive(&g_lock);
                free(to_free);
                AcquireSRWLockExclusive(&g_lock);
            } else {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        ReleaseSRWLockExclusive(&g_lock);
    }
}

UINT32 nb_conn_count(void)
{
    if (!g_inited) return 0;
    UINT32 count = 0;
    AcquireSRWLockShared(&g_lock);
    for (int i = 0; i < CONNECTION_HASH_SIZE; i++) {
        CONNECTION_INFO *ci = g_table[i];
        while (ci) { count++; ci = ci->next; }
    }
    ReleaseSRWLockShared(&g_lock);
    return count;
}
