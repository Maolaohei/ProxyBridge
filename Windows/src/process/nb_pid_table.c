#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <iphlpapi.h>
#include "process/nb_pid_table.h"

#pragma comment(lib, "iphlpapi.lib")

#define PID_SNAP_TTL_MS 80u
#define PID_ENTRY_CACHE 2048
#define PID_ENTRY_TTL_MS 30000u

typedef struct {
    UINT32 src_ip;
    UINT16 src_port;
    DWORD  pid;
    ULONGLONG ts;
    BOOL   is_udp;
    BOOL   used;
} PidEntry;

typedef struct {
    MIB_TCPTABLE_OWNER_PID *tcp4;
    DWORD tcp4_bytes;
    ULONGLONG tcp4_ts;
    MIB_UDPTABLE_OWNER_PID *udp4;
    DWORD udp4_bytes;
    ULONGLONG udp4_ts;
    MIB_TCP6TABLE_OWNER_PID *tcp6;
    DWORD tcp6_bytes;
    ULONGLONG tcp6_ts;
    MIB_UDP6TABLE_OWNER_PID *udp6;
    DWORD udp6_bytes;
    ULONGLONG udp6_ts;
    SRWLOCK lock;
    PidEntry cache[PID_ENTRY_CACHE];
    BOOL inited;
} PidTableState;

static PidTableState g_pt;

void nb_pid_table_init(void)
{
    if (g_pt.inited) return;
    ZeroMemory(&g_pt, sizeof(g_pt));
    InitializeSRWLock(&g_pt.lock);
    g_pt.inited = TRUE;
}

void nb_pid_table_shutdown(void)
{
    AcquireSRWLockExclusive(&g_pt.lock);
    free(g_pt.tcp4); g_pt.tcp4 = NULL;
    free(g_pt.udp4); g_pt.udp4 = NULL;
    free(g_pt.tcp6); g_pt.tcp6 = NULL;
    free(g_pt.udp6); g_pt.udp6 = NULL;
    ZeroMemory(g_pt.cache, sizeof(g_pt.cache));
    ReleaseSRWLockExclusive(&g_pt.lock);
}

static UINT32 cache_hash(UINT32 ip, UINT16 port, BOOL is_udp)
{
    UINT32 h = ip ^ ((UINT32)port << 16) ^ (is_udp ? 0xA5A5A5A5u : 0);
    return h % PID_ENTRY_CACHE;
}

static DWORD cache_get(UINT32 ip, UINT16 port, BOOL is_udp)
{
    ULONGLONG now = GetTickCount64();
    UINT32 idx = cache_hash(ip, port, is_udp);
    PidEntry *e = &g_pt.cache[idx];
    if (e->used && e->src_ip == ip && e->src_port == port && e->is_udp == is_udp &&
        (now - e->ts) < PID_ENTRY_TTL_MS)
        return e->pid;
    return 0;
}

static void cache_put(UINT32 ip, UINT16 port, DWORD pid, BOOL is_udp)
{
    if (pid == 0) return;
    UINT32 idx = cache_hash(ip, port, is_udp);
    PidEntry *e = &g_pt.cache[idx];
    e->src_ip = ip;
    e->src_port = port;
    e->pid = pid;
    e->ts = GetTickCount64();
    e->is_udp = is_udp;
    e->used = TRUE;
}

static BOOL refresh_tcp4(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.tcp4 && (now - g_pt.tcp4_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return FALSE;

    MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) return FALSE;
    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tbl);
        return FALSE;
    }
    free(g_pt.tcp4);
    g_pt.tcp4 = tbl;
    g_pt.tcp4_bytes = size;
    g_pt.tcp4_ts = now;
    return TRUE;
}

static BOOL refresh_udp4(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.udp4 && (now - g_pt.udp4_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    DWORD size = 0;
    DWORD rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return FALSE;

    MIB_UDPTABLE_OWNER_PID *tbl = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) return FALSE;
    if (GetExtendedUdpTable(tbl, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(tbl);
        return FALSE;
    }
    free(g_pt.udp4);
    g_pt.udp4 = tbl;
    g_pt.udp4_bytes = size;
    g_pt.udp4_ts = now;
    return TRUE;
}

static BOOL refresh_tcp6(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.tcp6 && (now - g_pt.tcp6_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return FALSE;

    MIB_TCP6TABLE_OWNER_PID *tbl = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!tbl) return FALSE;
    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tbl);
        return FALSE;
    }
    free(g_pt.tcp6);
    g_pt.tcp6 = tbl;
    g_pt.tcp6_bytes = size;
    g_pt.tcp6_ts = now;
    return TRUE;
}

static BOOL refresh_udp6(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.udp6 && (now - g_pt.udp6_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    DWORD size = 0;
    DWORD rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return FALSE;

    MIB_UDP6TABLE_OWNER_PID *tbl = (MIB_UDP6TABLE_OWNER_PID *)malloc(size);
    if (!tbl) return FALSE;
    if (GetExtendedUdpTable(tbl, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        free(tbl);
        return FALSE;
    }
    free(g_pt.udp6);
    g_pt.udp6 = tbl;
    g_pt.udp6_bytes = size;
    g_pt.udp6_ts = now;
    return TRUE;
}

DWORD nb_pid_lookup_tcp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();
    DWORD cached = cache_get(src_ip, src_port, FALSE);
    if (cached) return cached;

    AcquireSRWLockExclusive(&g_pt.lock);
    cached = cache_get(src_ip, src_port, FALSE);
    if (cached) { ReleaseSRWLockExclusive(&g_pt.lock); return cached; }

    DWORD pid = 0;
    if (refresh_tcp4() && g_pt.tcp4) {
        for (DWORD i = 0; i < g_pt.tcp4->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &g_pt.tcp4->table[i];
            if (row->dwLocalAddr == src_ip &&
                ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid;
                break;
            }
        }
    }
    cache_put(src_ip, src_port, pid, FALSE);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}

DWORD nb_pid_lookup_udp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();
    DWORD cached = cache_get(src_ip, src_port, TRUE);
    if (cached) return cached;

    AcquireSRWLockExclusive(&g_pt.lock);
    cached = cache_get(src_ip, src_port, TRUE);
    if (cached) { ReleaseSRWLockExclusive(&g_pt.lock); return cached; }

    DWORD pid = 0;
    if (refresh_udp4() && g_pt.udp4) {
        for (DWORD i = 0; i < g_pt.udp4->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &g_pt.udp4->table[i];
            if (row->dwLocalAddr == src_ip &&
                ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid;
                break;
            }
        }
        if (pid == 0) {
            for (DWORD i = 0; i < g_pt.udp4->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *row = &g_pt.udp4->table[i];
                if (row->dwLocalAddr == 0 &&
                    ntohs((UINT16)row->dwLocalPort) == src_port) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        }
    }
    cache_put(src_ip, src_port, pid, TRUE);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}

DWORD nb_pid_lookup_tcp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();
    UINT32 key = 0;
    memcpy(&key, src_ip6, 4);
    key ^= src_ip6[15];

    AcquireSRWLockExclusive(&g_pt.lock);
    DWORD pid = 0;
    if (refresh_tcp6() && g_pt.tcp6) {
        for (DWORD i = 0; i < g_pt.tcp6->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID *row = &g_pt.tcp6->table[i];
            if (ntohs((UINT16)row->dwLocalPort) == src_port &&
                memcmp(row->ucLocalAddr, src_ip6, 16) == 0) {
                pid = row->dwOwningPid;
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_pt.lock);
    (void)key;
    return pid;
}

DWORD nb_pid_lookup_udp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();
    AcquireSRWLockExclusive(&g_pt.lock);
    DWORD pid = 0;
    if (refresh_udp6() && g_pt.udp6) {
        for (DWORD i = 0; i < g_pt.udp6->dwNumEntries; i++) {
            MIB_UDP6ROW_OWNER_PID *row = &g_pt.udp6->table[i];
            if (ntohs((UINT16)row->dwLocalPort) == src_port &&
                memcmp(row->ucLocalAddr, src_ip6, 16) == 0) {
                pid = row->dwOwningPid;
                break;
            }
        }
        if (pid == 0) {
            static const UINT8 z16[16] = {0};
            for (DWORD i = 0; i < g_pt.udp6->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID *row = &g_pt.udp6->table[i];
                if (ntohs((UINT16)row->dwLocalPort) == src_port &&
                    memcmp(row->ucLocalAddr, z16, 16) == 0) {
                    pid = row->dwOwningPid;
                    break;
                }
            }
        }
    }
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}
