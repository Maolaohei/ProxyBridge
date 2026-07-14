#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <iphlpapi.h>
#include "process/nb_pid_table.h"

#pragma comment(lib, "iphlpapi.lib")

#define PID_SNAP_TTL_MS 120u
#define PID_ENTRY_CACHE 4096
#define PID_ENTRY_PROBE 4
#define PID_ENTRY_TTL_MS 30000u

typedef struct {
    UINT32 src_ip;
    UINT16 src_port;
    DWORD  pid;
    ULONGLONG ts;
    BOOL   is_udp;
    BOOL   used;
} PidEntry;

/* O(1) port index built after each snapshot refresh.
 * multi=1 means more than one local IP shares the port -> fall back to scan. */
typedef struct {
    DWORD  pid;
    UINT32 ip;   /* local addr for the primary row */
    BYTE   multi;
    BYTE   used;
} PortIndex;

typedef struct {
    MIB_TCPTABLE_OWNER_PID *tcp4;
    DWORD tcp4_bytes;
    ULONGLONG tcp4_ts;
    PortIndex tcp4_idx[65536];

    MIB_UDPTABLE_OWNER_PID *udp4;
    DWORD udp4_bytes;
    ULONGLONG udp4_ts;
    PortIndex udp4_idx[65536];

    MIB_TCP6TABLE_OWNER_PID *tcp6;
    DWORD tcp6_bytes;
    ULONGLONG tcp6_ts;
    PortIndex tcp6_idx[65536];

    MIB_UDP6TABLE_OWNER_PID *udp6;
    DWORD udp6_bytes;
    ULONGLONG udp6_ts;
    PortIndex udp6_idx[65536];

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
    ZeroMemory(g_pt.tcp4_idx, sizeof(g_pt.tcp4_idx));
    ZeroMemory(g_pt.udp4_idx, sizeof(g_pt.udp4_idx));
    ZeroMemory(g_pt.tcp6_idx, sizeof(g_pt.tcp6_idx));
    ZeroMemory(g_pt.udp6_idx, sizeof(g_pt.udp6_idx));
    ReleaseSRWLockExclusive(&g_pt.lock);
}

static UINT32 cache_hash(UINT32 ip, UINT16 port, BOOL is_udp)
{
    UINT32 h = ip ^ ((UINT32)port << 16) ^ (is_udp ? 0xA5A5A5A5u : 0);
    return h % PID_ENTRY_CACHE;
}

/* Caller must hold lock (shared for get, exclusive for put). */
static DWORD cache_get_locked(UINT32 ip, UINT16 port, BOOL is_udp)
{
    ULONGLONG now = GetTickCount64();
    UINT32 start = cache_hash(ip, port, is_udp);
    for (UINT32 p = 0; p < PID_ENTRY_PROBE; p++) {
        PidEntry *e = &g_pt.cache[(start + p) % PID_ENTRY_CACHE];
        if (e->used && e->src_ip == ip && e->src_port == port && e->is_udp == is_udp &&
            (now - e->ts) < PID_ENTRY_TTL_MS)
            return e->pid;
        if (!e->used)
            break;
    }
    return 0;
}

/* Caller must hold exclusive lock. */
static void cache_put_locked(UINT32 ip, UINT16 port, DWORD pid, BOOL is_udp)
{
    if (pid == 0) return;
    UINT32 start = cache_hash(ip, port, is_udp);
    ULONGLONG now = GetTickCount64();
    UINT32 victim = start;
    ULONGLONG oldest = now;
    for (UINT32 p = 0; p < PID_ENTRY_PROBE; p++) {
        UINT32 idx = (start + p) % PID_ENTRY_CACHE;
        PidEntry *e = &g_pt.cache[idx];
        if (!e->used ||
            (e->src_ip == ip && e->src_port == port && e->is_udp == is_udp) ||
            (now - e->ts) >= PID_ENTRY_TTL_MS) {
            e->src_ip = ip;
            e->src_port = port;
            e->pid = pid;
            e->ts = now;
            e->is_udp = is_udp;
            e->used = TRUE;
            return;
        }
        if (e->ts < oldest) {
            oldest = e->ts;
            victim = idx;
        }
    }
    {
        PidEntry *e = &g_pt.cache[victim];
        e->src_ip = ip;
        e->src_port = port;
        e->pid = pid;
        e->ts = now;
        e->is_udp = is_udp;
        e->used = TRUE;
    }
}

static void rebuild_tcp4_index(void)
{
    ZeroMemory(g_pt.tcp4_idx, sizeof(g_pt.tcp4_idx));
    if (!g_pt.tcp4) return;
    for (DWORD i = 0; i < g_pt.tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &g_pt.tcp4->table[i];
        UINT16 port = ntohs((UINT16)row->dwLocalPort);
        PortIndex *ix = &g_pt.tcp4_idx[port];
        if (!ix->used) {
            ix->used = 1;
            ix->pid = row->dwOwningPid;
            ix->ip = row->dwLocalAddr;
            ix->multi = 0;
        } else if (ix->ip != row->dwLocalAddr || ix->pid != row->dwOwningPid) {
            ix->multi = 1;
        }
    }
}

static void rebuild_udp4_index(void)
{
    ZeroMemory(g_pt.udp4_idx, sizeof(g_pt.udp4_idx));
    if (!g_pt.udp4) return;
    for (DWORD i = 0; i < g_pt.udp4->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &g_pt.udp4->table[i];
        UINT16 port = ntohs((UINT16)row->dwLocalPort);
        PortIndex *ix = &g_pt.udp4_idx[port];
        if (!ix->used) {
            ix->used = 1;
            ix->pid = row->dwOwningPid;
            ix->ip = row->dwLocalAddr;
            ix->multi = 0;
        } else if (ix->ip != row->dwLocalAddr || ix->pid != row->dwOwningPid) {
            ix->multi = 1;
        }
    }
}

/* IPv6 port index: multi when multiple owners/scopes share the port. */
static void rebuild_tcp6_index(void)
{
    ZeroMemory(g_pt.tcp6_idx, sizeof(g_pt.tcp6_idx));
    if (!g_pt.tcp6) return;
    for (DWORD i = 0; i < g_pt.tcp6->dwNumEntries; i++) {
        MIB_TCP6ROW_OWNER_PID *row = &g_pt.tcp6->table[i];
        UINT16 port = ntohs((UINT16)row->dwLocalPort);
        PortIndex *ix = &g_pt.tcp6_idx[port];
        if (!ix->used) {
            ix->used = 1;
            ix->pid = row->dwOwningPid;
            ix->ip = 0;
            ix->multi = 0;
        } else if (ix->pid != row->dwOwningPid) {
            ix->multi = 1;
        }
    }
}

static void rebuild_udp6_index(void)
{
    ZeroMemory(g_pt.udp6_idx, sizeof(g_pt.udp6_idx));
    if (!g_pt.udp6) return;
    for (DWORD i = 0; i < g_pt.udp6->dwNumEntries; i++) {
        MIB_UDP6ROW_OWNER_PID *row = &g_pt.udp6->table[i];
        UINT16 port = ntohs((UINT16)row->dwLocalPort);
        PortIndex *ix = &g_pt.udp6_idx[port];
        if (!ix->used) {
            ix->used = 1;
            ix->pid = row->dwOwningPid;
            ix->ip = 0;
            ix->multi = 0;
        } else if (ix->pid != row->dwOwningPid) {
            ix->multi = 1;
        }
    }
}

static BOOL refresh_tcp4(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.tcp4 && (now - g_pt.tcp4_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    for (int retry = 0; retry < 3; retry++) {
        DWORD size = g_pt.tcp4_bytes ? g_pt.tcp4_bytes : 0;
        if (g_pt.tcp4 && size > 0) {
            DWORD rc = GetExtendedTcpTable(g_pt.tcp4, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc == NO_ERROR) {
                g_pt.tcp4_bytes = size;
                g_pt.tcp4_ts = now;
                rebuild_tcp4_index();
                return TRUE;
            }
            if (rc != ERROR_INSUFFICIENT_BUFFER)
                return FALSE;
        } else {
            size = 0;
            DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
                return FALSE;
        }

        MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)realloc(g_pt.tcp4, size);
        if (!tbl) return FALSE;
        g_pt.tcp4 = tbl;
        g_pt.tcp4_bytes = size;

        DWORD rc = GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            g_pt.tcp4_bytes = size;
            g_pt.tcp4_ts = now;
            rebuild_tcp4_index();
            return TRUE;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        g_pt.tcp4_bytes = size ? size : (g_pt.tcp4_bytes * 2 + 4096);
    }
    return FALSE;
}

static BOOL refresh_udp4(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.udp4 && (now - g_pt.udp4_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    for (int retry = 0; retry < 3; retry++) {
        DWORD size = g_pt.udp4_bytes ? g_pt.udp4_bytes : 0;
        if (g_pt.udp4 && size > 0) {
            DWORD rc = GetExtendedUdpTable(g_pt.udp4, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (rc == NO_ERROR) {
                g_pt.udp4_bytes = size;
                g_pt.udp4_ts = now;
                rebuild_udp4_index();
                return TRUE;
            }
            if (rc != ERROR_INSUFFICIENT_BUFFER)
                return FALSE;
        } else {
            size = 0;
            DWORD rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
                return FALSE;
        }

        MIB_UDPTABLE_OWNER_PID *tbl = (MIB_UDPTABLE_OWNER_PID *)realloc(g_pt.udp4, size);
        if (!tbl) return FALSE;
        g_pt.udp4 = tbl;
        g_pt.udp4_bytes = size;

        DWORD rc = GetExtendedUdpTable(tbl, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) {
            g_pt.udp4_bytes = size;
            g_pt.udp4_ts = now;
            rebuild_udp4_index();
            return TRUE;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        g_pt.udp4_bytes = size ? size : (g_pt.udp4_bytes * 2 + 4096);
    }
    return FALSE;
}

static BOOL refresh_tcp6(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.tcp6 && (now - g_pt.tcp6_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    for (int retry = 0; retry < 3; retry++) {
        DWORD size = g_pt.tcp6_bytes ? g_pt.tcp6_bytes : 0;
        if (g_pt.tcp6 && size > 0) {
            DWORD rc = GetExtendedTcpTable(g_pt.tcp6, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc == NO_ERROR) {
                g_pt.tcp6_bytes = size;
                g_pt.tcp6_ts = now;
                rebuild_tcp6_index();
                return TRUE;
            }
            if (rc != ERROR_INSUFFICIENT_BUFFER)
                return FALSE;
        } else {
            size = 0;
            DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
                return FALSE;
        }

        MIB_TCP6TABLE_OWNER_PID *tbl = (MIB_TCP6TABLE_OWNER_PID *)realloc(g_pt.tcp6, size);
        if (!tbl) return FALSE;
        g_pt.tcp6 = tbl;
        g_pt.tcp6_bytes = size;

        DWORD rc = GetExtendedTcpTable(tbl, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            g_pt.tcp6_bytes = size;
            g_pt.tcp6_ts = now;
            rebuild_tcp6_index();
            return TRUE;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        g_pt.tcp6_bytes = size ? size : (g_pt.tcp6_bytes * 2 + 4096);
    }
    return FALSE;
}

static BOOL refresh_udp6(void)
{
    ULONGLONG now = GetTickCount64();
    if (g_pt.udp6 && (now - g_pt.udp6_ts) < PID_SNAP_TTL_MS)
        return TRUE;

    for (int retry = 0; retry < 3; retry++) {
        DWORD size = g_pt.udp6_bytes ? g_pt.udp6_bytes : 0;
        if (g_pt.udp6 && size > 0) {
            DWORD rc = GetExtendedUdpTable(g_pt.udp6, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (rc == NO_ERROR) {
                g_pt.udp6_bytes = size;
                g_pt.udp6_ts = now;
                rebuild_udp6_index();
                return TRUE;
            }
            if (rc != ERROR_INSUFFICIENT_BUFFER)
                return FALSE;
        } else {
            size = 0;
            DWORD rc = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0)
                return FALSE;
        }

        MIB_UDP6TABLE_OWNER_PID *tbl = (MIB_UDP6TABLE_OWNER_PID *)realloc(g_pt.udp6, size);
        if (!tbl) return FALSE;
        g_pt.udp6 = tbl;
        g_pt.udp6_bytes = size;

        DWORD rc = GetExtendedUdpTable(tbl, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) {
            g_pt.udp6_bytes = size;
            g_pt.udp6_ts = now;
            rebuild_udp6_index();
            return TRUE;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return FALSE;
        g_pt.udp6_bytes = size ? size : (g_pt.udp6_bytes * 2 + 4096);
    }
    return FALSE;
}

static DWORD scan_tcp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.tcp4) return 0;
    for (DWORD i = 0; i < g_pt.tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &g_pt.tcp4->table[i];
        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
            return row->dwOwningPid;
    }
    return 0;
}

static DWORD scan_udp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.udp4) return 0;
    for (DWORD i = 0; i < g_pt.udp4->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &g_pt.udp4->table[i];
        if (row->dwLocalAddr == src_ip &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
            return row->dwOwningPid;
    }
    for (DWORD i = 0; i < g_pt.udp4->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *row = &g_pt.udp4->table[i];
        if (row->dwLocalAddr == 0 &&
            ntohs((UINT16)row->dwLocalPort) == src_port)
            return row->dwOwningPid;
    }
    return 0;
}

static DWORD scan_tcp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.tcp6) return 0;
    for (DWORD i = 0; i < g_pt.tcp6->dwNumEntries; i++) {
        MIB_TCP6ROW_OWNER_PID *row = &g_pt.tcp6->table[i];
        if (ntohs((UINT16)row->dwLocalPort) == src_port &&
            memcmp(row->ucLocalAddr, src_ip6, 16) == 0)
            return row->dwOwningPid;
    }
    return 0;
}

static DWORD scan_udp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.udp6) return 0;
    for (DWORD i = 0; i < g_pt.udp6->dwNumEntries; i++) {
        MIB_UDP6ROW_OWNER_PID *row = &g_pt.udp6->table[i];
        if (ntohs((UINT16)row->dwLocalPort) == src_port &&
            memcmp(row->ucLocalAddr, src_ip6, 16) == 0)
            return row->dwOwningPid;
    }
    static const UINT8 zero[16] = {0};
    for (DWORD i = 0; i < g_pt.udp6->dwNumEntries; i++) {
        MIB_UDP6ROW_OWNER_PID *row = &g_pt.udp6->table[i];
        if (ntohs((UINT16)row->dwLocalPort) == src_port &&
            memcmp(row->ucLocalAddr, zero, 16) == 0)
            return row->dwOwningPid;
    }
    return 0;
}

static DWORD lookup_tcp4_indexed(UINT32 src_ip, UINT16 src_port)
{
    PortIndex *ix = &g_pt.tcp4_idx[src_port];
    if (!ix->used) return 0;
    if (ix->multi) return scan_tcp4(src_ip, src_port);
    if (ix->ip == src_ip || ix->ip == 0)
        return ix->pid;
    return 0;
}

static DWORD lookup_udp4_indexed(UINT32 src_ip, UINT16 src_port)
{
    PortIndex *ix = &g_pt.udp4_idx[src_port];
    if (!ix->used) return 0;
    if (ix->multi) return scan_udp4(src_ip, src_port);
    if (ix->ip == src_ip || ix->ip == 0)
        return ix->pid;
    return 0;
}

static DWORD lookup_tcp6_indexed(const UINT8 src_ip6[16], UINT16 src_port)
{
    PortIndex *ix = &g_pt.tcp6_idx[src_port];
    if (!ix->used) return 0;
    if (ix->multi) return scan_tcp6(src_ip6, src_port);
    return ix->pid ? scan_tcp6(src_ip6, src_port) : 0;
}

static DWORD lookup_udp6_indexed(const UINT8 src_ip6[16], UINT16 src_port)
{
    PortIndex *ix = &g_pt.udp6_idx[src_port];
    if (!ix->used) return 0;
    if (ix->multi) return scan_udp6(src_ip6, src_port);
    return ix->pid ? scan_udp6(src_ip6, src_port) : 0;
}

DWORD nb_pid_lookup_tcp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();

    AcquireSRWLockShared(&g_pt.lock);
    DWORD cached = cache_get_locked(src_ip, src_port, FALSE);
    if (cached) { ReleaseSRWLockShared(&g_pt.lock); return cached; }
    if (g_pt.tcp4 && (GetTickCount64() - g_pt.tcp4_ts) < PID_SNAP_TTL_MS) {
        DWORD pid = lookup_tcp4_indexed(src_ip, src_port);
        ReleaseSRWLockShared(&g_pt.lock);
        if (pid) {
            AcquireSRWLockExclusive(&g_pt.lock);
            cache_put_locked(src_ip, src_port, pid, FALSE);
            ReleaseSRWLockExclusive(&g_pt.lock);
            return pid;
        }
    } else {
        ReleaseSRWLockShared(&g_pt.lock);
    }

    AcquireSRWLockExclusive(&g_pt.lock);
    cached = cache_get_locked(src_ip, src_port, FALSE);
    if (cached) { ReleaseSRWLockExclusive(&g_pt.lock); return cached; }

    DWORD pid = 0;
    if (refresh_tcp4())
        pid = lookup_tcp4_indexed(src_ip, src_port);
    cache_put_locked(src_ip, src_port, pid, FALSE);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}

DWORD nb_pid_lookup_udp4(UINT32 src_ip, UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();

    AcquireSRWLockShared(&g_pt.lock);
    DWORD cached = cache_get_locked(src_ip, src_port, TRUE);
    if (cached) { ReleaseSRWLockShared(&g_pt.lock); return cached; }
    if (g_pt.udp4 && (GetTickCount64() - g_pt.udp4_ts) < PID_SNAP_TTL_MS) {
        DWORD pid = lookup_udp4_indexed(src_ip, src_port);
        ReleaseSRWLockShared(&g_pt.lock);
        if (pid) {
            AcquireSRWLockExclusive(&g_pt.lock);
            cache_put_locked(src_ip, src_port, pid, TRUE);
            ReleaseSRWLockExclusive(&g_pt.lock);
            return pid;
        }
    } else {
        ReleaseSRWLockShared(&g_pt.lock);
    }

    AcquireSRWLockExclusive(&g_pt.lock);
    cached = cache_get_locked(src_ip, src_port, TRUE);
    if (cached) { ReleaseSRWLockExclusive(&g_pt.lock); return cached; }

    DWORD pid = 0;
    if (refresh_udp4())
        pid = lookup_udp4_indexed(src_ip, src_port);
    cache_put_locked(src_ip, src_port, pid, TRUE);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}

DWORD nb_pid_lookup_tcp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();

    AcquireSRWLockShared(&g_pt.lock);
    if (g_pt.tcp6 && (GetTickCount64() - g_pt.tcp6_ts) < PID_SNAP_TTL_MS) {
        DWORD pid = lookup_tcp6_indexed(src_ip6, src_port);
        ReleaseSRWLockShared(&g_pt.lock);
        if (pid) return pid;
    } else {
        ReleaseSRWLockShared(&g_pt.lock);
    }

    AcquireSRWLockExclusive(&g_pt.lock);
    DWORD pid = 0;
    if (refresh_tcp6())
        pid = lookup_tcp6_indexed(src_ip6, src_port);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}

DWORD nb_pid_lookup_udp6(const UINT8 src_ip6[16], UINT16 src_port)
{
    if (!g_pt.inited) nb_pid_table_init();

    AcquireSRWLockShared(&g_pt.lock);
    if (g_pt.udp6 && (GetTickCount64() - g_pt.udp6_ts) < PID_SNAP_TTL_MS) {
        DWORD pid = lookup_udp6_indexed(src_ip6, src_port);
        ReleaseSRWLockShared(&g_pt.lock);
        if (pid) return pid;
    } else {
        ReleaseSRWLockShared(&g_pt.lock);
    }

    AcquireSRWLockExclusive(&g_pt.lock);
    DWORD pid = 0;
    if (refresh_udp6())
        pid = lookup_udp6_indexed(src_ip6, src_port);
    ReleaseSRWLockExclusive(&g_pt.lock);
    return pid;
}
