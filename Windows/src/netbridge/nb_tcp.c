#include "nb_tcp.h"
#include "../include/nb_proto.h"
#include "../security/nb_token.h"
#include "../process/nb_procname.h"
#include "nb_buf.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PROC_NAME 1024

/* ===== Connection Pool ===== */

#define POOL_SIZE         16
#define POOL_IDLE_TIMEOUT 30000   /* 30s */
#define RELAY_BUF_SIZE    131072  /* 128 KB — fewer syscalls per relay */
#define RELAY_TIMEOUT_MS  30000   /* 30s per-direction timeout */

/* TCP socket buffer size: 256 KB for high throughput */
#define SOCK_SNDBUF_SIZE  (256 * 1024)
#define SOCK_RCVBUF_SIZE  (256 * 1024)

/* Relay port — defaults to NB_CORE_TCP_PORT (CoreDirect).
 * Change via nb_tcp_set_relay_port() for Bridge mode. */
static uint16_t g_relay_port = NB_CORE_TCP_PORT;

/*
 * Per-slot lock design:
 * Each pool slot has its own SRWLOCK, so acquire/release only
 * locks the specific slot — no global contention.
 * The global g_pool_lock is ONLY used for cleanup/shutdown.
 */
typedef struct {
    SOCKET      sock;
    volatile LONG in_use;
    uint64_t    last_active;
    SRWLOCK     lock;       /* per-slot lock */
} PooledConn;

static PooledConn g_pool[POOL_SIZE];
static SRWLOCK g_pool_lock = SRWLOCK_INIT;  /* only for shutdown/cleanup */
static BOOL g_pool_initialized = FALSE;

/* Forward declarations */
static SOCKET nb_pool_create_conn(void);
static DWORD WINAPI nb_pool_warmup_thread(LPVOID arg);

void nb_tcp_pool_init(void)
{
    if (g_pool_initialized) return;
    for (int i = 0; i < POOL_SIZE; i++) {
        g_pool[i].sock = INVALID_SOCKET;
        g_pool[i].in_use = 0;
        g_pool[i].last_active = 0;
        InitializeSRWLock(&g_pool[i].lock);
    }
    g_pool_initialized = TRUE;

    /* Pre-warm in background thread — don't block startup */
    CreateThread(NULL, 0, nb_pool_warmup_thread, NULL, 0, NULL);
}

static DWORD WINAPI nb_pool_warmup_thread(LPVOID arg)
{
    (void)arg;
    /* Wait a moment for the listener to be ready */
    Sleep(100);

    int warmup = POOL_SIZE / 2;
    for (int i = 0; i < warmup; i++) {
        /* Only fill empty slots */
        AcquireSRWLockExclusive(&g_pool[i].lock);
        if (g_pool[i].sock == INVALID_SOCKET) {
            SOCKET s = nb_pool_create_conn();
            if (s != INVALID_SOCKET) {
                g_pool[i].sock = s;
                g_pool[i].last_active = GetTickCount64();
            }
        }
        ReleaseSRWLockExclusive(&g_pool[i].lock);
    }
    return 0;
}

void nb_tcp_set_relay_port(uint16_t port)
{
    g_relay_port = port;
    nb_tcp_pool_shutdown();
    nb_tcp_pool_init();
}

/* Create a new TCP connection to the relay */
static SOCKET nb_pool_create_conn(void)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    /* Optimize for throughput and low latency */
    int nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    int sndbuf = SOCK_SNDBUF_SIZE;
    int rcvbuf = SOCK_RCVBUF_SIZE;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&sndbuf, sizeof(sndbuf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&rcvbuf, sizeof(rcvbuf));

    /* Keepalive to detect dead connections */
    struct tcp_keepalive ka = {0};
    ka.onoff = 1;
    ka.keepalivetime = 10000;     /* 10s first probe */
    ka.keepaliveinterval = 3000;  /* 3s interval */
    DWORD bytesReturned = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytesReturned, NULL, NULL);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(NB_CORE_ADDR);
    sa.sin_port        = htons(g_relay_port);

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* Check if a pooled connection is still alive (non-blocking peek) */
static BOOL nb_pool_is_alive(SOCKET s)
{
    if (s == INVALID_SOCKET) return FALSE;

    /* Set non-blocking temporarily */
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);

    char buf[1];
    int ret = recv(s, buf, 1, MSG_PEEK);

    /* Restore blocking */
    mode = 0;
    ioctlsocket(s, FIONBIO, &mode);

    if (ret == 0) return FALSE;  /* connection closed */
    if (ret == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return TRUE;  /* no data yet = alive */
        return FALSE;
    }
    return TRUE;  /* data available = alive */
}

static SOCKET nb_pool_acquire(void)
{
    if (!g_pool_initialized) nb_tcp_pool_init();

    /* Phase 1: try each slot with per-slot lock (no global contention) */
    for (int i = 0; i < POOL_SIZE; i++) {
        AcquireSRWLockExclusive(&g_pool[i].lock);

        if (g_pool[i].sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_pool[i].in_use, 1, 0) == 0) {
            /* Verify connection is alive */
            if (nb_pool_is_alive(g_pool[i].sock)) {
                g_pool[i].last_active = GetTickCount64();
                ReleaseSRWLockExclusive(&g_pool[i].lock);
                return g_pool[i].sock;
            }
            /* Dead connection — discard and create new */
            closesocket(g_pool[i].sock);
            SOCKET s = nb_pool_create_conn();
            if (s != INVALID_SOCKET) {
                g_pool[i].sock = s;
                g_pool[i].last_active = GetTickCount64();
                ReleaseSRWLockExclusive(&g_pool[i].lock);
                return s;
            }
            g_pool[i].sock = INVALID_SOCKET;
            InterlockedExchange(&g_pool[i].in_use, 0);
            ReleaseSRWLockExclusive(&g_pool[i].lock);
            return INVALID_SOCKET;
        }

        /* Empty slot — create new connection */
        if (g_pool[i].sock == INVALID_SOCKET) {
            SOCKET s = nb_pool_create_conn();
            if (s != INVALID_SOCKET) {
                g_pool[i].sock = s;
                g_pool[i].in_use = 1;
                g_pool[i].last_active = GetTickCount64();
                ReleaseSRWLockExclusive(&g_pool[i].lock);
                return s;
            }
            ReleaseSRWLockExclusive(&g_pool[i].lock);
            return INVALID_SOCKET;
        }

        ReleaseSRWLockExclusive(&g_pool[i].lock);
    }

    /* Phase 2: pool exhausted — create a temporary connection */
    return nb_pool_create_conn();
}

void nb_tcp_pool_cleanup(void)
{
    if (!g_pool_initialized) return;
    uint64_t now = GetTickCount64();

    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < POOL_SIZE; i++) {
        AcquireSRWLockExclusive(&g_pool[i].lock);
        if (g_pool[i].sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_pool[i].in_use, 0, 0) == 0 &&
            now - g_pool[i].last_active > POOL_IDLE_TIMEOUT) {
            closesocket(g_pool[i].sock);
            g_pool[i].sock = INVALID_SOCKET;
        }
        ReleaseSRWLockExclusive(&g_pool[i].lock);
    }
    ReleaseSRWLockExclusive(&g_pool_lock);
}

void nb_tcp_pool_shutdown(void)
{
    if (!g_pool_initialized) return;
    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < POOL_SIZE; i++) {
        AcquireSRWLockExclusive(&g_pool[i].lock);
        if (g_pool[i].sock != INVALID_SOCKET) {
            closesocket(g_pool[i].sock);
            g_pool[i].sock = INVALID_SOCKET;
        }
        InterlockedExchange(&g_pool[i].in_use, 0);
        ReleaseSRWLockExclusive(&g_pool[i].lock);
    }
    ReleaseSRWLockExclusive(&g_pool_lock);
}

/* ===== Relay ===== */

typedef struct {
    SOCKET from;
    SOCKET to;
} RelayArg;

static DWORD WINAPI relay_thread(LPVOID arg)
{
    RelayArg *r = (RelayArg *)arg;

    char *buf = (char *)nb_buf_acquire_pool(NB_POOL_LARGE);
    if (!buf) {
        closesocket(r->from);
        closesocket(r->to);
        free(r);
        return 0;
    }

    DWORD timeout = RELAY_TIMEOUT_MS;
    setsockopt(r->from, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(r->to,   SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    int n;
    while ((n = recv(r->from, buf, NB_BUF_LARGE, 0)) > 0) {
        int sent = 0;
        while (sent < n) {
            int w = send(r->to, buf + sent, n - sent, 0);
            if (w <= 0) goto done;
            sent += w;
        }
    }
done:
    nb_buf_release_pool(buf, NB_POOL_LARGE);
    shutdown(r->from, SD_BOTH);
    shutdown(r->to,   SD_BOTH);
    closesocket(r->from);
    closesocket(r->to);
    free(r);
    return 0;
}

/* ===== Public API ===== */

int nb_tcp_forward(
    SOCKET orig_sock,
    const uint8_t *dst_addr, uint8_t addr_type,
    uint16_t dst_port, uint16_t src_port,
    uint32_t pid, const char *proc_name)
{
    if (!g_pool_initialized) nb_tcp_pool_init();

    /* Get process name if not provided */
    char proc_name_buf[MAX_PROC_NAME] = "";
    if (!proc_name || proc_name[0] == '\0') {
        const char *resolved = nb_procname_get(pid);
        if (resolved) {
            strncpy(proc_name_buf, resolved, MAX_PROC_NAME - 1);
            proc_name_buf[MAX_PROC_NAME - 1] = '\0';
        }
        proc_name = proc_name_buf;
    }
    uint8_t proc_name_len = (uint8_t)strlen(proc_name);
    if (proc_name_len > NB_PROC_NAME_MAX) proc_name_len = NB_PROC_NAME_MAX;

    /* Get connection from pool */
    SOCKET core_sock = nb_pool_acquire();
    if (core_sock == INVALID_SOCKET) return -1;

    /* Build and send NetBridge Header */
    uint8_t hdr_buf[128];
    uint32_t hdr_len = nb_tcp_header_serialize(
        hdr_buf, sizeof(hdr_buf),
        addr_type, dst_port, src_port,
        dst_addr, pid, nb_token_get(),
        proc_name, proc_name_len);

    if (hdr_len == 0 ||
        send(core_sock, (const char *)hdr_buf, (int)hdr_len, 0) != (int)hdr_len) {
        closesocket(core_sock);
        return -1;
    }

    /* Spawn bidirectional relay threads */
    RelayArg *r1 = (RelayArg *)malloc(sizeof(RelayArg));
    RelayArg *r2 = (RelayArg *)malloc(sizeof(RelayArg));
    if (!r1 || !r2) {
        free(r1); free(r2);
        closesocket(core_sock);
        closesocket(orig_sock);
        return -1;
    }
    r1->from = orig_sock; r1->to = core_sock;
    r2->from = core_sock; r2->to = orig_sock;

    HANDLE t1 = CreateThread(NULL, 0, relay_thread, r1, 0, NULL);
    HANDLE t2 = CreateThread(NULL, 0, relay_thread, r2, 0, NULL);
    if (t1) CloseHandle(t1);
    if (t2) CloseHandle(t2);

    return 0;
}
