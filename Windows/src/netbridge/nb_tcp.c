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

/* ===== IOCP Relay ===== */

#define IOCP_BUF_SIZE  65536
#define IOCP_WORKERS   4
#define IOCP_MAX_CONNS 1024

/* IOCP operation types */
#define IOCP_OP_RECV_ORIG  1
#define IOCP_OP_SEND_CORE  2
#define IOCP_OP_RECV_CORE  3
#define IOCP_OP_SEND_ORIG  4

typedef struct _IOCP_CONN {
    OVERLAPPED ov_orig_recv;
    OVERLAPPED ov_orig_send;
    OVERLAPPED ov_core_recv;
    OVERLAPPED ov_core_send;
    WSABUF buf_orig_recv;
    WSABUF buf_orig_send;
    WSABUF buf_core_recv;
    WSABUF buf_core_send;
    char data_orig_recv[IOCP_BUF_SIZE];
    char data_orig_send[IOCP_BUF_SIZE];
    char data_core_recv[IOCP_BUF_SIZE];
    char data_core_send[IOCP_BUF_SIZE];
    SOCKET orig_sock;
    SOCKET core_sock;
    volatile LONG active;     /* 1 = active, 0 = closing */
    volatile LONG refcount;   /* prevent double-free */
} IOCP_CONN;

static HANDLE g_iocp = NULL;
static volatile LONG g_active_conns = 0;

static IOCP_CONN* iocp_conn_alloc(void)
{
    IOCP_CONN *c = (IOCP_CONN *)calloc(1, sizeof(IOCP_CONN));
    if (!c) return NULL;
    c->orig_sock = INVALID_SOCKET;
    c->core_sock = INVALID_SOCKET;
    c->active = 1;
    InterlockedExchange(&c->refcount, 2); /* 2 sockets */

    c->buf_orig_recv.buf = c->data_orig_recv;
    c->buf_orig_recv.len = IOCP_BUF_SIZE;
    c->buf_orig_send.buf = c->data_orig_send;
    c->buf_orig_send.len = IOCP_BUF_SIZE;
    c->buf_core_recv.buf = c->data_core_recv;
    c->buf_core_recv.len = IOCP_BUF_SIZE;
    c->buf_core_send.buf = c->data_core_send;
    c->buf_core_send.len = IOCP_BUF_SIZE;

    InterlockedIncrement(&g_active_conns);
    return c;
}

static void iocp_conn_release(IOCP_CONN *c)
{
    if (!c) return;
    if (InterlockedDecrement(&c->refcount) == 0) {
        if (c->orig_sock != INVALID_SOCKET) closesocket(c->orig_sock);
        if (c->core_sock != INVALID_SOCKET) closesocket(c->core_sock);
        InterlockedDecrement(&g_active_conns);
        free(c);
    }
}

/* Post async recv */
static BOOL iocp_post_recv(SOCKET sock, OVERLAPPED *ov, WSABUF *buf)
{
    memset(ov, 0, sizeof(OVERLAPPED));
    DWORD flags = 0;
    DWORD bytesRecvd = 0;
    int rc = WSARecv(sock, buf, 1, &bytesRecvd, &flags, ov, NULL);
    return (rc == 0 || WSAGetLastError() == WSA_IO_PENDING);
}

/* Post async send */
static BOOL iocp_post_send(SOCKET sock, OVERLAPPED *ov, WSABUF *buf)
{
    memset(ov, 0, sizeof(OVERLAPPED));
    DWORD bytesSent = 0;
    int rc = WSASend(sock, buf, 1, &bytesSent, 0, ov, NULL);
    return (rc == 0 || WSAGetLastError() == WSA_IO_PENDING);
}

/* Worker thread — processes IOCP completions */
static DWORD WINAPI iocp_worker(LPVOID arg)
{
    (void)arg;
    DWORD bytes;
    ULONG_PTR key;
    OVERLAPPED *ov;

    while (GetQueuedCompletionStatus(g_iocp, &bytes, &key, &ov, INFINITE))
    {
        if (!ov) continue; /* Shutdown signal */

        IOCP_CONN *conn = (IOCP_CONN *)key;
        if (!conn->active || bytes == 0) {
            iocp_conn_release(conn);
            continue;
        }

        /* Determine which operation completed by comparing ov pointer */
        if (ov == &conn->ov_orig_recv) {
            /* Recv from orig → send to core */
            conn->buf_core_send.buf = conn->data_orig_recv;
            conn->buf_core_send.len = bytes;
            if (!iocp_post_send(conn->core_sock, &conn->ov_core_send, &conn->buf_core_send)) {
                conn->active = 0;
                iocp_conn_release(conn);
            }
        }
        else if (ov == &conn->ov_core_send) {
            /* Send to core done → recv more from orig */
            conn->buf_orig_recv.buf = conn->data_orig_recv;
            conn->buf_orig_recv.len = IOCP_BUF_SIZE;
            if (!iocp_post_recv(conn->orig_sock, &conn->ov_orig_recv, &conn->buf_orig_recv)) {
                conn->active = 0;
                iocp_conn_release(conn);
            }
        }
        else if (ov == &conn->ov_core_recv) {
            /* Recv from core → send to orig */
            conn->buf_orig_send.buf = conn->data_core_recv;
            conn->buf_orig_send.len = bytes;
            if (!iocp_post_send(conn->orig_sock, &conn->ov_orig_send, &conn->buf_orig_send)) {
                conn->active = 0;
                iocp_conn_release(conn);
            }
        }
        else if (ov == &conn->ov_orig_send) {
            /* Send to orig done → recv more from core */
            conn->buf_core_recv.buf = conn->data_core_recv;
            conn->buf_core_recv.len = IOCP_BUF_SIZE;
            if (!iocp_post_recv(conn->core_sock, &conn->ov_core_recv, &conn->buf_core_recv)) {
                conn->active = 0;
                iocp_conn_release(conn);
            }
        }
    }
    return 0;
}

/* Initialize IOCP subsystem — call once */
static void nb_iocp_init(void)
{
    if (g_iocp) return;

    g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, IOCP_WORKERS);
    if (!g_iocp) return;

    for (int i = 0; i < IOCP_WORKERS; i++) {
        CreateThread(NULL, 0, iocp_worker, NULL, 0, NULL);
    }
}

/* Start IOCP relay for a connection pair */
static int nb_iocp_relay(SOCKET orig_sock, SOCKET core_sock)
{
    if (!g_iocp) nb_iocp_init();
    if (!g_iocp) return -1;

    IOCP_CONN *conn = iocp_conn_alloc();
    if (!conn) return -1;

    conn->orig_sock = orig_sock;
    conn->core_sock = core_sock;

    /* Associate both sockets with IOCP */
    CreateIoCompletionPort((HANDLE)orig_sock, g_iocp, (ULONG_PTR)conn, 0);
    CreateIoCompletionPort((HANDLE)core_sock, g_iocp, (ULONG_PTR)conn, 0);

    /* Post initial recv from orig */
    if (!iocp_post_recv(orig_sock, &conn->ov_orig_recv, &conn->buf_orig_recv)) {
        conn->active = 0;
        iocp_conn_release(conn);
        return -1;
    }

    /* Post initial recv from core */
    if (!iocp_post_recv(core_sock, &conn->ov_core_recv, &conn->buf_core_recv)) {
        conn->active = 0;
        iocp_conn_release(conn);
        return -1;
    }

    return 0;
}

/* ===== Legacy relay (fallback) ===== */

typedef struct {
    SOCKET from;
    SOCKET to;
} RelayArg;

/* ===== Legacy relay (removed — using IOCP) ===== */

int nb_tcp_forward(
    SOCKET orig_sock,
    const uint8_t *dst_addr, uint8_t addr_type,
    uint16_t dst_port, uint16_t src_port,
    uint32_t pid, const char *proc_name)
{
    if (!g_pool_initialized) nb_tcp_pool_init();
    if (!g_iocp) nb_iocp_init();

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

    /* Build NetBridge Header */
    uint8_t hdr_buf[128];
    uint32_t hdr_len = nb_tcp_header_serialize(
        hdr_buf, sizeof(hdr_buf),
        addr_type, dst_port, src_port,
        dst_addr, pid, nb_token_get(),
        proc_name, proc_name_len);

    if (hdr_len == 0) {
        closesocket(core_sock);
        return -1;
    }

    /* Read first data from orig_sock to enable scatter-gather send */
    char *first_buf = (char *)nb_buf_acquire_pool(NB_POOL_LARGE);
    if (!first_buf) {
        send(core_sock, (const char *)hdr_buf, (int)hdr_len, 0);
        closesocket(core_sock);
        closesocket(orig_sock);
        return -1;
    }

    /* Set non-blocking on orig_sock briefly to peek first data */
    u_long mode = 1;
    ioctlsocket(orig_sock, FIONBIO, &mode);
    int first_len = recv(orig_sock, first_buf, NB_BUF_LARGE, MSG_PEEK);
    mode = 0;
    ioctlsocket(orig_sock, FIONBIO, &mode);

    if (first_len <= 0) {
        /* No data yet — send header only, relay will handle the rest */
        nb_buf_release_pool(first_buf, NB_POOL_LARGE);
        if (send(core_sock, (const char *)hdr_buf, (int)hdr_len, 0) != (int)hdr_len) {
            closesocket(core_sock);
            closesocket(orig_sock);
            return -1;
        }
    } else {
        /* Scatter-gather: header + first data in one syscall */
        WSABUF bufs[2];
        bufs[0].buf = (char *)hdr_buf;
        bufs[0].len = hdr_len;
        bufs[1].buf = first_buf;
        bufs[1].len = first_len;

        DWORD bytesSent = 0;
        WSASend(core_sock, bufs, 2, &bytesSent, 0, NULL, NULL);

        /* Actually consume the peeked data */
        recv(orig_sock, first_buf, first_len, 0);
        nb_buf_release_pool(first_buf, NB_POOL_LARGE);

        if (bytesSent != hdr_len + (DWORD)first_len) {
            closesocket(core_sock);
            closesocket(orig_sock);
            return -1;
        }
    }

    /* Start IOCP relay — zero threads per connection */
    if (nb_iocp_relay(orig_sock, core_sock) != 0) {
        closesocket(core_sock);
        closesocket(orig_sock);
        return -1;
    }

    return 0;
}
