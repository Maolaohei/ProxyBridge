#include "netbridge/nb_iocp_relay.h"

#include <mswsock.h>
#include <stdlib.h>
#include <string.h>

#define IOCP_BUF_SIZE  65536
#define IOCP_WORKERS   8

#define IOCP_OP_RECV_A  1
#define IOCP_OP_SEND_B  2
#define IOCP_OP_RECV_B  3
#define IOCP_OP_SEND_A  4

typedef struct _NB_IOCP_CONN {
    OVERLAPPED ov_a_recv;
    OVERLAPPED ov_a_send;
    OVERLAPPED ov_b_recv;
    OVERLAPPED ov_b_send;
    WSABUF buf_a_recv;
    WSABUF buf_a_send;
    WSABUF buf_b_recv;
    WSABUF buf_b_send;
    char data_a_recv[IOCP_BUF_SIZE];
    char data_a_send[IOCP_BUF_SIZE];
    char data_b_recv[IOCP_BUF_SIZE];
    char data_b_send[IOCP_BUF_SIZE];
    SOCKET sock_a;
    SOCKET sock_b;
    volatile LONG active;
    volatile LONG refcount;
} NB_IOCP_CONN;

static HANDLE g_iocp = NULL;
static HANDLE g_workers[IOCP_WORKERS];
static volatile LONG g_inited = 0;
static volatile LONG g_active_conns = 0;

static NB_IOCP_CONN *conn_alloc(void)
{
    NB_IOCP_CONN *c = (NB_IOCP_CONN *)calloc(1, sizeof(NB_IOCP_CONN));
    if (!c) return NULL;
    c->sock_a = INVALID_SOCKET;
    c->sock_b = INVALID_SOCKET;
    c->active = 1;
    InterlockedExchange(&c->refcount, 2);
    c->buf_a_recv.buf = c->data_a_recv; c->buf_a_recv.len = IOCP_BUF_SIZE;
    c->buf_a_send.buf = c->data_a_send; c->buf_a_send.len = IOCP_BUF_SIZE;
    c->buf_b_recv.buf = c->data_b_recv; c->buf_b_recv.len = IOCP_BUF_SIZE;
    c->buf_b_send.buf = c->data_b_send; c->buf_b_send.len = IOCP_BUF_SIZE;
    InterlockedIncrement(&g_active_conns);
    return c;
}

static void conn_release(NB_IOCP_CONN *c)
{
    if (!c) return;
    if (InterlockedDecrement(&c->refcount) == 0) {
        if (c->sock_a != INVALID_SOCKET) closesocket(c->sock_a);
        if (c->sock_b != INVALID_SOCKET) closesocket(c->sock_b);
        InterlockedDecrement(&g_active_conns);
        free(c);
    }
}

static BOOL post_recv(SOCKET sock, OVERLAPPED *ov, WSABUF *buf)
{
    memset(ov, 0, sizeof(*ov));
    DWORD flags = 0, n = 0;
    int rc = WSARecv(sock, buf, 1, &n, &flags, ov, NULL);
    return (rc == 0 || WSAGetLastError() == WSA_IO_PENDING);
}

static BOOL post_send(SOCKET sock, OVERLAPPED *ov, WSABUF *buf)
{
    memset(ov, 0, sizeof(*ov));
    DWORD n = 0;
    int rc = WSASend(sock, buf, 1, &n, 0, ov, NULL);
    return (rc == 0 || WSAGetLastError() == WSA_IO_PENDING);
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    (void)arg;
    for (;;) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED *ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(g_iocp, &bytes, &key, &ov, INFINITE);
        if (!ov) {
            /* shutdown packet */
            if (!ok) break;
            continue;
        }
        NB_IOCP_CONN *conn = (NB_IOCP_CONN *)key;
        if (!ok || !conn->active || bytes == 0) {
            InterlockedExchange(&conn->active, 0);
            shutdown(conn->sock_a, SD_BOTH);
            shutdown(conn->sock_b, SD_BOTH);
            conn_release(conn);
            continue;
        }

        if (ov == &conn->ov_a_recv) {
            conn->buf_b_send.buf = conn->data_a_recv;
            conn->buf_b_send.len = bytes;
            if (!post_send(conn->sock_b, &conn->ov_b_send, &conn->buf_b_send)) {
                InterlockedExchange(&conn->active, 0);
                conn_release(conn);
            }
        } else if (ov == &conn->ov_b_send) {
            conn->buf_a_recv.buf = conn->data_a_recv;
            conn->buf_a_recv.len = IOCP_BUF_SIZE;
            if (!post_recv(conn->sock_a, &conn->ov_a_recv, &conn->buf_a_recv)) {
                InterlockedExchange(&conn->active, 0);
                conn_release(conn);
            }
        } else if (ov == &conn->ov_b_recv) {
            conn->buf_a_send.buf = conn->data_b_recv;
            conn->buf_a_send.len = bytes;
            if (!post_send(conn->sock_a, &conn->ov_a_send, &conn->buf_a_send)) {
                InterlockedExchange(&conn->active, 0);
                conn_release(conn);
            }
        } else if (ov == &conn->ov_a_send) {
            conn->buf_b_recv.buf = conn->data_b_recv;
            conn->buf_b_recv.len = IOCP_BUF_SIZE;
            if (!post_recv(conn->sock_b, &conn->ov_b_recv, &conn->buf_b_recv)) {
                InterlockedExchange(&conn->active, 0);
                conn_release(conn);
            }
        }
    }
    return 0;
}

void nb_iocp_relay_init(void)
{
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0)
        return;
    ZeroMemory(g_workers, sizeof(g_workers));
    g_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, IOCP_WORKERS);
    if (!g_iocp) {
        InterlockedExchange(&g_inited, 0);
        return;
    }
    for (int i = 0; i < IOCP_WORKERS; i++) {
        g_workers[i] = CreateThread(NULL, 0, worker_main, NULL, 0, NULL);
    }
}

void nb_iocp_relay_shutdown(void)
{
    if (!g_iocp) return;
    for (int i = 0; i < IOCP_WORKERS; i++)
        PostQueuedCompletionStatus(g_iocp, 0, 0, NULL);
    for (int i = 0; i < IOCP_WORKERS; i++) {
        if (g_workers[i]) {
            WaitForSingleObject(g_workers[i], 2000);
            CloseHandle(g_workers[i]);
            g_workers[i] = NULL;
        }
    }
    CloseHandle(g_iocp);
    g_iocp = NULL;
    InterlockedExchange(&g_inited, 0);
}

int nb_iocp_relay_start(SOCKET a, SOCKET b)
{
    if (!g_iocp) nb_iocp_relay_init();
    if (!g_iocp) return -1;

    /* Ensure non-blocking for overlapped IO */
    u_long nb = 1;
    ioctlsocket(a, FIONBIO, &nb);
    ioctlsocket(b, FIONBIO, &nb);

    NB_IOCP_CONN *conn = conn_alloc();
    if (!conn) return -1;
    conn->sock_a = a;
    conn->sock_b = b;

    if (!CreateIoCompletionPort((HANDLE)a, g_iocp, (ULONG_PTR)conn, 0) ||
        !CreateIoCompletionPort((HANDLE)b, g_iocp, (ULONG_PTR)conn, 0)) {
        conn->sock_a = INVALID_SOCKET;
        conn->sock_b = INVALID_SOCKET;
        conn_release(conn);
        conn_release(conn);
        return -1;
    }

    if (!post_recv(a, &conn->ov_a_recv, &conn->buf_a_recv)) {
        conn->sock_a = INVALID_SOCKET;
        conn->sock_b = INVALID_SOCKET;
        InterlockedExchange(&conn->active, 0);
        conn_release(conn);
        conn_release(conn);
        return -1;
    }
    if (!post_recv(b, &conn->ov_b_recv, &conn->buf_b_recv)) {
        /* A recv is outstanding under IOCP; transfer ownership and let worker tear down. */
        InterlockedExchange(&conn->active, 0);
        shutdown(a, SD_BOTH);
        shutdown(b, SD_BOTH);
        conn_release(conn); /* one direction ended; worker releases the other */
        return 0; /* ownership transferred; do not let caller close */
    }
    return 0;
}
