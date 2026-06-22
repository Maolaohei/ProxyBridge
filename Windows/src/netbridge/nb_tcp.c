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

#define POOL_SIZE         8
#define POOL_IDLE_TIMEOUT 30000   /* 30s */
#define RELAY_BUF_SIZE    131072  /* 128 KB — fewer syscalls per relay */
#define RELAY_TIMEOUT_MS  30000   /* 30s per-direction timeout */

typedef struct {
    SOCKET      sock;
    volatile LONG in_use;
    uint64_t    last_active;
    SRWLOCK     lock;
} PooledConn;

static PooledConn g_pool[POOL_SIZE];
static SRWLOCK g_pool_lock = SRWLOCK_INIT;
static BOOL g_pool_initialized = FALSE;

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
}

static SOCKET nb_pool_acquire(void)
{
    AcquireSRWLockExclusive(&g_pool_lock);

    /* Try to find an idle connection */
    for (int i = 0; i < POOL_SIZE; i++) {
        if (InterlockedCompareExchange(&g_pool[i].in_use, 1, 0) == 0) {
            if (g_pool[i].sock != INVALID_SOCKET) {
                ReleaseSRWLockExclusive(&g_pool_lock);
                return g_pool[i].sock;
            }
            /* Found empty slot — create new connection and store it */
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
                struct sockaddr_in sa = {0};
                sa.sin_family      = AF_INET;
                sa.sin_addr.s_addr = inet_addr(NB_CORE_ADDR);
                sa.sin_port        = htons(NB_CORE_TCP_PORT);

                if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
                    g_pool[i].sock = s;
                    g_pool[i].last_active = GetTickCount64();
                    ReleaseSRWLockExclusive(&g_pool_lock);
                    return s;
                }
                closesocket(s);
            }
            InterlockedExchange(&g_pool[i].in_use, 0);
            ReleaseSRWLockExclusive(&g_pool_lock);
            return INVALID_SOCKET;
        }
    }

    ReleaseSRWLockExclusive(&g_pool_lock);

    /* Pool full — create a temporary connection (not pooled) */
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(NB_CORE_ADDR);
    sa.sin_port        = htons(NB_CORE_TCP_PORT);

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

static void nb_pool_release(SOCKET s)
{
    if (s == INVALID_SOCKET) return;

    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_pool[i].sock == s) {
            g_pool[i].last_active = GetTickCount64();
            InterlockedExchange(&g_pool[i].in_use, 0);
            ReleaseSRWLockExclusive(&g_pool_lock);
            return;
        }
    }
    ReleaseSRWLockExclusive(&g_pool_lock);

    /* Not in pool — close directly */
    closesocket(s);
}

void nb_tcp_pool_cleanup(void)
{
    if (!g_pool_initialized) return;
    uint64_t now = GetTickCount64();
    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_pool[i].sock != INVALID_SOCKET &&
            InterlockedCompareExchange(&g_pool[i].in_use, 0, 0) == 0 &&
            now - g_pool[i].last_active > POOL_IDLE_TIMEOUT) {
            closesocket(g_pool[i].sock);
            g_pool[i].sock = INVALID_SOCKET;
        }
    }
    ReleaseSRWLockExclusive(&g_pool_lock);
}

void nb_tcp_pool_shutdown(void)
{
    if (!g_pool_initialized) return;
    AcquireSRWLockExclusive(&g_pool_lock);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_pool[i].sock != INVALID_SOCKET) {
            closesocket(g_pool[i].sock);
            g_pool[i].sock = INVALID_SOCKET;
        }
        InterlockedExchange(&g_pool[i].in_use, 0);
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

    /* 128 KB buffer from pool — fewer recv/send syscalls */
    char *buf = (char *)nb_buf_acquire_pool(NB_POOL_LARGE);
    if (!buf) {
        closesocket(r->from);
        closesocket(r->to);
        free(r);
        return 0;
    }

    /* Set timeouts to prevent permanent blocking */
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
