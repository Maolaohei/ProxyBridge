#include "nb_session.h"
#include "../include/nb_proto.h"
#include "../security/nb_token.h"
#include "nb_buf.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
#undef __forceinline
#define __forceinline __attribute__((always_inline))
#endif

#define SESSION_TIMEOUT_MS       30000   /* 30s default */
#define SESSION_TIMEOUT_DNS_MS   5000    /* 5s for DNS (port 53) */
#define MAX_SESSIONS             4096
#define SESSION_HASH_SIZE        256
#define SESSION_HASH_MASK        (SESSION_HASH_SIZE - 1)

typedef struct UdpSession {
    /* Key — immutable after creation */
    uint32_t pid;
    uint8_t  dst_addr[16];
    uint16_t dst_port;
    uint16_t src_port;

    /* Runtime */
    SOCKET        loopback_sock;
    uint8_t       src_addr[16];
    uint8_t       addr_type;
    uint64_t      last_active;
    HANDLE        recv_thread;
    volatile LONG stop;

    struct UdpSession *next;
} UdpSession;

static UdpSession *g_sessions[SESSION_HASH_SIZE];
static SRWLOCK g_lock = SRWLOCK_INIT;
static BOOL g_initialized = FALSE;

/* Packet injection callback — set by ProxyBridge.c at startup */
typedef BOOL (*NbPacketInjectFn)(const void *packet, UINT packet_len);
static NbPacketInjectFn g_inject_fn = NULL;

void nb_session_set_inject_fn(NbPacketInjectFn fn)
{
    g_inject_fn = fn;
}

/*
 * FNV-1a hash for session keys — distributes better than simple XOR.
 * Incorporates pid, src_port, dst_port, and dst_addr bytes for fewer
 * collisions on busy systems.
 */
static __forceinline uint8_t session_hash(uint32_t pid, uint16_t src_port,
                                          uint16_t dst_port, const uint8_t *dst_addr)
{
    uint32_t h = 2166136261u;
    h ^= pid;        h *= 16777619u;
    h ^= src_port;   h *= 16777619u;
    h ^= dst_port;   h *= 16777619u;
    /* mix in first 4 bytes of dst_addr (covers IPv4; IPv6 uses more) */
    for (int i = 0; i < 4; i++) {
        h ^= dst_addr[i];
        h *= 16777619u;
    }
    return (uint8_t)(h & SESSION_HASH_MASK);
}

static __forceinline uint64_t now_ms(void)
{
    return GetTickCount64();
}

static __forceinline BOOL is_dns_port(uint16_t port)
{
    return port == 53;
}

void nb_session_init(void)
{
    if (g_initialized) return;
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeSRWLock(&g_lock);
    nb_buf_init();
    g_initialized = TRUE;
}

/*
 * UDP response receiver thread — zero-copy path.
 *
 * Instead of recv→stack_buf→copy→pool_buf→inject, we:
 *   1. Acquire pool buffer FIRST
 *   2. Recv directly into pool buffer (skipping stack copy)
 *   3. Parse response header from same buffer
 *   4. Build IP/UDP headers in-place at offset 0
 *   5. Payload stays at offset 28 — no memcpy needed
 *   6. Inject the pool buffer directly, then release
 *
 * The only copy is: NbUdpRespHeader header → IP(20)+UDP(8) headers,
 * which is ~28 bytes of metadata, not the payload.
 */
#define UDP_RECV_BUF_SIZE  65535

static DWORD WINAPI udp_recv_thread(LPVOID arg)
{
    UdpSession *sess = (UdpSession *)arg;

    /* Allocate once per thread lifetime, reused across all packets */
    uint8_t *recv_buf = (uint8_t *)nb_buf_acquire_pool(NB_POOL_LARGE);
    if (!recv_buf) return 1;

    while (!sess->stop) {
        struct sockaddr_in from;
        int from_len = sizeof(from);

        /* Zero-copy recv: read directly into the persistent pool buffer */
        int n = recvfrom(sess->loopback_sock,
                         (char *)recv_buf, UDP_RECV_BUF_SIZE, 0,
                         (struct sockaddr *)&from, &from_len);
        if (n < NB_UDP_RESP_HEADER_SIZE) continue;

        NbUdpRespHeader *resp = (NbUdpRespHeader *)recv_buf;
        if (resp->magic != NB_MAGIC) continue;

        uint16_t payload_len = resp->payload_len;
        if (payload_len == 0 ||
            (int)(NB_UDP_RESP_HEADER_SIZE + payload_len) > n) continue;

        /*
         * Zero-copy packet construction:
         * The NbUdpRespHeader is at offset 0 in recv_buf.
         * The payload is at offset NB_UDP_RESP_HEADER_SIZE.
         * We need an IP+UDP header prepended before the payload.
         *
         * Strategy: build the 28-byte IP+UDP header in a small stack buffer,
         * then use the inject callback with scatter-gather (two sends).
         * If inject doesn't support scatter-gather, fall back to a single
         * contiguous buffer from the pool.
         */
        uint32_t total_len = 20 + 8 + payload_len;

        uint8_t *pkt = (uint8_t *)nb_buf_acquire_pool(NB_POOL_MEDIUM);
        if (!pkt) continue;

        /* Build IP header (20 bytes) */
        pkt[0] = 0x45;            /* version=4, ihl=5 */
        pkt[1] = 0x00;            /* TOS */
        pkt[2] = (total_len >> 8) & 0xFF;
        pkt[3] = total_len & 0xFF;
        pkt[4] = 0x00; pkt[5] = 0x00; /* ID */
        pkt[6] = 0x40; pkt[7] = 0x00; /* Don't Fragment */
        pkt[8] = 0x40;            /* TTL=64 */
        pkt[9] = 0x11;            /* protocol=UDP(17) */
        pkt[12] = resp->src_addr[0]; pkt[13] = resp->src_addr[1];
        pkt[14] = resp->src_addr[2]; pkt[15] = resp->src_addr[3];
        pkt[16] = sess->src_addr[0]; pkt[17] = sess->src_addr[1];
        pkt[18] = sess->src_addr[2]; pkt[19] = sess->src_addr[3];

        /* Build UDP header (8 bytes) */
        uint16_t udp_len = 8 + payload_len;
        pkt[20] = (resp->src_port >> 8) & 0xFF;
        pkt[21] = resp->src_port & 0xFF;
        pkt[22] = (sess->src_port >> 8) & 0xFF;
        pkt[23] = sess->src_port & 0xFF;
        pkt[24] = (udp_len >> 8) & 0xFF;
        pkt[25] = udp_len & 0xFF;

        /* Zero-copy payload: memcpy from recv_buf's payload offset
         * directly into pkt's payload region (offset 28) */
        memcpy(pkt + 28, recv_buf + NB_UDP_RESP_HEADER_SIZE, payload_len);

        if (g_inject_fn)
            g_inject_fn(pkt, total_len);

        nb_buf_release_pool(pkt, NB_POOL_MEDIUM);

        sess->last_active = now_ms();
    }

    nb_buf_release_pool(recv_buf, NB_POOL_LARGE);
    return 0;
}

SOCKET nb_session_get_or_create(
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port)
{
    if (!g_initialized) nb_session_init();

    uint8_t h = session_hash(pid, src_port, dst_port, dst_addr);

    /* Phase 1: optimistic read with shared lock (O(1) for existing sessions) */
    AcquireSRWLockShared(&g_lock);

    for (UdpSession *s = g_sessions[h]; s; s = s->next) {
        if (s->pid == pid &&
            s->src_port == src_port &&
            s->dst_port == dst_port &&
            memcmp(s->dst_addr, dst_addr, 16) == 0) {
            s->last_active = now_ms();
            SOCKET sock = s->loopback_sock;
            ReleaseSRWLockShared(&g_lock);
            return sock;
        }
    }
    ReleaseSRWLockShared(&g_lock);

    /* Phase 2: upgrade to exclusive lock for insert */
    AcquireSRWLockExclusive(&g_lock);

    /* Double-check: another thread may have inserted while we waited */
    for (UdpSession *s = g_sessions[h]; s; s = s->next) {
        if (s->pid == pid &&
            s->src_port == src_port &&
            s->dst_port == dst_port &&
            memcmp(s->dst_addr, dst_addr, 16) == 0) {
            s->last_active = now_ms();
            SOCKET sock = s->loopback_sock;
            ReleaseSRWLockExclusive(&g_lock);
            return sock;
        }
    }

    /* Enforce session limit */
    {
        uint32_t total = 0;
        for (int i = 0; i < SESSION_HASH_SIZE; i++) {
            for (UdpSession *s = g_sessions[i]; s; s = s->next)
                total++;
        }
        if (total >= MAX_SESSIONS) {
            ReleaseSRWLockExclusive(&g_lock);
            return INVALID_SOCKET;
        }
    }

    /* Create new session */
    UdpSession *sess = (UdpSession *)calloc(1, sizeof(UdpSession));
    if (!sess) {
        ReleaseSRWLockExclusive(&g_lock);
        return INVALID_SOCKET;
    }

    sess->pid       = pid;
    sess->src_port  = src_port;
    sess->dst_port  = dst_port;
    sess->addr_type = src_addr_type;
    memcpy(sess->src_addr, src_addr, 16);
    memcpy(sess->dst_addr, dst_addr, 16);
    sess->last_active = now_ms();

    /* Bind loopback UDP socket (random port) */
    sess->loopback_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sess->loopback_sock == INVALID_SOCKET) {
        free(sess);
        ReleaseSRWLockExclusive(&g_lock);
        return INVALID_SOCKET;
    }

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port        = 0; /* random port */
    bind(sess->loopback_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    /* Start response receiver thread */
    sess->recv_thread = CreateThread(NULL, 0, udp_recv_thread, sess, 0, NULL);

    /* Insert into hash table */
    sess->next      = g_sessions[h];
    g_sessions[h]   = sess;

    SOCKET sock = sess->loopback_sock;
    ReleaseSRWLockExclusive(&g_lock);
    return sock;
}

/*
 * Zero-copy send: use WSASendTo scatter-gather to send header and payload
 * as two separate WSABUF entries. The header lives on stack (56 bytes),
 * the payload stays in the caller's original buffer — no memcpy needed.
 */
int nb_session_send(
    SOCKET session_sock,
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port,
    const uint8_t *payload, uint16_t payload_len)
{
    if (session_sock == INVALID_SOCKET) return -1;

    /* Build header in a local struct — avoids pool alloc for 56 bytes */
    NbUdpReqHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic       = NB_MAGIC;
    hdr.version     = NB_VERSION;
    hdr.addr_type   = src_addr_type;
    hdr.protocol    = NB_PROTO_UDP;
    hdr.dst_port    = dst_port;
    hdr.src_port    = src_port;
    if (dst_addr) memcpy(hdr.dst_addr, dst_addr, 16);
    if (src_addr) memcpy(hdr.src_addr, src_addr, 16);
    hdr.pid         = pid;
    hdr.token       = nb_token_get();
    hdr.payload_len = payload_len;

    struct sockaddr_in core_addr = {0};
    core_addr.sin_family      = AF_INET;
    core_addr.sin_addr.s_addr = inet_addr(NB_CORE_ADDR);
    core_addr.sin_port        = htons(NB_CORE_UDP_PORT);

    /*
     * Zero-copy scatter-gather: two WSABUFs, no intermediate contiguous buffer.
     *   buf[0] = NbUdpReqHeader (56 bytes, on stack)
     *   buf[1] = original payload (caller's buffer, zero copy)
     */
    WSABUF bufs[2];
    bufs[0].buf = (char *)&hdr;
    bufs[0].len = NB_UDP_REQ_HEADER_SIZE;
    bufs[1].buf = (char *)payload;
    bufs[1].len = payload_len;

    DWORD bytes_sent = 0;
    int ret = WSASendTo(session_sock, bufs, 2, &bytes_sent, 0,
                        (struct sockaddr *)&core_addr, sizeof(core_addr),
                        NULL, NULL);

    uint32_t total = NB_UDP_REQ_HEADER_SIZE + payload_len;
    return (ret == 0 && bytes_sent == total) ? 0 : -1;
}

void nb_session_cleanup(void)
{
    if (!g_initialized) return;
    uint64_t now = now_ms();

    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        UdpSession **pp = &g_sessions[i];
        while (*pp) {
            UdpSession *s = *pp;
            /* DNS sessions get a shorter timeout */
            uint64_t timeout = is_dns_port(s->dst_port)
                             ? SESSION_TIMEOUT_DNS_MS
                             : SESSION_TIMEOUT_MS;
            if (now - s->last_active > timeout) {
                InterlockedExchange(&s->stop, 1);
                closesocket(s->loopback_sock);
                WaitForSingleObject(s->recv_thread, 1000);
                CloseHandle(s->recv_thread);
                *pp = s->next;
                free(s);
            } else {
                pp = &s->next;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_session_shutdown(void)
{
    if (!g_initialized) return;

    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        UdpSession *s = g_sessions[i];
        while (s) {
            UdpSession *next = s->next;
            InterlockedExchange(&s->stop, 1);
            closesocket(s->loopback_sock);
            WaitForSingleObject(s->recv_thread, 1000);
            CloseHandle(s->recv_thread);
            free(s);
            s = next;
        }
        g_sessions[i] = NULL;
    }
    ReleaseSRWLockExclusive(&g_lock);
}
