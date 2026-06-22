#include "nb_session.h"
#include "../include/nb_proto.h"
#include "../security/nb_token.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SESSION_TIMEOUT_MS  30000   /* 30s */
#define MAX_SESSIONS        4096
#define SESSION_HASH_SIZE   256

typedef struct UdpSession {
    /* Key */
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

static uint8_t session_hash(uint16_t src_port, uint16_t dst_port) {
    return (uint8_t)((src_port ^ dst_port) & (SESSION_HASH_SIZE - 1));
}

void nb_session_init(void)
{
    if (g_initialized) return;
    memset(g_sessions, 0, sizeof(g_sessions));
    InitializeSRWLock(&g_lock);
    g_initialized = TRUE;
}

/* UDP response receiver thread */
static DWORD WINAPI udp_recv_thread(LPVOID arg)
{
    UdpSession *sess = (UdpSession *)arg;
    uint8_t buf[65535];
    struct sockaddr_in from;
    int from_len = sizeof(from);

    while (!sess->stop) {
        int n = recvfrom(sess->loopback_sock,
                         (char *)buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &from_len);
        if (n < NB_UDP_RESP_HEADER_SIZE) continue;

        NbUdpRespHeader *resp = (NbUdpRespHeader *)buf;
        if (resp->magic != NB_MAGIC) continue;

        uint8_t *payload = buf + NB_UDP_RESP_HEADER_SIZE;
        uint16_t payload_len = resp->payload_len;

        if (payload_len == 0 ||
            (int)(NB_UDP_RESP_HEADER_SIZE + payload_len) > n) continue;

        /* Build raw IP/UDP packet for WinDivert injection */
        uint32_t total_len = 20 + 8 + payload_len; /* IP(20) + UDP(8) + payload */
        uint8_t *pkt = (uint8_t *)calloc(1, total_len);
        if (!pkt) continue;

        /* IP header */
        pkt[0] = 0x45;            /* version=4, ihl=5 */
        pkt[1] = 0x00;            /* TOS */
        pkt[2] = (total_len >> 8) & 0xFF;
        pkt[3] = total_len & 0xFF;
        pkt[4] = 0x00; pkt[5] = 0x00; /* ID */
        pkt[6] = 0x40; pkt[7] = 0x00; /* Don't Fragment */
        pkt[8] = 0x40;            /* TTL=64 */
        pkt[9] = 0x11;            /* protocol=UDP(17) */
        /* checksum=0 (WinDivert will calculate) */
        pkt[12] = resp->src_addr[0]; pkt[13] = resp->src_addr[1];
        pkt[14] = resp->src_addr[2]; pkt[15] = resp->src_addr[3];
        pkt[16] = sess->src_addr[0]; pkt[17] = sess->src_addr[1];
        pkt[18] = sess->src_addr[2]; pkt[19] = sess->src_addr[3];

        /* UDP header */
        uint16_t udp_len = 8 + payload_len;
        pkt[20] = (resp->src_port >> 8) & 0xFF;
        pkt[21] = resp->src_port & 0xFF;
        pkt[22] = (sess->src_port >> 8) & 0xFF;
        pkt[23] = sess->src_port & 0xFF;
        pkt[24] = (udp_len >> 8) & 0xFF;
        pkt[25] = udp_len & 0xFF;
        /* UDP checksum=0 (optional for IPv4) */

        /* Payload */
        memcpy(pkt + 28, payload, payload_len);

        /* Inject via callback */
        if (g_inject_fn)
            g_inject_fn(pkt, total_len);
        free(pkt);

        sess->last_active = GetTickCount64();
    }
    return 0;
}

SOCKET nb_session_get_or_create(
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port)
{
    if (!g_initialized) nb_session_init();

    uint8_t h = session_hash(src_port, dst_port);

    AcquireSRWLockExclusive(&g_lock);

    /* Find existing session */
    for (UdpSession *s = g_sessions[h]; s; s = s->next) {
        if (s->pid      == pid      &&
            s->src_port == src_port &&
            s->dst_port == dst_port &&
            memcmp(s->dst_addr, dst_addr, 16) == 0) {
            s->last_active = GetTickCount64();
            SOCKET sock = s->loopback_sock;
            ReleaseSRWLockExclusive(&g_lock);
            return sock;
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
    sess->last_active = GetTickCount64();

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

int nb_session_send(
    SOCKET session_sock,
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port,
    const uint8_t *payload, uint16_t payload_len)
{
    if (session_sock == INVALID_SOCKET) return -1;

    uint32_t total = NB_UDP_REQ_HEADER_SIZE + payload_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;

    NbUdpReqHeader *hdr = (NbUdpReqHeader *)buf;
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic       = NB_MAGIC;
    hdr->version     = NB_VERSION;
    hdr->addr_type   = src_addr_type;
    hdr->protocol    = NB_PROTO_UDP;
    hdr->dst_port    = dst_port;
    hdr->src_port    = src_port;
    if (dst_addr) memcpy(hdr->dst_addr, dst_addr, 16);
    if (src_addr) memcpy(hdr->src_addr, src_addr, 16);
    hdr->pid         = pid;
    hdr->token       = nb_token_get();
    hdr->payload_len = payload_len;
    if (payload && payload_len > 0) {
        memcpy(buf + NB_UDP_REQ_HEADER_SIZE, payload, payload_len);
    }

    struct sockaddr_in core_addr = {0};
    core_addr.sin_family      = AF_INET;
    core_addr.sin_addr.s_addr = inet_addr(NB_CORE_ADDR);
    core_addr.sin_port        = htons(NB_CORE_UDP_PORT);

    int ret = sendto(session_sock, (const char *)buf, (int)total, 0,
                     (struct sockaddr *)&core_addr, sizeof(core_addr));

    free(buf);
    return (ret == (int)total) ? 0 : -1;
}

void nb_session_cleanup(void)
{
    if (!g_initialized) return;
    uint64_t now = GetTickCount64();

    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        UdpSession **pp = &g_sessions[i];
        while (*pp) {
            UdpSession *s = *pp;
            if (now - s->last_active > SESSION_TIMEOUT_MS) {
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
