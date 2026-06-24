#ifndef NB_PROTO_H
#define NB_PROTO_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

/* MSVC compatibility: _Static_assert is C11, MSVC uses static_assert */
#if defined(_MSC_VER) && !defined(_Static_assert)
#define _Static_assert(cond, msg) static_assert(cond, msg)
#endif

/*
 * NetBridge Protocol Definition (v2.1.0)
 *
 * This header is the SINGLE SOURCE OF TRUTH for the binary protocol
 * between ProxyBridgeCore (C) and NetBridge Bridge (Go).
 *
 * Any field change MUST:
 *   1. Update this header
 *   2. Update Go side: internal/protocol/tcp.go, udp.go
 *   3. Update golden test files
 *   4. Pass cross-language golden test
 */

/* ===== Constants ===== */

#define NB_MAGIC         ((uint32_t)0x4E425632u)  /* "NBv2" LE */
#define NB_VERSION       ((uint8_t)1)

#define NB_ADDR_IPV4     ((uint8_t)0x04)
#define NB_ADDR_IPV6     ((uint8_t)0x06)

#define NB_PROTO_TCP     ((uint8_t)6)   /* IANA */
#define NB_PROTO_UDP     ((uint8_t)17)  /* IANA */

#define NB_ERR_VERSION   ((uint8_t)0x01)
#define NB_ERR_TOKEN     ((uint8_t)0x02)

#define NB_PROC_NAME_MAX ((uint8_t)64)

/* Core listening ports */
#define NB_CORE_TCP_PORT  35000
#define NB_CORE_UDP_PORT  35001
#define NB_CORE_ADDR      "127.0.0.1"

/* ===== TCP Header (variable length) ===== */

/*
 * TCP Channel Header layout:
 *   Offset  Size  Field
 *   0       4     magic (NB_MAGIC)
 *   4       1     version (NB_VERSION)
 *   5       1     addr_type (NB_ADDR_IPV4 / NB_ADDR_IPV6)
 *   6       1     protocol (NB_PROTO_TCP = 6)
 *   7       1     proc_name_len (0..64)
 *   8       2     dst_port (LE)
 *   10      2     src_port (LE)
 *   12      16    dst_addr (IPv4: first 4 bytes, rest zero; IPv6: all 16)
 *   28      4     pid (LE)
 *   32      4     token (LE)
 *   36      N     proc_name (UTF-8, N = proc_name_len)
 *   36+N    M     reserved (0..3 bytes, pad to 4-byte boundary)
 *
 * Total = 36 + proc_name_len + ((4 - (36 + proc_name_len) % 4) % 4)
 */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  protocol;
    uint8_t  proc_name_len;
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t  dst_addr[16];
    uint32_t pid;
    uint32_t token;
    /* variable: proc_name[proc_name_len] + reserved[0..3] */
} NbTcpHeader;
#pragma pack(pop)

#define NB_TCP_HEADER_BASE_SIZE 36

/* ===== UDP Request Header (56 bytes, fixed) ===== */

/*
 * UDP Request Header layout:
 *   Offset  Size  Field
 *   0       4     magic
 *   4       1     version
 *   5       1     addr_type
 *   6       1     protocol (NB_PROTO_UDP = 17)
 *   7       1     reserved
 *   8       2     dst_port (LE)
 *   10      2     src_port (LE)
 *   12      16    dst_addr
 *   28      16    src_addr
 *   44      4     pid (LE)
 *   48      4     token (LE)
 *   52      2     payload_len (LE)
 *   54      2     reserved2
 *   Total: 56 bytes
 */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  protocol;
    uint8_t  reserved;
    uint16_t dst_port;
    uint16_t src_port;
    uint8_t  dst_addr[16];
    uint8_t  src_addr[16];
    uint32_t pid;
    uint32_t token;
    uint16_t payload_len;
    uint16_t reserved2;
} NbUdpReqHeader;
#pragma pack(pop)

#define NB_UDP_REQ_HEADER_SIZE 56

/* ===== UDP Response Header (32 bytes, fixed) ===== */

/*
 * UDP Response Header layout:
 *   Offset  Size  Field
 *   0       4     magic
 *   4       1     version
 *   5       1     addr_type
 *   6       2     reserved
 *   8       2     src_port (LE)
 *   10      2     reserved2
 *   12      16    src_addr
 *   28      2     payload_len (LE)
 *   30      2     reserved3
 *   Total: 32 bytes
 */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  addr_type;
    uint8_t  reserved[2];
    uint16_t src_port;
    uint16_t reserved2;
    uint8_t  src_addr[16];
    uint16_t payload_len;
    uint16_t reserved3;
} NbUdpRespHeader;
#pragma pack(pop)

#define NB_UDP_RESP_HEADER_SIZE 32

/* ===== Error Packet (8 bytes, TCP only) ===== */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  error_code;
    uint16_t reserved;
} NbError;
#pragma pack(pop)

#define NB_ERROR_SIZE 8

/* ===== Compile-time Assertions ===== */

/* TCP Header */
_Static_assert(sizeof(NbTcpHeader) == NB_TCP_HEADER_BASE_SIZE, "NbTcpHeader base size mismatch");
_Static_assert(offsetof(NbTcpHeader, magic)        == 0,  "NbTcpHeader.magic offset");
_Static_assert(offsetof(NbTcpHeader, version)      == 4,  "NbTcpHeader.version offset");
_Static_assert(offsetof(NbTcpHeader, addr_type)    == 5,  "NbTcpHeader.addr_type offset");
_Static_assert(offsetof(NbTcpHeader, protocol)     == 6,  "NbTcpHeader.protocol offset");
_Static_assert(offsetof(NbTcpHeader, proc_name_len)== 7,  "NbTcpHeader.proc_name_len offset");
_Static_assert(offsetof(NbTcpHeader, dst_port)     == 8,  "NbTcpHeader.dst_port offset");
_Static_assert(offsetof(NbTcpHeader, src_port)     == 10, "NbTcpHeader.src_port offset");
_Static_assert(offsetof(NbTcpHeader, dst_addr)     == 12, "NbTcpHeader.dst_addr offset");
_Static_assert(offsetof(NbTcpHeader, pid)          == 28, "NbTcpHeader.pid offset");
_Static_assert(offsetof(NbTcpHeader, token)        == 32, "NbTcpHeader.token offset");

/* UDP Request Header */
_Static_assert(sizeof(NbUdpReqHeader) == NB_UDP_REQ_HEADER_SIZE, "NbUdpReqHeader size mismatch");
_Static_assert(offsetof(NbUdpReqHeader, magic)       == 0,  "NbUdpReqHeader.magic offset");
_Static_assert(offsetof(NbUdpReqHeader, dst_port)    == 8,  "NbUdpReqHeader.dst_port offset");
_Static_assert(offsetof(NbUdpReqHeader, src_port)    == 10, "NbUdpReqHeader.src_port offset");
_Static_assert(offsetof(NbUdpReqHeader, dst_addr)    == 12, "NbUdpReqHeader.dst_addr offset");
_Static_assert(offsetof(NbUdpReqHeader, src_addr)    == 28, "NbUdpReqHeader.src_addr offset");
_Static_assert(offsetof(NbUdpReqHeader, pid)         == 44, "NbUdpReqHeader.pid offset");
_Static_assert(offsetof(NbUdpReqHeader, token)       == 48, "NbUdpReqHeader.token offset");
_Static_assert(offsetof(NbUdpReqHeader, payload_len) == 52, "NbUdpReqHeader.payload_len offset");

/* UDP Response Header */
_Static_assert(sizeof(NbUdpRespHeader) == NB_UDP_RESP_HEADER_SIZE, "NbUdpRespHeader size mismatch");
_Static_assert(offsetof(NbUdpRespHeader, magic)       == 0,  "NbUdpRespHeader.magic offset");
_Static_assert(offsetof(NbUdpRespHeader, src_port)    == 8,  "NbUdpRespHeader.src_port offset");
_Static_assert(offsetof(NbUdpRespHeader, src_addr)    == 12, "NbUdpRespHeader.src_addr offset");
_Static_assert(offsetof(NbUdpRespHeader, payload_len) == 28, "NbUdpRespHeader.payload_len offset");

/* Error */
_Static_assert(sizeof(NbError) == NB_ERROR_SIZE, "NbError size mismatch");

/* ===== Helper: compute total TCP header size ===== */

static inline uint32_t nb_tcp_header_total(uint8_t proc_name_len)
{
    uint32_t raw = NB_TCP_HEADER_BASE_SIZE + proc_name_len;
    return (raw + 3u) & ~3u;  /* align to 4 bytes */
}

/* ===== Helper: serialize TCP header into buffer ===== */

static inline uint32_t nb_tcp_header_serialize(
    uint8_t *out, uint32_t out_cap,
    uint8_t addr_type, uint16_t dst_port, uint16_t src_port,
    const uint8_t *dst_addr, uint32_t pid, uint32_t token,
    const char *proc_name, uint8_t proc_name_len)
{
    uint32_t total = nb_tcp_header_total(proc_name_len);
    if (total > out_cap) return 0;

    NbTcpHeader *h = (NbTcpHeader *)out;
    h->magic         = NB_MAGIC;
    h->version       = NB_VERSION;
    h->addr_type     = addr_type;
    h->protocol      = NB_PROTO_TCP;
    h->proc_name_len = proc_name_len;
    h->dst_port      = dst_port;
    h->src_port      = src_port;
    if (dst_addr) memcpy(h->dst_addr, dst_addr, 16);
    else memset(h->dst_addr, 0, 16);
    h->pid           = pid;
    h->token         = token;

    if (proc_name_len > 0 && proc_name) {
        memcpy(out + NB_TCP_HEADER_BASE_SIZE, proc_name, proc_name_len);
    }

    /* zero padding */
    memset(out + NB_TCP_HEADER_BASE_SIZE + proc_name_len, 0,
           total - NB_TCP_HEADER_BASE_SIZE - proc_name_len);

    return total;
}

#endif /* NB_PROTO_H */
