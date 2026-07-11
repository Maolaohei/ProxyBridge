#include "process/nb_flow_decision.h"

#include <string.h>

#define FLOW_TTL_MS        30000u
#define FLOW_TABLE_SIZE    8192u
#define FLOW_MAX_PROBE     8u

typedef struct {
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8  proto;
    UINT8  family;   /* 4 or 6 */
    UINT8  decision; /* NbFlowDecision */
    UINT8  used;
    UINT8  src_ip6[16];
    UINT8  dst_ip6[16];
    ULONGLONG expires;
} FlowEntry;

static FlowEntry g_table[FLOW_TABLE_SIZE];
static volatile LONG g_inited;
static SRWLOCK g_lock;

/* O(1) secondary cache for src-port hot path (bitmap, 65536 bits each). */
static volatile LONG g_port_decided[2048]; /* 65536 / 32 */
static volatile LONG g_port_direct[2048];

static ULONGLONG now_ms(void)
{
    return GetTickCount64();
}

static UINT32 mix32(UINT32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static UINT32 hash_v4(UINT32 sip, UINT16 sp, UINT32 dip, UINT16 dp, UINT8 proto)
{
    UINT32 h = mix32(sip ^ ((UINT32)sp << 16) ^ dip ^ ((UINT32)dp << 1) ^ proto);
    return h % FLOW_TABLE_SIZE;
}

static UINT32 hash_v6(const UINT8 s[16], UINT16 sp, const UINT8 d[16], UINT16 dp, UINT8 proto)
{
    UINT32 h = 2166136261u;
    for (int i = 0; i < 16; i++) { h ^= s[i]; h *= 16777619u; }
    h ^= sp; h *= 16777619u;
    for (int i = 0; i < 16; i++) { h ^= d[i]; h *= 16777619u; }
    h ^= dp; h *= 16777619u;
    h ^= proto;
    return h % FLOW_TABLE_SIZE;
}

void nb_flow_decision_init(void)
{
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0)
        return;
    InitializeSRWLock(&g_lock);
    ZeroMemory(g_table, sizeof(g_table));
    ZeroMemory((void*)g_port_decided, sizeof(g_port_decided));
    ZeroMemory((void*)g_port_direct, sizeof(g_port_direct));
}

void nb_flow_decision_clear_all(void)
{
    AcquireSRWLockExclusive(&g_lock);
    ZeroMemory(g_table, sizeof(g_table));
    ReleaseSRWLockExclusive(&g_lock);
    ZeroMemory((void*)g_port_decided, sizeof(g_port_decided));
    ZeroMemory((void*)g_port_direct, sizeof(g_port_direct));
}

void nb_flow_decision_expire(void)
{
    ULONGLONG now = now_ms();
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (g_table[i].used && g_table[i].expires <= now)
            g_table[i].used = 0;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

static NbFlowDecision lookup_slot_v4(UINT32 idx, UINT32 sip, UINT16 sp, UINT32 dip, UINT16 dp, UINT8 proto, ULONGLONG now)
{
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (!e->used)
            return NB_FLOW_NONE;
        if (e->family == 4 && e->src_ip == sip && e->dst_ip == dip &&
            e->src_port == sp && e->dst_port == dp && e->proto == proto) {
            if (e->expires <= now) {
                e->used = 0;
                return NB_FLOW_NONE;
            }
            return (NbFlowDecision)e->decision;
        }
    }
    return NB_FLOW_NONE;
}

NbFlowDecision nb_flow_lookup_v4(UINT32 src_ip, UINT16 src_port,
                                 UINT32 dst_ip, UINT16 dst_port, UINT8 proto)
{
    if (!g_inited) nb_flow_decision_init();
    ULONGLONG now = now_ms();
    UINT32 idx = hash_v4(src_ip, src_port, dst_ip, dst_port, proto);
    NbFlowDecision d;
    AcquireSRWLockShared(&g_lock);
    d = lookup_slot_v4(idx, src_ip, src_port, dst_ip, dst_port, proto, now);
    ReleaseSRWLockShared(&g_lock);
    return d;
}

static void set_slot_v4(UINT32 sip, UINT16 sp, UINT32 dip, UINT16 dp, UINT8 proto, NbFlowDecision decision)
{
    if (!g_inited) nb_flow_decision_init();
    ULONGLONG now = now_ms();
    UINT32 idx = hash_v4(sip, sp, dip, dp, proto);
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (!e->used || e->expires <= now ||
            (e->family == 4 && e->src_ip == sip && e->dst_ip == dip &&
             e->src_port == sp && e->dst_port == dp && e->proto == proto)) {
            e->used = 1;
            e->family = 4;
            e->src_ip = sip; e->dst_ip = dip;
            e->src_port = sp; e->dst_port = dp;
            e->proto = proto;
            e->decision = (UINT8)decision;
            e->expires = now + FLOW_TTL_MS;
            ReleaseSRWLockExclusive(&g_lock);
            return;
        }
    }
    /* Table crowded: overwrite first slot */
    FlowEntry *e = &g_table[idx];
    e->used = 1; e->family = 4;
    e->src_ip = sip; e->dst_ip = dip;
    e->src_port = sp; e->dst_port = dp;
    e->proto = proto; e->decision = (UINT8)decision;
    e->expires = now + FLOW_TTL_MS;
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_flow_set_v4(UINT32 src_ip, UINT16 src_port,
                    UINT32 dst_ip, UINT16 dst_port, UINT8 proto,
                    NbFlowDecision decision)
{
    set_slot_v4(src_ip, src_port, dst_ip, dst_port, proto, decision);
}

void nb_flow_clear_v4(UINT32 src_ip, UINT16 src_port,
                      UINT32 dst_ip, UINT16 dst_port, UINT8 proto)
{
    if (!g_inited) return;
    UINT32 idx = hash_v4(src_ip, src_port, dst_ip, dst_port, proto);
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (e->used && e->family == 4 && e->src_ip == src_ip && e->dst_ip == dst_ip &&
            e->src_port == src_port && e->dst_port == dst_port && e->proto == proto) {
            e->used = 0;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_flow_clear_src_port_v4(UINT16 src_port)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (g_table[i].used && g_table[i].family == 4 && g_table[i].src_port == src_port)
            g_table[i].used = 0;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

static NbFlowDecision lookup_slot_v6(UINT32 idx, const UINT8 s[16], UINT16 sp,
                                     const UINT8 d[16], UINT16 dp, UINT8 proto, ULONGLONG now)
{
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (!e->used)
            return NB_FLOW_NONE;
        if (e->family == 6 && e->src_port == sp && e->dst_port == dp && e->proto == proto &&
            memcmp(e->src_ip6, s, 16) == 0 && memcmp(e->dst_ip6, d, 16) == 0) {
            if (e->expires <= now) { e->used = 0; return NB_FLOW_NONE; }
            return (NbFlowDecision)e->decision;
        }
    }
    return NB_FLOW_NONE;
}

NbFlowDecision nb_flow_lookup_v6(const UINT8 src_ip6[16], UINT16 src_port,
                                 const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto)
{
    if (!g_inited) nb_flow_decision_init();
    ULONGLONG now = now_ms();
    UINT32 idx = hash_v6(src_ip6, src_port, dst_ip6, dst_port, proto);
    NbFlowDecision d;
    AcquireSRWLockShared(&g_lock);
    d = lookup_slot_v6(idx, src_ip6, src_port, dst_ip6, dst_port, proto, now);
    ReleaseSRWLockShared(&g_lock);
    return d;
}

void nb_flow_set_v6(const UINT8 src_ip6[16], UINT16 src_port,
                    const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto,
                    NbFlowDecision decision)
{
    if (!g_inited) nb_flow_decision_init();
    ULONGLONG now = now_ms();
    UINT32 idx = hash_v6(src_ip6, src_port, dst_ip6, dst_port, proto);
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (!e->used || e->expires <= now ||
            (e->family == 6 && e->src_port == src_port && e->dst_port == dst_port &&
             e->proto == proto && memcmp(e->src_ip6, src_ip6, 16) == 0 &&
             memcmp(e->dst_ip6, dst_ip6, 16) == 0)) {
            e->used = 1; e->family = 6;
            memcpy(e->src_ip6, src_ip6, 16);
            memcpy(e->dst_ip6, dst_ip6, 16);
            e->src_port = src_port; e->dst_port = dst_port;
            e->proto = proto; e->decision = (UINT8)decision;
            e->expires = now + FLOW_TTL_MS;
            ReleaseSRWLockExclusive(&g_lock);
            return;
        }
    }
    FlowEntry *e = &g_table[idx];
    e->used = 1; e->family = 6;
    memcpy(e->src_ip6, src_ip6, 16);
    memcpy(e->dst_ip6, dst_ip6, 16);
    e->src_port = src_port; e->dst_port = dst_port;
    e->proto = proto; e->decision = (UINT8)decision;
    e->expires = now + FLOW_TTL_MS;
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_flow_clear_v6(const UINT8 src_ip6[16], UINT16 src_port,
                      const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto)
{
    if (!g_inited) return;
    UINT32 idx = hash_v6(src_ip6, src_port, dst_ip6, dst_port, proto);
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 p = 0; p < FLOW_MAX_PROBE; p++) {
        FlowEntry *e = &g_table[(idx + p) % FLOW_TABLE_SIZE];
        if (e->used && e->family == 6 && e->src_port == src_port && e->dst_port == dst_port &&
            e->proto == proto && memcmp(e->src_ip6, src_ip6, 16) == 0 &&
            memcmp(e->dst_ip6, dst_ip6, 16) == 0) {
            e->used = 0;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void nb_flow_clear_src_port_v6(UINT16 src_port)
{
    if (!g_inited) return;
    AcquireSRWLockExclusive(&g_lock);
    for (UINT32 i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (g_table[i].used && g_table[i].family == 6 && g_table[i].src_port == src_port)
            g_table[i].used = 0;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/* ---- port-level secondary cache (O(1) bitmap) + flow invalidation ---- */
static __forceinline void port_bit_set(volatile LONG *bits, UINT16 p)
{
    UINT32 idx = (UINT32)p >> 5;
    LONG mask = (LONG)(1u << (p & 31));
    InterlockedOr(&bits[idx], mask);
}

static __forceinline void port_bit_clear(volatile LONG *bits, UINT16 p)
{
    UINT32 idx = (UINT32)p >> 5;
    LONG mask = (LONG)(1u << (p & 31));
    InterlockedAnd(&bits[idx], ~mask);
}

static __forceinline BOOL port_bit_test(const volatile LONG *bits, UINT16 p)
{
    UINT32 idx = (UINT32)p >> 5;
    LONG mask = (LONG)(1u << (p & 31));
    return (bits[idx] & mask) != 0;
}

void nb_port_decision_init(void) { nb_flow_decision_init(); }
void nb_port_decision_clear_all(void) { nb_flow_decision_clear_all(); }
void nb_port_decision_expire(void) { nb_flow_decision_expire(); }

BOOL nb_port_is_decided(UINT16 p)
{
    if (!g_inited) return FALSE;
    return port_bit_test(g_port_decided, p);
}

BOOL nb_port_is_direct(UINT16 p)
{
    if (!g_inited) return FALSE;
    return port_bit_test(g_port_direct, p);
}

void nb_port_set_direct(UINT16 p)
{
    if (!g_inited) nb_flow_decision_init();
    port_bit_set(g_port_decided, p);
    port_bit_set(g_port_direct, p);
}

void nb_port_set_decided(UINT16 p)
{
    if (!g_inited) nb_flow_decision_init();
    port_bit_set(g_port_decided, p);
    port_bit_clear(g_port_direct, p);
}

void nb_port_clear(UINT16 p)
{
    port_bit_clear(g_port_decided, p);
    port_bit_clear(g_port_direct, p);
    /* Also drop any 5-tuple entries using this local source port. */
    nb_flow_clear_src_port_v4(p);
    nb_flow_clear_src_port_v6(p);
}
