#include "process/nb_port_decision.h"

#define PORT_DECISION_TTL_MS 30000u

static volatile LONG g_decided[2048];
static volatile LONG g_direct[2048];
/* Coarse timestamp buckets (ms / 1024) per port; 0 = unused. */
static volatile ULONG g_stamp[65536];
static volatile LONG g_initialized;

static ULONG now_bucket(void)
{
    return (ULONG)(GetTickCount64() >> 10); /* ~1.024s resolution */
}

void nb_port_decision_init(void)
{
    if (InterlockedCompareExchange(&g_initialized, 1, 0) != 0)
        return;
    ZeroMemory((void*)g_decided, sizeof(g_decided));
    ZeroMemory((void*)g_direct, sizeof(g_direct));
    ZeroMemory((void*)g_stamp, sizeof(g_stamp));
}

void nb_port_decision_clear_all(void)
{
    ZeroMemory((void*)g_decided, sizeof(g_decided));
    ZeroMemory((void*)g_direct, sizeof(g_direct));
    ZeroMemory((void*)g_stamp, sizeof(g_stamp));
}

static BOOL stamp_valid(UINT16 p)
{
    ULONG s = g_stamp[p];
    if (s == 0)
        return FALSE;
    ULONG age_buckets = now_bucket() - s;
    /* 30s / 1.024s ? 29 buckets */
    return age_buckets <= (PORT_DECISION_TTL_MS / 1024u + 1u);
}

BOOL nb_port_is_decided(UINT16 p)
{
    if (!((g_decided[p >> 5] >> (p & 31)) & 1))
        return FALSE;
    if (!stamp_valid(p)) {
        nb_port_clear(p);
        return FALSE;
    }
    return TRUE;
}

BOOL nb_port_is_direct(UINT16 p)
{
    return (g_direct[p >> 5] >> (p & 31)) & 1;
}

void nb_port_set_direct(UINT16 p)
{
    InterlockedOr(&g_decided[p >> 5], (LONG)(1u << (p & 31)));
    InterlockedOr(&g_direct[p >> 5], (LONG)(1u << (p & 31)));
    g_stamp[p] = now_bucket();
    if (g_stamp[p] == 0)
        g_stamp[p] = 1;
}

void nb_port_set_decided(UINT16 p)
{
    InterlockedOr(&g_decided[p >> 5], (LONG)(1u << (p & 31)));
    InterlockedAnd(&g_direct[p >> 5], (LONG)~(1u << (p & 31)));
    g_stamp[p] = now_bucket();
    if (g_stamp[p] == 0)
        g_stamp[p] = 1;
}

void nb_port_clear(UINT16 p)
{
    InterlockedAnd(&g_decided[p >> 5], (LONG)~(1u << (p & 31)));
    InterlockedAnd(&g_direct[p >> 5], (LONG)~(1u << (p & 31)));
    g_stamp[p] = 0;
}

void nb_port_decision_expire(void)
{
    /* Lazy expiry on read is primary; periodic pass keeps stamp table fresh. */
    ULONG now = now_bucket();
    for (UINT32 p = 0; p < 65536u; p++) {
        ULONG s = g_stamp[p];
        if (s == 0)
            continue;
        if (now - s > (PORT_DECISION_TTL_MS / 1024u + 1u))
            nb_port_clear((UINT16)p);
    }
}
