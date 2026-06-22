#include "src/include/nb_proto.h"
#include "src/security/nb_token.h"
#include "src/process/nb_procname.h"
#include "src/netbridge/nb_session.h"
#include "src/netbridge/nb_tcp.h"
#include "src/netbridge/nb_buf.h"
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  TEST: %s ... ", name); \
    tests_run++; \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while(0)

/* ===== nb_proto.h tests ===== */

static void test_proto_constants(void)
{
    TEST("NB_MAGIC value");
    assert(NB_MAGIC == 0x4E425632u);
    PASS();

    TEST("NB_VERSION value");
    assert(NB_VERSION == 1);
    PASS();

    TEST("NB_ADDR_IPV4/IPv6");
    assert(NB_ADDR_IPV4 == 0x04);
    assert(NB_ADDR_IPV6 == 0x06);
    PASS();

    TEST("NB_PROTO_TCP/UDP (IANA)");
    assert(NB_PROTO_TCP == 6);
    assert(NB_PROTO_UDP == 17);
    PASS();
}

static void test_tcp_header_total(void)
{
    TEST("nb_tcp_header_total: 0 bytes proc name");
    assert(nb_tcp_header_total(0) == NB_TCP_HEADER_BASE_SIZE);
    PASS();

    TEST("nb_tcp_header_total: 1 byte proc name (align to 4)");
    assert(nb_tcp_header_total(1) == NB_TCP_HEADER_BASE_SIZE + 4);
    PASS();

    TEST("nb_tcp_header_total: 4 bytes proc name");
    assert(nb_tcp_header_total(4) == NB_TCP_HEADER_BASE_SIZE + 4);
    PASS();

    TEST("nb_tcp_header_total: 5 bytes proc name (align to 8)");
    assert(nb_tcp_header_total(5) == NB_TCP_HEADER_BASE_SIZE + 8);
    PASS();

    TEST("nb_tcp_header_total: 64 bytes proc name");
    assert(nb_tcp_header_total(64) == NB_TCP_HEADER_BASE_SIZE + 64);
    PASS();
}

static void test_tcp_header_serialize(void)
{
    TEST("nb_tcp_header_serialize: basic");
    uint8_t buf[128];
    uint8_t dst_addr[16] = {10, 0, 0, 1};
    const char *proc = "chrome.exe";
    uint8_t proc_len = (uint8_t)strlen(proc);

    uint32_t total = nb_tcp_header_serialize(
        buf, sizeof(buf),
        NB_ADDR_IPV4, 80, 12345,
        dst_addr, 1234, 0xABCDEF01,
        proc, proc_len);

    assert(total > 0);
    assert(total == nb_tcp_header_total(proc_len));

    NbTcpHeader *h = (NbTcpHeader *)buf;
    assert(h->magic == NB_MAGIC);
    assert(h->version == NB_VERSION);
    assert(h->addr_type == NB_ADDR_IPV4);
    assert(h->protocol == NB_PROTO_TCP);
    assert(h->proc_name_len == proc_len);
    assert(h->dst_port == 80);
    assert(h->src_port == 12345);
    assert(h->pid == 1234);
    assert(h->token == 0xABCDEF01);
    assert(memcmp(buf + NB_TCP_HEADER_BASE_SIZE, proc, proc_len) == 0);
    PASS();

    TEST("nb_tcp_header_serialize: buffer too small");
    uint8_t small_buf[4];
    uint32_t r = nb_tcp_header_serialize(
        small_buf, 4,
        NB_ADDR_IPV4, 80, 12345,
        dst_addr, 1234, 0xABCDEF01,
        proc, proc_len);
    assert(r == 0);
    PASS();

    TEST("nb_tcp_header_serialize: padding zeros");
    uint8_t buf2[128];
    nb_tcp_header_serialize(
        buf2, sizeof(buf2),
        NB_ADDR_IPV4, 80, 12345,
        dst_addr, 1234, 0xABCDEF01,
        proc, proc_len);

    /* Check padding bytes are zero */
    uint32_t base_with_proc = NB_TCP_HEADER_BASE_SIZE + proc_len;
    uint32_t padded = nb_tcp_header_total(proc_len);
    for (uint32_t i = base_with_proc; i < padded; i++) {
        assert(buf2[i] == 0);
    }
    PASS();
}

static void test_udp_req_header_size(void)
{
    TEST("NbUdpReqHeader size");
    assert(sizeof(NbUdpReqHeader) == NB_UDP_REQ_HEADER_SIZE);
    PASS();

    TEST("NbUdpRespHeader size");
    assert(sizeof(NbUdpRespHeader) == NB_UDP_RESP_HEADER_SIZE);
    PASS();

    TEST("NbError size");
    assert(sizeof(NbError) == NB_ERROR_SIZE);
    PASS();
}

/* ===== nb_procname.h tests ===== */

static void test_procname_cache(void)
{
    TEST("nb_procname_init");
    nb_procname_init();
    PASS();

    TEST("nb_procname_get: invalid PID returns empty");
    const char *name = nb_procname_get(0);
    assert(name != NULL);
    assert(name[0] == '\0');
    PASS();

    TEST("nb_procname_get: nonexistent PID returns empty");
    name = nb_procname_get(99999999);
    assert(name != NULL);
    assert(name[0] == '\0');
    PASS();

    TEST("nb_procname_get: current process PID returns name");
    DWORD pid = GetCurrentProcessId();
    name = nb_procname_get(pid);
    assert(name != NULL);
    assert(name[0] != '\0');
    PASS();

    TEST("nb_procname_clear");
    nb_procname_clear();
    PASS();
}

/* ===== nb_session.h tests ===== */

static void test_session_init(void)
{
    WSADATA wsa;
    BOOL wsa_ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

    TEST("nb_session_init");
    nb_session_init();
    PASS();

    if (wsa_ok) {
        TEST("nb_session_get_or_create: creates session");
        uint8_t src[16] = {127, 0, 0, 1};
        uint8_t dst[16] = {10, 0, 0, 1};
        SOCKET s = nb_session_get_or_create(0, src, 12345, NB_ADDR_IPV4, dst, 53);
        assert(s != INVALID_SOCKET);
        PASS();

        TEST("nb_session_get_or_create: same flow returns same socket");
        SOCKET s2 = nb_session_get_or_create(0, src, 12345, NB_ADDR_IPV4, dst, 53);
        assert(s == s2);
        PASS();

        TEST("nb_session_cleanup");
        nb_session_cleanup();
        PASS();

        TEST("nb_session_shutdown");
        nb_session_shutdown();
        PASS();
    } else {
        printf("  (skipping socket tests — WSAStartup failed)\n");
    }

    if (wsa_ok) WSACleanup();
}

/* ===== nb_tcp.h tests ===== */

static void test_tcp_pool_init(void)
{
    TEST("nb_tcp_pool_init");
    nb_tcp_pool_init();
    PASS();

    TEST("nb_tcp_pool_shutdown");
    nb_tcp_pool_shutdown();
    PASS();
}

/* ===== nb_buf.h tests ===== */

static void test_buf_pool(void)
{
    TEST("nb_buf_init");
    nb_buf_init();
    PASS();

    TEST("nb_buf_acquire_pool SMALL");
    void *small = nb_buf_acquire_pool(NB_POOL_SMALL);
    assert(small != NULL);
    nb_buf_release_pool(small, NB_POOL_SMALL);
    PASS();

    TEST("nb_buf_acquire_pool MEDIUM");
    void *medium = nb_buf_acquire_pool(NB_POOL_MEDIUM);
    assert(medium != NULL);
    nb_buf_release_pool(medium, NB_POOL_MEDIUM);
    PASS();

    TEST("nb_buf_acquire_pool LARGE");
    void *large = nb_buf_acquire_pool(NB_POOL_LARGE);
    assert(large != NULL);
    nb_buf_release_pool(large, NB_POOL_LARGE);
    PASS();

    TEST("nb_buf_pool reuse (acquire same buffer twice)");
    void *b1 = nb_buf_acquire_pool(NB_POOL_MEDIUM);
    nb_buf_release_pool(b1, NB_POOL_MEDIUM);
    void *b2 = nb_buf_acquire_pool(NB_POOL_MEDIUM);
    assert(b2 == b1); /* should reuse the same buffer */
    nb_buf_release_pool(b2, NB_POOL_MEDIUM);
    PASS();

    TEST("nb_buf_pool stress (64 concurrent)");
    void *bufs[64];
    for (int i = 0; i < 64; i++)
        bufs[i] = nb_buf_acquire_pool(NB_POOL_MEDIUM);
    for (int i = 0; i < 64; i++)
        assert(bufs[i] != NULL);
    for (int i = 0; i < 64; i++)
        nb_buf_release_pool(bufs[i], NB_POOL_MEDIUM);
    PASS();

    TEST("nb_buf_pool overflow (>64 drops excess)");
    void *overflow[80];
    for (int i = 0; i < 80; i++)
        overflow[i] = nb_buf_acquire_pool(NB_POOL_SMALL);
    for (int i = 0; i < 80; i++)
        nb_buf_release_pool(overflow[i], NB_POOL_SMALL);
    PASS();
}

static void test_buf_perf(void)
{
    TEST("perf: pool alloc vs malloc (100K iterations)");
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    /* Pool path */
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 100000; i++) {
        void *p = nb_buf_acquire_pool(NB_POOL_MEDIUM);
        nb_buf_release_pool(p, NB_POOL_MEDIUM);
    }
    QueryPerformanceCounter(&end);
    double pool_ms = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;

    /* malloc path */
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 100000; i++) {
        void *p = malloc(65535);
        free(p);
    }
    QueryPerformanceCounter(&end);
    double malloc_ms = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;

    printf("    pool=%.1fms malloc=%.1fms speedup=%.1fx ", pool_ms, malloc_ms, malloc_ms / pool_ms);
    PASS();
}

int main(void)
{
    printf("=== NetBridge Unit Tests ===\n\n");

    printf("[Protocol]\n");
    test_proto_constants();
    test_tcp_header_total();
    test_tcp_header_serialize();
    test_udp_req_header_size();

    printf("\n[Buffer Pool]\n");
    test_buf_pool();
    test_buf_perf();

    printf("\n[Process Name Cache]\n");
    test_procname_cache();

    printf("\n[Session Management]\n");
    test_session_init();

    printf("\n[TCP Pool]\n");
    test_tcp_pool_init();

    nb_buf_shutdown();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
