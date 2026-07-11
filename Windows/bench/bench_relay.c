/*
 * Real-machine throughput / latency benchmark for ProxyBridge relay.
 *
 * Modes:
 *   direct   - loopback TCP echo baseline
 *   iocp     - shared IOCP bidirectional relay
 *   compare  - run both
 *
 * Example:
 *   .\bench_relay.exe compare --bytes 67108864 --conns 32 --latency 200
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/netbridge/nb_iocp_relay.h"

#pragma comment(lib, "ws2_32.lib")

typedef struct {
    UINT16 echo_port;
    size_t bytes;
    int use_iocp;
    volatile LONG *errors;
    volatile LONG *done;
} Job;

static SOCKET listen_loopback(UINT16 *out_port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    BOOL on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    struct sockaddr_in a;
    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (listen(s, 512) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int alen = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &alen);
    if (out_port)
        *out_port = ntohs(a.sin_port);
    return s;
}

static SOCKET connect_loopback(UINT16 port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
    int buf = 4 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf, sizeof(buf));
    BOOL nodelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    struct sockaddr_in a;
    ZeroMemory(&a, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static int send_all(SOCKET s, const char *buf, int len)
{
    int off = 0;
    while (off < len) {
        int n = send(s, buf + off, len - off, 0);
        if (n <= 0)
            return -1;
        off += n;
    }
    return 0;
}

static int recv_exact(SOCKET s, char *buf, int len)
{
    int off = 0;
    while (off < len) {
        int n = recv(s, buf + off, len - off, 0);
        if (n <= 0)
            return -1;
        off += n;
    }
    return 0;
}

static DWORD WINAPI echo_worker(LPVOID arg)
{
    SOCKET s = (SOCKET)(uintptr_t)arg;
    char *buf = (char *)malloc(256 * 1024);
    if (!buf) {
        closesocket(s);
        return 1;
    }
    int n;
    while ((n = recv(s, buf, 256 * 1024, 0)) > 0) {
        if (send_all(s, buf, n) != 0)
            break;
    }
    free(buf);
    closesocket(s);
    return 0;
}

static DWORD WINAPI accept_loop(LPVOID arg)
{
    SOCKET ls = (SOCKET)(uintptr_t)arg;
    for (;;) {
        SOCKET c = accept(ls, NULL, NULL);
        if (c == INVALID_SOCKET)
            break;
        HANDLE h = CreateThread(NULL, 0, echo_worker, (LPVOID)(uintptr_t)c, 0, NULL);
        if (h)
            CloseHandle(h);
        else
            closesocket(c);
    }
    return 0;
}

static DWORD WINAPI job_worker(LPVOID arg)
{
    Job *job = (Job *)arg;
    SOCKET write_sock = INVALID_SOCKET;
    SOCKET relay_a = INVALID_SOCKET;
    SOCKET relay_b = INVALID_SOCKET;

    if (job->use_iocp) {
        /*
         * Topology:
         *   write_sock  --TCP-->  relay_a  ==IOCP==  relay_b  --TCP-->  echo
         */
        UINT16 side_port = 0;
        SOCKET side_ls = listen_loopback(&side_port);
        if (side_ls == INVALID_SOCKET) {
            InterlockedIncrement(job->errors);
            free(job);
            return 1;
        }
        write_sock = connect_loopback(side_port);
        relay_a = accept(side_ls, NULL, NULL);
        closesocket(side_ls);
        if (write_sock == INVALID_SOCKET || relay_a == INVALID_SOCKET) {
            if (write_sock != INVALID_SOCKET)
                closesocket(write_sock);
            if (relay_a != INVALID_SOCKET)
                closesocket(relay_a);
            InterlockedIncrement(job->errors);
            free(job);
            return 1;
        }
        relay_b = connect_loopback(job->echo_port);
        if (relay_b == INVALID_SOCKET) {
            closesocket(write_sock);
            closesocket(relay_a);
            InterlockedIncrement(job->errors);
            free(job);
            return 1;
        }
        if (nb_iocp_relay_start(relay_a, relay_b) != 0) {
            closesocket(write_sock);
            closesocket(relay_a);
            closesocket(relay_b);
            InterlockedIncrement(job->errors);
            free(job);
            return 1;
        }
        /* ownership of relay_a/relay_b transferred to IOCP */
    } else {
        write_sock = connect_loopback(job->echo_port);
        if (write_sock == INVALID_SOCKET) {
            InterlockedIncrement(job->errors);
            free(job);
            return 1;
        }
    }

    char *buf = (char *)malloc(256 * 1024);
    if (!buf) {
        closesocket(write_sock);
        InterlockedIncrement(job->errors);
        free(job);
        return 1;
    }
    memset(buf, 0xA5, 256 * 1024);

    size_t remaining = job->bytes;
    while (remaining > 0) {
        int chunk = (int)((remaining > 256 * 1024) ? (256 * 1024) : remaining);
        if (send_all(write_sock, buf, chunk) != 0 ||
            recv_exact(write_sock, buf, chunk) != 0) {
            InterlockedIncrement(job->errors);
            free(buf);
            closesocket(write_sock);
            free(job);
            return 1;
        }
        remaining -= (size_t)chunk;
    }

    free(buf);
    closesocket(write_sock);
    InterlockedIncrement(job->done);
    free(job);
    return 0;
}

static double run_throughput(int use_iocp, size_t total_bytes, int conns)
{
    UINT16 echo_port = 0;
    SOCKET echo_ls = listen_loopback(&echo_port);
    if (echo_ls == INVALID_SOCKET)
        return -1.0;
    HANDLE acc = CreateThread(NULL, 0, accept_loop, (LPVOID)(uintptr_t)echo_ls, 0, NULL);

    volatile LONG errors = 0, done = 0;
    HANDLE *threads = (HANDLE *)calloc((size_t)conns, sizeof(HANDLE));
    if (!threads) {
        closesocket(echo_ls);
        return -1.0;
    }

    size_t per = total_bytes / (size_t)conns;
    if (per == 0)
        per = total_bytes;

    ULONGLONG t0 = GetTickCount64();
    for (int i = 0; i < conns; i++) {
        Job *job = (Job *)malloc(sizeof(Job));
        job->echo_port = echo_port;
        job->bytes = per;
        job->use_iocp = use_iocp;
        job->errors = &errors;
        job->done = &done;
        threads[i] = CreateThread(NULL, 0, job_worker, job, 0, NULL);
    }
    WaitForMultipleObjects(conns, threads, TRUE, INFINITE);
    ULONGLONG t1 = GetTickCount64();
    for (int i = 0; i < conns; i++) {
        if (threads[i])
            CloseHandle(threads[i]);
    }
    free(threads);

    closesocket(echo_ls);
    if (acc) {
        /* accept loop ends after listen socket closed */
        WaitForSingleObject(acc, 1000);
        CloseHandle(acc);
    }

    if (errors > 0 || done != conns)
        return -1.0;
    double sec = (t1 > t0) ? ((double)(t1 - t0) / 1000.0) : 0.001;
    double mb = ((double)(per * (size_t)conns)) / (1024.0 * 1024.0);
    return mb / sec;
}

static double percentile(double *arr, int n, double p)
{
    if (n <= 0)
        return 0;
    int idx = (int)(p * (n - 1));
    if (idx < 0)
        idx = 0;
    if (idx >= n)
        idx = n - 1;
    return arr[idx];
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void run_latency(int use_iocp, int n, double *p50, double *p99)
{
    UINT16 echo_port = 0;
    SOCKET echo_ls = listen_loopback(&echo_port);
    HANDLE acc = CreateThread(NULL, 0, accept_loop, (LPVOID)(uintptr_t)echo_ls, 0, NULL);
    double *samples = (double *)calloc((size_t)n, sizeof(double));
    char payload[64];
    memset(payload, 0x5A, sizeof(payload));

    for (int i = 0; i < n; i++) {
        SOCKET write_sock;
        if (use_iocp) {
            UINT16 side_port = 0;
            SOCKET side_ls = listen_loopback(&side_port);
            write_sock = connect_loopback(side_port);
            SOCKET relay_a = accept(side_ls, NULL, NULL);
            closesocket(side_ls);
            SOCKET relay_b = connect_loopback(echo_port);
            if (write_sock == INVALID_SOCKET || relay_a == INVALID_SOCKET || relay_b == INVALID_SOCKET ||
                nb_iocp_relay_start(relay_a, relay_b) != 0) {
                if (write_sock != INVALID_SOCKET)
                    closesocket(write_sock);
                samples[i] = 9999.0;
                continue;
            }
        } else {
            write_sock = connect_loopback(echo_port);
            if (write_sock == INVALID_SOCKET) {
                samples[i] = 9999.0;
                continue;
            }
        }

        LARGE_INTEGER f, t0, t1;
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&t0);
        if (send_all(write_sock, payload, (int)sizeof(payload)) != 0 ||
            recv_exact(write_sock, payload, (int)sizeof(payload)) != 0) {
            samples[i] = 9999.0;
        } else {
            QueryPerformanceCounter(&t1);
            samples[i] = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)f.QuadPart;
        }
        closesocket(write_sock);
    }

    closesocket(echo_ls);
    if (acc) {
        WaitForSingleObject(acc, 1000);
        CloseHandle(acc);
    }

    qsort(samples, (size_t)n, sizeof(double), cmp_double);
    *p50 = percentile(samples, n, 0.50);
    *p99 = percentile(samples, n, 0.99);
    free(samples);
}

static void run_one(const char *name, int use_iocp, size_t bytes, int conns, int latency_n)
{
    printf("[%s]\n", name);
    double thr = run_throughput(use_iocp, bytes, conns);
    double p50 = 0, p99 = 0;
    run_latency(use_iocp, latency_n, &p50, &p99);
    if (thr < 0)
        printf("  throughput: FAILED\n");
    else
        printf("  throughput: %.2f MB/s  (%d conns, %.1f MB total)\n",
               thr, conns, bytes / (1024.0 * 1024.0));
    printf("  latency  : p50=%.3f ms  p99=%.3f ms  (n=%d, 64B RTT)\n\n", p50, p99, latency_n);
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    const char *mode = "compare";
    size_t bytes = 64ull * 1024ull * 1024ull;
    int conns = 16;
    int latency_n = 200;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "direct") || !strcmp(argv[i], "iocp") || !strcmp(argv[i], "compare"))
            mode = argv[i];
        else if (!strcmp(argv[i], "--bytes") && i + 1 < argc)
            bytes = _strtoui64(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--conns") && i + 1 < argc)
            conns = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--latency") && i + 1 < argc)
            latency_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--help")) {
            printf("Usage: bench_relay.exe [direct|iocp|compare] [--bytes N] [--conns N] [--latency N]\n");
            WSACleanup();
            return 0;
        }
    }

    printf("ProxyBridge relay real-machine benchmark\n");
    printf("  mode=%s bytes=%llu conns=%d latency=%d\n\n",
           mode, (unsigned long long)bytes, conns, latency_n);

    nb_iocp_relay_init();

    if (!strcmp(mode, "direct") || !strcmp(mode, "compare"))
        run_one("Direct TCP", 0, bytes, conns, latency_n);
    if (!strcmp(mode, "iocp") || !strcmp(mode, "compare"))
        run_one("IOCP Relay", 1, bytes, conns, latency_n);

    nb_iocp_relay_shutdown();
    WSACleanup();
    return 0;
}
