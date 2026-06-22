#include "nb_procname.h"
#include <windows.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>

#define PROC_CACHE_SIZE  512
#define PROC_CACHE_TTL   5000  /* 5 seconds */
#define MAX_PROC_NAME    64

typedef struct {
    uint32_t pid;
    char     name[MAX_PROC_NAME];
    uint64_t expires;
} ProcCacheEntry;

static ProcCacheEntry g_cache[PROC_CACHE_SIZE];
static SRWLOCK g_cache_lock = SRWLOCK_INIT;
static BOOL g_initialized = FALSE;

/* FNV-1a hash */
static uint32_t fnv1a(uint32_t pid) {
    uint32_t h = 2166136261u;
    h ^= pid; h *= 16777619u;
    return h % PROC_CACHE_SIZE;
}

void nb_procname_init(void)
{
    if (g_initialized) return;
    memset(g_cache, 0, sizeof(g_cache));
    InitializeSRWLock(&g_cache_lock);
    g_initialized = TRUE;
}

const char* nb_procname_get(uint32_t pid)
{
    if (!g_initialized) nb_procname_init();

    uint64_t now = GetTickCount64();
    uint32_t idx = fnv1a(pid);

    /* Read-lock fast path */
    AcquireSRWLockShared(&g_cache_lock);
    if (g_cache[idx].pid == pid && now < g_cache[idx].expires) {
        const char *name = g_cache[idx].name;
        ReleaseSRWLockShared(&g_cache_lock);
        return name;
    }
    ReleaseSRWLockShared(&g_cache_lock);

    /* Cache miss — query system */
    char fullPath[MAX_PATH] = "";
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (hProc) {
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameA(hProc, 0, fullPath, &size)) {
            char *base = strrchr(fullPath, '\\');
            if (base) base++; else base = fullPath;
            strncpy(fullPath, base, sizeof(fullPath) - 1);
            fullPath[sizeof(fullPath) - 1] = '\0';
        }
        CloseHandle(hProc);
    }

    /* Write-lock update cache */
    AcquireSRWLockExclusive(&g_cache_lock);
    g_cache[idx].pid     = pid;
    strncpy(g_cache[idx].name, fullPath, MAX_PROC_NAME - 1);
    g_cache[idx].name[MAX_PROC_NAME - 1] = '\0';
    g_cache[idx].expires = now + PROC_CACHE_TTL;
    ReleaseSRWLockExclusive(&g_cache_lock);

    return g_cache[idx].name;
}

void nb_procname_clear(void)
{
    if (!g_initialized) return;
    AcquireSRWLockExclusive(&g_cache_lock);
    memset(g_cache, 0, sizeof(g_cache));
    ReleaseSRWLockExclusive(&g_cache_lock);
}
