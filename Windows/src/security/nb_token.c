#include "nb_token.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

static uint32_t g_nb_token = 0;

int nb_token_init(void)
{
    const int max_retry = 20;  /* 20 * 500ms = 10s */
    for (int i = 0; i < max_retry; i++) {
        HANDLE hMap = OpenFileMappingA(
            FILE_MAP_READ, FALSE, "Local\\BrayNBToken");
        if (hMap) {
            LPVOID pView = MapViewOfFile(
                hMap, FILE_MAP_READ, 0, 0, sizeof(uint32_t));
            if (pView) {
                memcpy(&g_nb_token, pView, sizeof(uint32_t));
                UnmapViewOfFile(pView);
                CloseHandle(hMap);
                return 0;
            }
            CloseHandle(hMap);
        }
        Sleep(500);
    }
    fprintf(stderr, "[NetBridge] Cannot read token after 10s, abort.\n");
    return -1;
}

uint32_t nb_token_get(void) { return g_nb_token; }
