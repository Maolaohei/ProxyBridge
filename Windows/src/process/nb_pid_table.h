#ifndef NB_PID_TABLE_H
#define NB_PID_TABLE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void nb_pid_table_init(void);
void nb_pid_table_shutdown(void);

/* Snapshot-backed PID lookup. Returns 0 if unknown. */
DWORD nb_pid_lookup_tcp4(UINT32 src_ip, UINT16 src_port);
DWORD nb_pid_lookup_udp4(UINT32 src_ip, UINT16 src_port);
DWORD nb_pid_lookup_tcp6(const UINT8 src_ip6[16], UINT16 src_port);
DWORD nb_pid_lookup_udp6(const UINT8 src_ip6[16], UINT16 src_port);

#ifdef __cplusplus
}
#endif

#endif /* NB_PID_TABLE_H */
