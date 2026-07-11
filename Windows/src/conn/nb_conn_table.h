#ifndef NB_CONN_TABLE_H
#define NB_CONN_TABLE_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void nb_conn_init(void);
void nb_conn_clear_all(void);
void nb_conn_cleanup_stale(void); /* >60s idle */

void nb_conn_add(UINT16 src_port, UINT32 src_ip, UINT32 dest_ip, UINT16 dest_port, UINT32 proxy_config_id);
void nb_conn_add_v6(UINT16 src_port, const UINT8 src_ip6[16], const UINT8 dest_ip6[16], UINT16 dest_port, UINT32 proxy_config_id);
BOOL nb_conn_get(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port);
BOOL nb_conn_get_full(UINT16 src_port, UINT32 *dest_ip, UINT16 *dest_port, UINT32 *proxy_config_id);
BOOL nb_conn_get_full_v6(UINT16 src_port, UINT8 dest_ip6[16], UINT16 *dest_port, UINT32 *proxy_config_id);
UINT32 nb_conn_get_proxy_id(UINT16 src_port);
BOOL nb_conn_is_tracked(UINT16 src_port);
void nb_conn_remove(UINT16 src_port);
UINT32 nb_conn_count(void);

/* Reverse lookup for SOCKS5 UDP replies */
BOOL nb_conn_find_v4_udp_sender(UINT32 orig_dest_ip, UINT16 orig_dest_port, UINT32 *src_ip, UINT16 *src_port);
BOOL nb_conn_find_v6_udp_sender(const UINT8 orig_dest_ip6[16], UINT16 orig_dest_port, UINT8 src_ip6[16], UINT16 *src_port);

#ifdef __cplusplus
}
#endif

#endif /* NB_CONN_TABLE_H */
