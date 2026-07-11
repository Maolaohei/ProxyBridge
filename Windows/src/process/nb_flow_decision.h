#ifndef NB_FLOW_DECISION_H
#define NB_FLOW_DECISION_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Flow decision: DIRECT / DECIDED(proxy|block). TTL-based invalidation. */
typedef enum {
    NB_FLOW_NONE = 0,
    NB_FLOW_DIRECT = 1,
    NB_FLOW_DECIDED = 2   /* proxy or block already handled for this flow */
} NbFlowDecision;

void nb_flow_decision_init(void);
void nb_flow_decision_clear_all(void);
void nb_flow_decision_expire(void);

/* IPv4 5-tuple (host byte order for ports; network order for IPs as UINT32 wire value). */
NbFlowDecision nb_flow_lookup_v4(UINT32 src_ip, UINT16 src_port,
                                 UINT32 dst_ip, UINT16 dst_port, UINT8 proto);
void nb_flow_set_v4(UINT32 src_ip, UINT16 src_port,
                    UINT32 dst_ip, UINT16 dst_port, UINT8 proto,
                    NbFlowDecision decision);
void nb_flow_clear_v4(UINT32 src_ip, UINT16 src_port,
                      UINT32 dst_ip, UINT16 dst_port, UINT8 proto);
/* Clear all flows using a local (src) port ? used on FIN/RST when full tuple unknown. */
void nb_flow_clear_src_port_v4(UINT16 src_port);

/* IPv6: key uses 16-byte addresses. */
NbFlowDecision nb_flow_lookup_v6(const UINT8 src_ip6[16], UINT16 src_port,
                                 const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto);
void nb_flow_set_v6(const UINT8 src_ip6[16], UINT16 src_port,
                    const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto,
                    NbFlowDecision decision);
void nb_flow_clear_v6(const UINT8 src_ip6[16], UINT16 src_port,
                      const UINT8 dst_ip6[16], UINT16 dst_port, UINT8 proto);
void nb_flow_clear_src_port_v6(UINT16 src_port);

/* Backward-compatible port-level API (src-port only, weaker than 5-tuple). */
void nb_port_decision_init(void);
void nb_port_decision_clear_all(void);
BOOL nb_port_is_decided(UINT16 p);
BOOL nb_port_is_direct(UINT16 p);
void nb_port_set_direct(UINT16 p);
void nb_port_set_decided(UINT16 p);
void nb_port_clear(UINT16 p);
void nb_port_decision_expire(void);

#ifdef __cplusplus
}
#endif

#endif /* NB_FLOW_DECISION_H */
