#ifndef NB_PORT_DECISION_H
#define NB_PORT_DECISION_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Per-src-port decision cache with TTL to avoid stale DIRECT after port reuse. */
void nb_port_decision_init(void);
void nb_port_decision_clear_all(void);

BOOL nb_port_is_decided(UINT16 p);
BOOL nb_port_is_direct(UINT16 p);
void nb_port_set_direct(UINT16 p);
void nb_port_set_decided(UINT16 p); /* decided but not direct (proxy/block) */
void nb_port_clear(UINT16 p);

/* Expire aged decisions; call from cleanup worker. */
void nb_port_decision_expire(void);

#ifdef __cplusplus
}
#endif

#endif /* NB_PORT_DECISION_H */
