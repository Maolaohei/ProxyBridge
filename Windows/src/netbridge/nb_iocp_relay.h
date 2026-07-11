#ifndef NB_IOCP_RELAY_H
#define NB_IOCP_RELAY_H

#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shared IOCP bidirectional relay used by NetBridge CoreDirect and Legacy SOCKS/HTTP. */
void nb_iocp_relay_init(void);
void nb_iocp_relay_shutdown(void);

/* Non-blocking: takes ownership of both sockets on success (caller must not close).
 * Returns 0 on success, -1 on failure (caller still owns sockets). */
int nb_iocp_relay_start(SOCKET a, SOCKET b);

#ifdef __cplusplus
}
#endif

#endif
