#ifndef NB_SESSION_H
#define NB_SESSION_H

#include <winsock2.h>
#include <stdint.h>

/*
 * UDP Session management for NetBridge protocol.
 *
 * Each intercepted UDP flow creates a session:
 *   - A loopback UDP socket bound to a random local port
 *   - NbUdpReqHeader sent with each packet to Core (127.0.0.1:35001)
 *   - NbUdpRespHeader received from Core, injected back via WinDivert
 *
 * Session key: the loopback socket's local port L (globally unique).
 * Core side uses clientAddr (127.0.0.1:L) as session identifier.
 */

/* Initialize the session manager. */
void nb_session_init(void);

/* Get or create a session for the given flow.
 * Returns the loopback socket to use for sending to Core.
 * On first call for a flow, creates socket, binds random port,
 * and starts the response receiver thread. */
SOCKET nb_session_get_or_create(
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port);

/* Send a UDP packet to Core via the session's loopback socket.
 * Wraps payload in NbUdpReqHeader. Returns 0 on success. */
int nb_session_send(
    SOCKET session_sock,
    uint32_t pid,
    const uint8_t *src_addr, uint16_t src_port, uint8_t src_addr_type,
    const uint8_t *dst_addr, uint16_t dst_port,
    const uint8_t *payload, uint16_t payload_len);

/* Cleanup sessions idle for more than 30s. Call periodically. */
void nb_session_cleanup(void);

/* Shutdown all sessions. */
void nb_session_shutdown(void);

#endif /* NB_SESSION_H */
