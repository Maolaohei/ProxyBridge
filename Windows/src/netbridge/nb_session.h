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
 * Session key: (pid, src_port, dst_port, dst_addr) — O(1) hash lookup.
 * Read-heavy workload: SRWLOCK shared for lookups, exclusive for insert/remove.
 */

/* Initialize the session manager. */
void nb_session_init(void);

/* Set the packet injection callback (called from ProxyBridge.c at startup).
 * The callback signature is: BOOL inject(const void *packet, UINT packet_len) */
typedef BOOL (*NbPacketInjectFn)(const void *packet, unsigned int packet_len);
void nb_session_set_inject_fn(NbPacketInjectFn fn);

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

/* Cleanup idle sessions. DNS sessions (dst_port 53) use shorter timeout. */
void nb_session_cleanup(void);

/* Shutdown all sessions. */
void nb_session_shutdown(void);

#endif /* NB_SESSION_H */
