#ifndef NB_TCP_H
#define NB_TCP_H

#include <winsock2.h>
#include <stdint.h>

/*
 * TCP forwarding for NetBridge protocol.
 *
 * When a TCP connection matches a PROXY rule, instead of going through
 * the old SOCKS5 relay path, we:
 *   1. Connect to relay port (127.0.0.1:NB_RELAY_TCP_PORT)
 *   2. Send NbTcpHeader with original destination + PID + token
 *   3. Bidirectional relay between original socket and relay connection
 *
 * Connection pool: maintains N pre-established connections to relay
 * to avoid TCP handshake overhead per connection.
 */

/* Initialize the TCP pool. Must be called before nb_tcp_forward. */
void nb_tcp_pool_init(void);

/* Set the relay TCP port (default: NB_CORE_TCP_PORT).
 * Call before nb_tcp_forward to redirect traffic to NetBridgeBridge. */
void nb_tcp_set_relay_port(uint16_t port);

/* Forward a TCP connection through NetBridge.
 *   orig_sock   - the original client socket (from WinDivert redirect)
 *   dst_addr    - 16-byte original destination IP (IPv4: first 4 bytes)
 *   addr_type   - NB_ADDR_IPV4 or NB_ADDR_IPV6
 *   dst_port    - original destination port (host byte order)
 *   src_port    - original source port (host byte order)
 *   pid         - source process PID
 *   proc_name   - process name string (from nb_procname_get)
 *
 * Returns 0 on success, -1 on failure.
 * On success, spawns relay threads; caller must NOT use orig_sock after. */
int nb_tcp_forward(
    SOCKET orig_sock,
    const uint8_t *dst_addr, uint8_t addr_type,
    uint16_t dst_port, uint16_t src_port,
    uint32_t pid, const char *proc_name);

/* Cleanup idle pool connections. Call periodically. */
void nb_tcp_pool_cleanup(void);

/* Shutdown the pool (close all connections). */
void nb_tcp_pool_shutdown(void);

#endif /* NB_TCP_H */
