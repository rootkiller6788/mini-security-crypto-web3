#ifndef P2P_NETWORK_H
#define P2P_NETWORK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET p2p_socket;
#define P2P_INVALID_SOCKET INVALID_SOCKET
#define P2P_SOCKET_ERROR   SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
typedef int p2p_socket;
#define P2P_INVALID_SOCKET (-1)
#define P2P_SOCKET_ERROR   (-1)
#endif

#define P2P_MAX_PEERS            125
#define P2P_MAX_SEEDS            32
#define P2P_MAX_DNS_SEEDS        16
#define P2P_NODE_ID_LEN          32
#define P2P_IP_STR_LEN           46
#define P2P_DEFAULT_PORT         8333
#define P2P_HANDSHAKE_SIZE       256
#define P2P_MAX_MESSAGE_SIZE     (2 * 1024 * 1024)
#define P2P_KAD_BUCKETS          256
#define P2P_KAD_BUCKET_SIZE      20
#define P2P_PROTOCOL_VERSION     70015

typedef enum {
    P2P_MSG_VERSION      = 0x01,
    P2P_MSG_VERACK       = 0x02,
    P2P_MSG_PING         = 0x03,
    P2P_MSG_PONG         = 0x04,
    P2P_MSG_GETADDR      = 0x05,
    P2P_MSG_ADDR         = 0x06,
    P2P_MSG_INV          = 0x07,
    P2P_MSG_GETDATA      = 0x08,
    P2P_MSG_TX           = 0x09,
    P2P_MSG_BLOCK        = 0x0A,
    P2P_MSG_GETBLOCKS    = 0x0B,
    P2P_MSG_GETHEADERS   = 0x0C,
    P2P_MSG_HEADERS      = 0x0D,
    P2P_MSG_MEMPOOL      = 0x0E,
    P2P_MSG_NOTFOUND     = 0x0F,
    P2P_MSG_REJECT       = 0x10,
    P2P_MSG_FEEFILTER    = 0x11,
    P2P_MSG_SENDHEADERS  = 0x12,
} p2p_msg_type;

typedef enum {
    P2P_INV_ERROR   = 0,
    P2P_INV_TX      = 1,
    P2P_INV_BLOCK   = 2,
    P2P_INV_FILTERED_BLOCK = 3,
    P2P_INV_CMPCT_BLOCK    = 4,
} p2p_inv_type;

typedef struct {
    uint32_t type;
    uint8_t  hash[32];
} p2p_inv_item;

typedef struct {
    uint8_t  id[P2P_NODE_ID_LEN];
    char     ip[P2P_IP_STR_LEN];
    uint16_t port;
    uint64_t last_seen;
    uint64_t first_seen;
    int64_t  score;
    int      banned;
    int      connected;
    p2p_socket sock;
} p2p_peer;

typedef struct {
    p2p_peer peers[P2P_MAX_PEERS];
    size_t   count;
    p2p_socket listen_sock;
    int       listening;
    uint16_t  port;
    int       running;
} p2p_peer_manager;

typedef struct {
    p2p_peer peers[P2P_KAD_BUCKET_SIZE];
    size_t   count;
} p2p_kad_bucket;

typedef struct {
    p2p_kad_bucket buckets[P2P_KAD_BUCKETS];
    uint8_t         node_id[P2P_NODE_ID_LEN];
    size_t          total_peers;
} p2p_kad_table;

typedef struct {
    char     host[256];
    uint16_t port;
    int      used;
} p2p_dns_seed;

typedef struct {
    p2p_dns_seed seeds[P2P_MAX_DNS_SEEDS];
    p2p_peer     fixed_nodes[P2P_MAX_SEEDS];
    size_t       dns_seed_count;
    size_t       fixed_node_count;
} p2p_bootstrap;

typedef struct {
    uint32_t magic;
    p2p_msg_type command;
    uint32_t length;
    uint8_t  checksum[4];
    uint8_t *payload;
} p2p_message;

int  p2p_socket_init(void);
void p2p_socket_cleanup(void);
int  p2p_socket_create(p2p_socket *sock);
int  p2p_socket_close(p2p_socket sock);
int  p2p_socket_connect(p2p_socket sock, const char *ip, uint16_t port);
int  p2p_socket_bind(p2p_socket sock, uint16_t port);
int  p2p_socket_listen(p2p_socket sock, int backlog);
int  p2p_socket_accept(p2p_socket listen_sock, p2p_socket *client, char ip[P2P_IP_STR_LEN], uint16_t *port);
int  p2p_socket_send(p2p_socket sock, const uint8_t *data, size_t len);
int  p2p_socket_recv(p2p_socket sock, uint8_t *buf, size_t bufsz, size_t *received);
int  p2p_socket_flush(p2p_socket sock);
int  p2p_socket_set_timeout(p2p_socket sock, int seconds);

int  p2p_peer_init(p2p_peer *peer, const char *ip, uint16_t port);
void p2p_peer_close(p2p_peer *peer);
int  p2p_peer_connect(p2p_peer *peer);
int  p2p_peer_send(p2p_peer *peer, const uint8_t *data, size_t len);
int  p2p_peer_recv(p2p_peer *peer, uint8_t *buf, size_t bufsz, size_t *received);
int  p2p_peer_score_add(p2p_peer *peer, int64_t delta);
int  p2p_peer_ban(p2p_peer *peer);
int  p2p_peer_is_banned(const p2p_peer *peer, int *banned);

int  p2p_pm_init(p2p_peer_manager *pm, uint16_t port);
void p2p_pm_free(p2p_peer_manager *pm);
int  p2p_pm_start(p2p_peer_manager *pm);
int  p2p_pm_stop(p2p_peer_manager *pm);
int  p2p_pm_add_peer(p2p_peer_manager *pm, const char *ip, uint16_t port);
int  p2p_pm_remove_peer(p2p_peer_manager *pm, p2p_socket sock);
int  p2p_pm_find_peer(p2p_peer_manager *pm, const char *ip, uint16_t port, p2p_peer **peer);
int  p2p_pm_accept(p2p_peer_manager *pm);
int  p2p_pm_send_all(p2p_peer_manager *pm, const uint8_t *data, size_t len);
int  p2p_pm_send_to(p2p_peer_manager *pm, const uint8_t *data, size_t len,
                    const uint8_t *exclude_id);
int  p2p_pm_count(p2p_peer_manager *pm, size_t *count);

int  p2p_handshake_create(p2p_peer_manager *pm, uint8_t *buf, size_t *len, size_t bufsz);
int  p2p_handshake_parse(const uint8_t *buf, size_t len, int *valid);
int  p2p_handshake_do(p2p_peer *peer, p2p_peer_manager *pm, int *ok);

int  p2p_msg_create(p2p_msg_type cmd, const uint8_t *payload, uint32_t len,
                    p2p_message *msg);
void p2p_msg_free(p2p_message *msg);
int  p2p_msg_send(p2p_peer *peer, const p2p_message *msg);
int  p2p_msg_recv(p2p_peer *peer, p2p_message *msg);
int  p2p_msg_serialize(const p2p_message *msg, uint8_t *buf, size_t *len, size_t bufsz);
int  p2p_msg_deserialize(p2p_message *msg, const uint8_t *buf, size_t len);

int  p2p_broadcast_tx(p2p_peer_manager *pm, const uint8_t *tx_data, size_t tx_len,
                      const uint8_t txid[32]);
int  p2p_broadcast_block(p2p_peer_manager *pm, const uint8_t *block_data, size_t block_len,
                         const uint8_t block_hash[32]);

int  p2p_inv_create(p2p_inv_type type, const uint8_t hash[32], p2p_inv_item *item);
int  p2p_inv_broadcast(p2p_peer_manager *pm, p2p_inv_type type, const uint8_t hash[32]);
int  p2p_inv_getdata(p2p_peer_manager *pm, p2p_inv_type type, const uint8_t hash[32]);

int  p2p_kad_init(p2p_kad_table *table);
int  p2p_kad_add_peer(p2p_kad_table *table, const p2p_peer *peer);
int  p2p_kad_find_peers(p2p_kad_table *table, const uint8_t target_id[P2P_NODE_ID_LEN],
                        p2p_peer *results, size_t *count, size_t max_results);
int  p2p_kad_distance(const uint8_t a[P2P_NODE_ID_LEN],
                      const uint8_t b[P2P_NODE_ID_LEN], uint8_t dist[P2P_NODE_ID_LEN]);

int  p2p_bootstrap_init(p2p_bootstrap *bs);
int  p2p_bootstrap_add_seed(p2p_bootstrap *bs, const char *host, uint16_t port);
int  p2p_bootstrap_add_fixed(p2p_bootstrap *bs, const char *ip, uint16_t port);
int  p2p_bootstrap_resolve(p2p_bootstrap *bs, p2p_peer_manager *pm);

int  p2p_generate_node_id(uint8_t node_id[P2P_NODE_ID_LEN]);

uint64_t p2p_time_now(void);

#ifdef __cplusplus
}
#endif

#endif
