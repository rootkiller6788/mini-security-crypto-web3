#include "p2p_network.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifndef _WIN32
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#endif

#include <openssl/sha.h>
#include <openssl/rand.h>

uint64_t p2p_time_now(void) {
    return (uint64_t)time(NULL);
}

int p2p_generate_node_id(uint8_t node_id[P2P_NODE_ID_LEN]) {
    if (!node_id) return -1;
    return RAND_bytes(node_id, P2P_NODE_ID_LEN) == 1 ? 0 : -1;
}

int p2p_socket_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

void p2p_socket_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int p2p_socket_create(p2p_socket *sock) {
    if (!sock) return -1;
    *sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*sock == P2P_INVALID_SOCKET) return -1;
    return 0;
}

int p2p_socket_close(p2p_socket sock) {
    if (sock == P2P_INVALID_SOCKET) return -1;
#ifdef _WIN32
    return closesocket(sock) == 0 ? 0 : -1;
#else
    return close(sock) == 0 ? 0 : -1;
#endif
}

int p2p_socket_connect(p2p_socket sock, const char *ip, uint16_t port) {
    if (sock == P2P_INVALID_SOCKET || !ip) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) return -1;
#ifdef _WIN32
    int r = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
#else
    int r = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
#endif
    return r == 0 ? 0 : -1;
}

int p2p_socket_bind(p2p_socket sock, uint16_t port) {
    if (sock == P2P_INVALID_SOCKET) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    int opt = 1;
#ifdef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    return bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0 ? 0 : -1;
}

int p2p_socket_listen(p2p_socket sock, int backlog) {
    if (sock == P2P_INVALID_SOCKET) return -1;
    return listen(sock, backlog) == 0 ? 0 : -1;
}

int p2p_socket_accept(p2p_socket listen_sock, p2p_socket *client, char ip[P2P_IP_STR_LEN], uint16_t *port) {
    if (listen_sock == P2P_INVALID_SOCKET || !client || !ip || !port) return -1;
    struct sockaddr_in addr;
    p2p_socklen_t addrlen = sizeof(addr);
    *client = accept(listen_sock, (struct sockaddr *)&addr, &addrlen);
    if (*client == P2P_INVALID_SOCKET) return -1;
    inet_ntop(AF_INET, &addr.sin_addr, ip, P2P_IP_STR_LEN);
    *port = ntohs(addr.sin_port);
    return 0;
}

int p2p_socket_send(p2p_socket sock, const uint8_t *data, size_t len) {
    if (sock == P2P_INVALID_SOCKET || !data) return -1;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, (const char *)(data + sent), (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int p2p_socket_recv(p2p_socket sock, uint8_t *buf, size_t bufsz, size_t *received) {
    if (sock == P2P_INVALID_SOCKET || !buf || !received) return -1;
    ssize_t n = recv(sock, (char *)buf, (int)bufsz, 0);
    if (n <= 0) { *received = 0; return -1; }
    *received = (size_t)n;
    return 0;
}

int p2p_socket_flush(p2p_socket sock) {
    (void)sock;
    return 0;
}

int p2p_socket_set_timeout(p2p_socket sock, int seconds) {
    if (sock == P2P_INVALID_SOCKET) return -1;
#ifdef _WIN32
    DWORD tv = (DWORD)(seconds * 1000);
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv)) != 0) return -1;
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) return -1;
#endif
    return 0;
}

int p2p_peer_init(p2p_peer *peer, const char *ip, uint16_t port) {
    if (!peer || !ip) return -1;
    memset(peer, 0, sizeof(p2p_peer));
    strncpy(peer->ip, ip, P2P_IP_STR_LEN - 1);
    peer->port = port;
    peer->sock = P2P_INVALID_SOCKET;
    peer->last_seen = 0;
    peer->first_seen = p2p_time_now();
    peer->score = 0;
    peer->banned = 0;
    peer->connected = 0;
    return 0;
}

void p2p_peer_close(p2p_peer *peer) {
    if (!peer) return;
    if (peer->sock != P2P_INVALID_SOCKET) {
        p2p_socket_close(peer->sock);
        peer->sock = P2P_INVALID_SOCKET;
    }
    peer->connected = 0;
}

int p2p_peer_connect(p2p_peer *peer) {
    if (!peer) return -1;
    if (p2p_socket_create(&peer->sock) != 0) return -1;
    if (p2p_socket_connect(peer->sock, peer->ip, peer->port) != 0) {
        p2p_socket_close(peer->sock);
        peer->sock = P2P_INVALID_SOCKET;
        return -1;
    }
    p2p_socket_set_timeout(peer->sock, 30);
    peer->connected = 1;
    peer->last_seen = p2p_time_now();
    return 0;
}

int p2p_peer_send(p2p_peer *peer, const uint8_t *data, size_t len) {
    if (!peer || !data) return -1;
    if (peer->sock == P2P_INVALID_SOCKET) return -1;
    int r = p2p_socket_send(peer->sock, data, len);
    if (r == 0) peer->last_seen = p2p_time_now();
    return r;
}

int p2p_peer_recv(p2p_peer *peer, uint8_t *buf, size_t bufsz, size_t *received) {
    if (!peer || !buf || !received) return -1;
    if (peer->sock == P2P_INVALID_SOCKET) return -1;
    int r = p2p_socket_recv(peer->sock, buf, bufsz, received);
    if (r == 0) peer->last_seen = p2p_time_now();
    return r;
}

int p2p_peer_score_add(p2p_peer *peer, int64_t delta) {
    if (!peer) return -1;
    peer->score += delta;
    return 0;
}

int p2p_peer_ban(p2p_peer *peer) {
    if (!peer) return -1;
    peer->banned = 1;
    peer->score = -1000;
    p2p_peer_close(peer);
    return 0;
}

int p2p_peer_is_banned(const p2p_peer *peer, int *banned) {
    if (!peer || !banned) return -1;
    *banned = peer->banned;
    return 0;
}

int p2p_pm_init(p2p_peer_manager *pm, uint16_t port) {
    if (!pm) return -1;
    memset(pm, 0, sizeof(p2p_peer_manager));
    pm->port = port;
    pm->listen_sock = P2P_INVALID_SOCKET;
    pm->listening = 0;
    pm->running = 0;
    return 0;
}

void p2p_pm_free(p2p_peer_manager *pm) {
    if (!pm) return;
    p2p_pm_stop(pm);
    for (size_t i = 0; i < pm->count; i++) {
        p2p_peer_close(&pm->peers[i]);
    }
    memset(pm, 0, sizeof(p2p_peer_manager));
}

int p2p_pm_start(p2p_peer_manager *pm) {
    if (!pm) return -1;
    if (p2p_socket_create(&pm->listen_sock) != 0) return -1;
    if (p2p_socket_bind(pm->listen_sock, pm->port) != 0) {
        p2p_socket_close(pm->listen_sock);
        pm->listen_sock = P2P_INVALID_SOCKET;
        return -1;
    }
    if (p2p_socket_listen(pm->listen_sock, 5) != 0) {
        p2p_socket_close(pm->listen_sock);
        pm->listen_sock = P2P_INVALID_SOCKET;
        return -1;
    }
    pm->listening = 1;
    pm->running = 1;
    return 0;
}

int p2p_pm_stop(p2p_peer_manager *pm) {
    if (!pm) return -1;
    pm->running = 0;
    if (pm->listen_sock != P2P_INVALID_SOCKET) {
        p2p_socket_close(pm->listen_sock);
        pm->listen_sock = P2P_INVALID_SOCKET;
    }
    pm->listening = 0;
    for (size_t i = 0; i < pm->count; i++) {
        p2p_peer_close(&pm->peers[i]);
    }
    return 0;
}

int p2p_pm_add_peer(p2p_peer_manager *pm, const char *ip, uint16_t port) {
    if (!pm || !ip) return -1;
    if (pm->count >= P2P_MAX_PEERS) {
        for (size_t i = 0; i < pm->count; i++) {
            if (!pm->peers[i].connected) {
                p2p_peer_close(&pm->peers[i]);
                return p2p_peer_init(&pm->peers[i], ip, port);
            }
        }
        return -1;
    }
    p2p_peer *peer = &pm->peers[pm->count];
    if (p2p_peer_init(peer, ip, port) != 0) return -1;
    if (p2p_peer_connect(peer) != 0) {
        p2p_peer_close(peer);
        return -1;
    }
    pm->count++;
    return 0;
}

int p2p_pm_remove_peer(p2p_peer_manager *pm, p2p_socket sock) {
    if (!pm || sock == P2P_INVALID_SOCKET) return -1;
    for (size_t i = 0; i < pm->count; i++) {
        if (pm->peers[i].sock == sock) {
            p2p_peer_close(&pm->peers[i]);
            if (i < pm->count - 1) {
                memmove(&pm->peers[i], &pm->peers[i + 1], (pm->count - i - 1) * sizeof(p2p_peer));
            }
            pm->count--;
            return 0;
        }
    }
    return -1;
}

int p2p_pm_find_peer(p2p_peer_manager *pm, const char *ip, uint16_t port, p2p_peer **peer) {
    if (!pm || !ip || !peer) return -1;
    for (size_t i = 0; i < pm->count; i++) {
        if (strcmp(pm->peers[i].ip, ip) == 0 && pm->peers[i].port == port) {
            *peer = &pm->peers[i];
            return 0;
        }
    }
    *peer = NULL;
    return -1;
}

int p2p_pm_accept(p2p_peer_manager *pm) {
    if (!pm || !pm->listening) return -1;
    char ip[P2P_IP_STR_LEN];
    uint16_t port;
    p2p_socket client;
    if (p2p_socket_accept(pm->listen_sock, &client, ip, &port) != 0) return -1;
    if (pm->count >= P2P_MAX_PEERS) {
        p2p_socket_close(client);
        return -1;
    }
    p2p_peer *peer = &pm->peers[pm->count];
    memset(peer, 0, sizeof(p2p_peer));
    strncpy(peer->ip, ip, P2P_IP_STR_LEN - 1);
    peer->port = port;
    peer->sock = client;
    peer->connected = 1;
    peer->last_seen = p2p_time_now();
    peer->first_seen = p2p_time_now();
    p2p_socket_set_timeout(peer->sock, 30);
    pm->count++;
    return 0;
}

int p2p_pm_send_all(p2p_peer_manager *pm, const uint8_t *data, size_t len) {
    if (!pm || !data) return -1;
    for (size_t i = 0; i < pm->count; i++) {
        if (pm->peers[i].connected && !pm->peers[i].banned) {
            p2p_peer_send(&pm->peers[i], data, len);
        }
    }
    return 0;
}

int p2p_pm_send_to(p2p_peer_manager *pm, const uint8_t *data, size_t len,
                    const uint8_t *exclude_id) {
    if (!pm || !data) return -1;
    for (size_t i = 0; i < pm->count; i++) {
        if (pm->peers[i].connected && !pm->peers[i].banned) {
            if (exclude_id && memcmp(pm->peers[i].id, exclude_id, P2P_NODE_ID_LEN) == 0) continue;
            p2p_peer_send(&pm->peers[i], data, len);
        }
    }
    return 0;
}

int p2p_pm_count(p2p_peer_manager *pm, size_t *count) {
    if (!pm || !count) return -1;
    *count = pm->count;
    return 0;
}

int p2p_handshake_create(p2p_peer_manager *pm, uint8_t *buf, size_t *len, size_t bufsz) {
    if (!pm || !buf || !len || bufsz < P2P_HANDSHAKE_SIZE) return -1;
    memset(buf, 0, bufsz);
    uint32_t version = P2P_PROTOCOL_VERSION;
    uint64_t services = 1;
    int64_t timestamp = (int64_t)p2p_time_now();
    size_t off = 0;
    memcpy(buf + off, &version, 4); off += 4;
    memcpy(buf + off, &services, 8); off += 8;
    memcpy(buf + off, &timestamp, 8); off += 8;
    memset(buf + off, 0, 26); off += 26;
    memset(buf + off, 0xFF, 16); off += 16;
    uint16_t port_be = htons(pm->port);
    memcpy(buf + off, &port_be, 2); off += 2;
    *len = off;
    return 0;
}

int p2p_handshake_parse(const uint8_t *buf, size_t len, int *valid) {
    if (!buf || !valid || len < 20) return -1;
    *valid = 0;
    uint32_t version;
    memcpy(&version, buf, 4);
    if (version >= 70001) *valid = 1;
    return 0;
}

int p2p_handshake_do(p2p_peer *peer, p2p_peer_manager *pm, int *ok) {
    if (!peer || !pm || !ok) return -1;
    *ok = 0;
    uint8_t buf[P2P_HANDSHAKE_SIZE];
    size_t len = 0;
    if (p2p_handshake_create(pm, buf, &len, sizeof(buf)) != 0) return -1;
    if (p2p_peer_send(peer, buf, len) != 0) return -1;
    size_t received = 0;
    if (p2p_peer_recv(peer, buf, sizeof(buf), &received) != 0) return -1;
    int valid = 0;
    if (p2p_handshake_parse(buf, received, &valid) != 0) return -1;
    *ok = valid;
    return 0;
}

int p2p_msg_create(p2p_msg_type cmd, const uint8_t *payload, uint32_t len, p2p_message *msg) {
    if (!msg) return -1;
    memset(msg, 0, sizeof(p2p_message));
    msg->magic = 0xD9B4BEF9;
    msg->command = cmd;
    msg->length = len;
    if (payload && len > 0) {
        msg->payload = malloc(len);
        if (!msg->payload) return -1;
        memcpy(msg->payload, payload, len);
        SHA256_CTX ctx;
        uint8_t hash[32];
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, payload, len);
        SHA256_Final(hash, &ctx);
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, hash, 32);
        SHA256_Final(hash, &ctx);
        memcpy(msg->checksum, hash, 4);
    }
    return 0;
}

void p2p_msg_free(p2p_message *msg) {
    if (!msg) return;
    free(msg->payload);
    memset(msg, 0, sizeof(p2p_message));
}

int p2p_msg_send(p2p_peer *peer, const p2p_message *msg) {
    if (!peer || !msg) return -1;
    uint8_t buf[4096];
    size_t len = 0;
    if (p2p_msg_serialize(msg, buf, &len, sizeof(buf)) != 0) return -1;
    return p2p_peer_send(peer, buf, len);
}

int p2p_msg_recv(p2p_peer *peer, p2p_message *msg) {
    if (!peer || !msg) return -1;
    uint8_t buf[4096];
    size_t received = 0;
    if (p2p_peer_recv(peer, buf, sizeof(buf), &received) != 0) return -1;
    if (received < 24) return -1;
    return p2p_msg_deserialize(msg, buf, received);
}

int p2p_msg_serialize(const p2p_message *msg, uint8_t *buf, size_t *len, size_t bufsz) {
    if (!msg || !buf || !len || bufsz < 24 + msg->length) return -1;
    size_t off = 0;
    memcpy(buf + off, &msg->magic, 4); off += 4;
    uint32_t cmd = (uint32_t)msg->command;
    memcpy(buf + off, &cmd, 4); off += 4;
    memcpy(buf + off, &msg->length, 4); off += 4;
    memcpy(buf + off, msg->checksum, 4); off += 4;
    if (msg->payload && msg->length > 0) {
        memcpy(buf + off, msg->payload, msg->length);
        off += msg->length;
    }
    *len = off;
    return 0;
}

int p2p_msg_deserialize(p2p_message *msg, const uint8_t *buf, size_t len) {
    if (!msg || !buf || len < 24) return -1;
    memset(msg, 0, sizeof(p2p_message));
    size_t off = 0;
    memcpy(&msg->magic, buf + off, 4); off += 4;
    uint32_t cmd;
    memcpy(&cmd, buf + off, 4); off += 4;
    msg->command = (p2p_msg_type)cmd;
    memcpy(&msg->length, buf + off, 4); off += 4;
    memcpy(msg->checksum, buf + off, 4); off += 4;
    if (msg->length > 0 && off + msg->length <= len) {
        msg->payload = malloc(msg->length);
        if (!msg->payload) return -1;
        memcpy(msg->payload, buf + off, msg->length);
    }
    return 0;
}

int p2p_broadcast_tx(p2p_peer_manager *pm, const uint8_t *tx_data, size_t tx_len,
                      const uint8_t txid[32]) {
    if (!pm || !tx_data || !txid) return -1;
    p2p_inv_item item;
    p2p_inv_create(P2P_INV_TX, txid, &item);
    p2p_inv_broadcast(pm, P2P_INV_TX, txid);
    return 0;
}

int p2p_broadcast_block(p2p_peer_manager *pm, const uint8_t *block_data, size_t block_len,
                         const uint8_t block_hash[32]) {
    if (!pm || !block_data || !block_hash) return -1;
    p2p_inv_broadcast(pm, P2P_INV_BLOCK, block_hash);
    return 0;
}

int p2p_inv_create(p2p_inv_type type, const uint8_t hash[32], p2p_inv_item *item) {
    if (!hash || !item) return -1;
    item->type = (uint32_t)type;
    memcpy(item->hash, hash, 32);
    return 0;
}

int p2p_inv_broadcast(p2p_peer_manager *pm, p2p_inv_type type, const uint8_t hash[32]) {
    if (!pm || !hash) return -1;
    uint8_t payload[37];
    payload[0] = 1;
    uint32_t t = (uint32_t)type;
    memcpy(payload + 1, &t, 4);
    memcpy(payload + 5, hash, 32);
    p2p_message msg;
    if (p2p_msg_create(P2P_MSG_INV, payload, 37, &msg) != 0) return -1;
    p2p_pm_send_all(pm, payload, 37);
    p2p_msg_free(&msg);
    return 0;
}

int p2p_inv_getdata(p2p_peer_manager *pm, p2p_inv_type type, const uint8_t hash[32]) {
    if (!pm || !hash) return -1;
    uint8_t payload[37];
    payload[0] = 1;
    uint32_t t = (uint32_t)type;
    memcpy(payload + 1, &t, 4);
    memcpy(payload + 5, hash, 32);
    p2p_message msg;
    if (p2p_msg_create(P2P_MSG_GETDATA, payload, 37, &msg) != 0) return -1;
    p2p_pm_send_all(pm, payload, 37);
    p2p_msg_free(&msg);
    return 0;
}

int p2p_kad_init(p2p_kad_table *table) {
    if (!table) return -1;
    memset(table, 0, sizeof(p2p_kad_table));
    p2p_generate_node_id(table->node_id);
    table->total_peers = 0;
    return 0;
}

int p2p_kad_add_peer(p2p_kad_table *table, const p2p_peer *peer) {
    if (!table || !peer) return -1;
    uint8_t dist[P2P_NODE_ID_LEN];
    p2p_kad_distance(table->node_id, peer->id, dist);
    int bucket_idx = 0;
    for (int i = 0; i < P2P_NODE_ID_LEN * 8; i++) {
        if (dist[i / 8] & (1 << (7 - (i % 8)))) { bucket_idx = i; break; }
    }
    if (bucket_idx >= P2P_KAD_BUCKETS) bucket_idx = P2P_KAD_BUCKETS - 1;
    p2p_kad_bucket *bucket = &table->buckets[bucket_idx];
    if (bucket->count < P2P_KAD_BUCKET_SIZE) {
        memcpy(&bucket->peers[bucket->count], peer, sizeof(p2p_peer));
        bucket->count++;
        table->total_peers++;
    }
    return 0;
}

int p2p_kad_find_peers(p2p_kad_table *table, const uint8_t target_id[P2P_NODE_ID_LEN],
                        p2p_peer *results, size_t *count, size_t max_results) {
    if (!table || !target_id || !results || !count) return -1;
    *count = 0;
    uint8_t dist[P2P_NODE_ID_LEN];
    p2p_kad_distance(table->node_id, target_id, dist);
    int bucket_idx = 0;
    for (int i = 0; i < P2P_NODE_ID_LEN * 8; i++) {
        if (dist[i / 8] & (1 << (7 - (i % 8)))) { bucket_idx = i; break; }
    }
    for (int i = 0; i < P2P_KAD_BUCKETS && *count < max_results; i++) {
        int idx = bucket_idx - i;
        if (idx < 0) break;
        p2p_kad_bucket *bucket = &table->buckets[idx];
        for (size_t j = 0; j < bucket->count && *count < max_results; j++) {
            memcpy(&results[*count], &bucket->peers[j], sizeof(p2p_peer));
            (*count)++;
        }
    }
    return 0;
}

int p2p_kad_distance(const uint8_t a[P2P_NODE_ID_LEN],
                      const uint8_t b[P2P_NODE_ID_LEN], uint8_t dist[P2P_NODE_ID_LEN]) {
    if (!a || !b || !dist) return -1;
    for (int i = 0; i < P2P_NODE_ID_LEN; i++) {
        dist[i] = a[i] ^ b[i];
    }
    return 0;
}

int p2p_bootstrap_init(p2p_bootstrap *bs) {
    if (!bs) return -1;
    memset(bs, 0, sizeof(p2p_bootstrap));
    static const char *default_seeds[] = {
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
    };
    static const int default_seed_count = 4;
    for (int i = 0; i < default_seed_count && i < P2P_MAX_DNS_SEEDS; i++) {
        strncpy(bs->seeds[i].host, default_seeds[i], 255);
        bs->seeds[i].port = P2P_DEFAULT_PORT;
        bs->seeds[i].used = 0;
        bs->dns_seed_count++;
    }
    return 0;
}

int p2p_bootstrap_add_seed(p2p_bootstrap *bs, const char *host, uint16_t port) {
    if (!bs || !host) return -1;
    if (bs->dns_seed_count >= P2P_MAX_DNS_SEEDS) return -1;
    p2p_dns_seed *seed = &bs->seeds[bs->dns_seed_count];
    strncpy(seed->host, host, 255);
    seed->port = port;
    seed->used = 0;
    bs->dns_seed_count++;
    return 0;
}

int p2p_bootstrap_add_fixed(p2p_bootstrap *bs, const char *ip, uint16_t port) {
    if (!bs || !ip) return -1;
    if (bs->fixed_node_count >= P2P_MAX_SEEDS) return -1;
    p2p_peer *node = &bs->fixed_nodes[bs->fixed_node_count];
    memset(node, 0, sizeof(p2p_peer));
    strncpy(node->ip, ip, P2P_IP_STR_LEN - 1);
    node->port = port;
    bs->fixed_node_count++;
    return 0;
}

int p2p_bootstrap_resolve(p2p_bootstrap *bs, p2p_peer_manager *pm) {
    if (!bs || !pm) return -1;
    int added = 0;
    for (size_t i = 0; i < bs->fixed_node_count; i++) {
        p2p_peer *node = &bs->fixed_nodes[i];
        if (p2p_pm_add_peer(pm, node->ip, node->port) == 0) added++;
    }
    for (size_t i = 0; i < bs->dns_seed_count; i++) {
        p2p_dns_seed *seed = &bs->seeds[i];
        if (seed->used) continue;
        struct hostent *he = gethostbyname(seed->host);
        if (!he) continue;
        for (int j = 0; he->h_addr_list[j] != NULL; j++) {
            struct in_addr addr;
            memcpy(&addr, he->h_addr_list[j], sizeof(addr));
            char ip[P2P_IP_STR_LEN];
            inet_ntop(AF_INET, &addr, ip, P2P_IP_STR_LEN);
            if (p2p_pm_add_peer(pm, ip, seed->port) == 0) added++;
            if (added >= 8) break;
        }
        seed->used = 1;
    }
    return added > 0 ? 0 : -1;
}
