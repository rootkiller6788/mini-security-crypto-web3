#include "utxo_model.h"
#include "consensus_pow.h"
#include "p2p_network.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define WALLET_MAX_UTXOS 256
#define WALLET_MAX_ADDRS 16

typedef struct {
    uint8_t  pubkey[UTOX_MODEL_PUBKEY_LEN];
    uint8_t  privkey[32];
    char     address[UTOX_MODEL_ADDRESS_LEN];
    uint64_t balance;
} wallet_keypair;

typedef struct {
    wallet_keypair keys[WALLET_MAX_ADDRS];
    int            key_count;
    utxo_set       utxos;
    uint64_t       total_balance;
} wallet;

static int wallet_init(wallet *w, size_t utxo_capacity) {
    if (!w) return -1;
    memset(w, 0, sizeof(wallet));
    w->key_count = 0;
    w->total_balance = 0;
    return utxo_set_init(&w->utxos, utxo_capacity);
}

static void wallet_free(wallet *w) {
    if (!w) return;
    utxo_set_free(&w->utxos);
    memset(w, 0, sizeof(wallet));
}

static int wallet_generate_key(wallet *w) {
    if (!w || w->key_count >= WALLET_MAX_ADDRS) return -1;
    wallet_keypair *kp = &w->keys[w->key_count];
    for (int i = 0; i < UTOX_MODEL_PUBKEY_LEN; i++) {
        kp->pubkey[i] = (uint8_t)((rand() % 256));
    }
    kp->pubkey[0] = w->key_count % 2 ? 0x02 : 0x03;
    for (int i = 0; i < 32; i++) {
        kp->privkey[i] = (uint8_t)((rand() % 256));
    }
    int compressed = (kp->pubkey[0] == 0x02 || kp->pubkey[0] == 0x03) ? 1 : 0;
    utxo_pubkey_to_address(kp->pubkey, compressed, kp->address);
    kp->balance = 0;
    w->key_count++;
    return 0;
}

static wallet_keypair *wallet_find_address(wallet *w, const char *address) {
    if (!w || !address) return NULL;
    for (int i = 0; i < w->key_count; i++) {
        if (strcmp(w->keys[i].address, address) == 0) return &w->keys[i];
    }
    return NULL;
}

static int wallet_add_utxo(wallet *w, const uint8_t *txid, uint32_t vout,
                            uint64_t value, const char *address, uint32_t height) {
    if (!w || !txid || !address) return -1;
    wallet_keypair *kp = wallet_find_address(w, address);
    if (!kp) return -1;

    utxo_entry entry;
    memset(&entry, 0, sizeof(entry));
    memcpy(entry.txid, txid, UTOX_MODEL_TXID_LEN);
    entry.vout = vout;
    entry.value = value;
    entry.height = height;
    entry.spent = 0;
    memcpy(entry.scriptPubKey, address, UTOX_MODEL_SCRIPTPUB_MAX > 64 ? 64 : UTOX_MODEL_SCRIPTPUB_MAX);
    entry.scriptPubKey_len = (uint16_t)strlen(address);

    if (utxo_set_add(&w->utxos, &entry) != 0) return -1;
    kp->balance += value;
    w->total_balance += value;
    return 0;
}

static uint64_t wallet_get_balance(const wallet *w, const char *address) {
    if (!w || !address) return 0;
    wallet_keypair *kp = wallet_find_address((wallet *)w, address);
    return kp ? kp->balance : 0;
}

typedef struct {
    uint8_t  txid[UTOX_MODEL_TXID_LEN];
    uint8_t  from_addr[UTOX_MODEL_ADDRESS_LEN];
    uint8_t  to_addr[UTOX_MODEL_ADDRESS_LEN];
    uint64_t amount;
    uint64_t fee;
    uint32_t timestamp;
    int      confirmed;
} wallet_tx_record;

#define WALLET_MAX_HISTORY 128

typedef struct {
    wallet_tx_record entries[WALLET_MAX_HISTORY];
    int              count;
    wallet          *wallet_ref;
} wallet_history;

static void wallet_history_init(wallet_history *hist, wallet *w) {
    if (!hist || !w) return;
    memset(hist, 0, sizeof(wallet_history));
    hist->wallet_ref = w;
}

static int wallet_history_add(wallet_history *hist, const char *from, const char *to,
                               uint64_t amount, uint64_t fee, int confirmed) {
    if (!hist || !from || !to || hist->count >= WALLET_MAX_HISTORY) return -1;
    wallet_tx_record *rec = &hist->entries[hist->count];
    memset(rec, 0, sizeof(wallet_tx_record));
    for (int i = 0; i < UTOX_MODEL_TXID_LEN; i++) rec->txid[i] = (uint8_t)rand();
    strncpy(rec->from_addr, from, UTOX_MODEL_ADDRESS_LEN - 1);
    strncpy(rec->to_addr, to, UTOX_MODEL_ADDRESS_LEN - 1);
    rec->amount = amount;
    rec->fee = fee;
    rec->timestamp = (uint32_t)time(NULL);
    rec->confirmed = confirmed;
    hist->count++;
    return 0;
}

static void wallet_history_print(const wallet_history *hist) {
    if (!hist) return;
    printf("\n%-34s %-34s %-12s %-8s %s\n", "From", "To", "Amount", "Fee", "Status");
    printf("----------------------------------------------------------------------------------------\n");
    for (int i = 0; i < hist->count; i++) {
        const wallet_tx_record *r = &hist->entries[i];
        printf("%-34s %-34s %9llu %7llu %s\n",
               r->from_addr, r->to_addr,
               (unsigned long long)r->amount, (unsigned long long)r->fee,
               r->confirmed ? "Confirmed" : "Pending");
    }
}

int main(void) {
    printf("========================================\n");
    printf("  Mini Blockchain Wallet Demo\n");
    printf("========================================\n\n");

    srand((unsigned int)time(NULL));

    printf("--- Initializing Wallet ---\n\n");

    wallet my_wallet;
    wallet_init(&my_wallet, WALLET_MAX_UTXOS);

    for (int i = 0; i < 3; i++) {
        wallet_generate_key(&my_wallet);
        printf("Address %d: %s\n", i + 1, my_wallet.keys[i].address);
    }

    wallet_history history;
    wallet_history_init(&history, &my_wallet);

    printf("\n--- Receiving Funds (Coinbase + Transactions) ---\n\n");

    uint8_t cb_txid[UTOX_MODEL_TXID_LEN];
    for (int i = 0; i < UTOX_MODEL_TXID_LEN; i++) cb_txid[i] = (uint8_t)(0xAA + i);

    wallet_add_utxo(&my_wallet, cb_txid, 0, 5000000000ULL,
                    my_wallet.keys[0].address, 1);
    printf("+ 50.00000000 BTC mined to %s\n", my_wallet.keys[0].address);

    uint8_t tx1[UTOX_MODEL_TXID_LEN];
    for (int i = 0; i < UTOX_MODEL_TXID_LEN; i++) tx1[i] = (uint8_t)(0x10 + i);

    wallet_add_utxo(&my_wallet, tx1, 1, 2500000000ULL,
                    my_wallet.keys[0].address, 10);
    printf("+ 25.00000000 BTC received at %s\n", my_wallet.keys[0].address);

    wallet_add_utxo(&my_wallet, tx1, 0, 1000000000ULL,
                    my_wallet.keys[1].address, 10);
    printf("+ 10.00000000 BTC received at %s\n", my_wallet.keys[1].address);

    printf("\n--- Wallet Balance ---\n\n");
    printf("%-34s %12s\n", "Address", "Balance");
    printf("----------------------------------------------\n");
    for (int i = 0; i < my_wallet.key_count; i++) {
        double btc = (double)my_wallet.keys[i].balance / 100000000.0;
        printf("%-34s %10.8f BTC\n", my_wallet.keys[i].address, btc);
    }
    double total_btc = (double)my_wallet.total_balance / 100000000.0;
    printf("----------------------------------------------\n");
    printf("%-34s %10.8f BTC\n", "TOTAL", total_btc);

    printf("\n--- Creating a Transaction ---\n\n");

    const char *from_addr = my_wallet.keys[0].address;
    const char *to_addr = my_wallet.keys[2].address;
    uint64_t send_amount = 1500000000ULL;
    uint64_t fee = 100000ULL;

    printf("From: %s\n", from_addr);
    printf("To:   %s\n", to_addr);
    printf("Amount: %.8f BTC\n", (double)send_amount / 100000000.0);
    printf("Fee: %.8f BTC\n", (double)fee / 100000000.0);

    uint64_t balance = wallet_get_balance(&my_wallet, from_addr);
    printf("Available: %.8f BTC\n", (double)balance / 100000000.0);

    if (balance >= send_amount + fee) {
        utxo_entry *selected = NULL;
        size_t sel_count = 0;
        uint64_t sel_total = 0;
        uint64_t change = 0;

        int r = utxo_coin_selection(&my_wallet.utxos, send_amount + fee, 100,
                                     &selected, &sel_count, &sel_total, &change);
        if (r == 0) {
            printf("\nCoin selection: %zu UTXOs, total %.8f BTC + %.8f BTC change\n",
                   sel_count, (double)sel_total / 100000000.0,
                   (double)change / 100000000.0);

            for (size_t i = 0; i < sel_count; i++) {
                utxo_set_spend(&my_wallet.utxos, selected[i].txid, selected[i].vout);
                my_wallet.keys[0].balance -= selected[i].value;
                my_wallet.total_balance -= selected[i].value;
            }

            my_wallet.keys[2].balance += send_amount;
            my_wallet.total_balance += send_amount;

            if (change > 0) {
                my_wallet.keys[0].balance += change;
                my_wallet.total_balance += change;
            }

            wallet_history_add(&history, from_addr, to_addr, send_amount, fee, 0);

            printf("Transaction created successfully!\n");
        } else {
            printf("Coin selection failed\n");
        }
        free(selected);
    } else {
        printf("Insufficient balance!\n");
    }

    printf("\n--- Updated Balances ---\n\n");
    printf("%-34s %12s\n", "Address", "Balance");
    printf("----------------------------------------------\n");
    for (int i = 0; i < my_wallet.key_count; i++) {
        double btc = (double)my_wallet.keys[i].balance / 100000000.0;
        printf("%-34s %10.8f BTC\n", my_wallet.keys[i].address, btc);
    }
    total_btc = (double)my_wallet.total_balance / 100000000.0;
    printf("----------------------------------------------\n");
    printf("%-34s %10.8f BTC\n", "TOTAL", total_btc);

    printf("\n--- Transaction History ---\n");
    wallet_history_print(&history);

    printf("\n--- P2P Network Simulation ---\n\n");

    p2p_socket_init();

    p2p_peer_manager pm;
    p2p_pm_init(&pm, 8333);

    p2p_bootstrap bootstrap;
    p2p_bootstrap_init(&bootstrap);

    p2p_peer *fake_peers[] = { NULL, NULL, NULL };
    const char *peer_ips[] = { "192.168.1.100", "10.0.0.50", "172.16.0.200" };
    uint16_t peer_ports[] = { 8333, 8333, 8334 };

    for (int i = 0; i < 3; i++) {
        fake_peers[i] = malloc(sizeof(p2p_peer));
        p2p_peer_init(fake_peers[i], peer_ips[i], peer_ports[i]);
        p2p_generate_node_id(fake_peers[i]->id);

        if (pm.count < P2P_MAX_PEERS) {
            memcpy(&pm.peers[pm.count], fake_peers[i], sizeof(p2p_peer));
            pm.count++;
        }
        printf("Peer %d: %s:%u  score=%lld\n",
               i + 1, peer_ips[i], peer_ports[i], (long long)pm.peers[i].score);
    }

    p2p_peer_score_add(&pm.peers[0], 50);
    p2p_peer_score_add(&pm.peers[1], -20);
    p2p_peer_score_add(&pm.peers[2], 100);

    printf("\nAfter scoring:\n");
    for (size_t i = 0; i < pm.count; i++) {
        printf("  Peer %zu: score=%lld  banned=%d\n",
               i + 1, (long long)pm.peers[i].score, pm.peers[i].banned);
    }

    if (pm.peers[1].score < -10) {
        p2p_peer_ban(&pm.peers[1]);
        printf("  Peer 2 banned for misbehavior!\n");
    }

    printf("\n--- Kademlia DHT ---\n\n");

    p2p_kad_table kad;
    p2p_kad_init(&kad);

    for (size_t i = 0; i < pm.count; i++) {
        p2p_kad_add_peer(&kad, &pm.peers[i]);
    }
    printf("Kademlia table: %zu peers across %d buckets\n",
           kad.total_peers, P2P_KAD_BUCKETS);

    printf("\n--- Transaction Broadcasting ---\n\n");

    uint8_t sample_txid[32];
    for (int i = 0; i < 32; i++) sample_txid[i] = (uint8_t)rand();

    p2p_inv_broadcast(&pm, P2P_INV_TX, sample_txid);
    printf("INV message sent to %zu peers for tx: ", pm.count);
    for (int i = 0; i < 8; i++) printf("%02x", sample_txid[i]);
    printf("...\n");

    printf("\n--- MemPool Sync ---\n\n");

    p2p_message pool_msg;
    if (p2p_msg_create(P2P_MSG_MEMPOOL, NULL, 0, &pool_msg) == 0) {
        printf("MEMPOOL request message created (type=%u, size=%u)\n",
               (unsigned)pool_msg.command, pool_msg.length);
        p2p_msg_free(&pool_msg);
    }

    printf("\n========================================\n");
    printf("  Wallet Demo Complete!\n");
    printf("========================================\n");

    wallet_free(&my_wallet);
    p2p_pm_free(&pm);
    for (int i = 0; i < 3; i++) free(fake_peers[i]);
    p2p_socket_cleanup();

    return 0;
}
