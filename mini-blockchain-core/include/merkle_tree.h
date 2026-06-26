#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MERKLE_HASH_LEN    32
#define MERKLE_MAX_CHILDREN 16
#define MERKLE_PROOF_MAX_DEPTH 64
#define MERKLE_TRIE_KEY_MAX    64

typedef struct {
    uint8_t hash[MERKLE_HASH_LEN];
} merkle_hash;

typedef struct merkle_node_s {
    merkle_hash           node_hash;
    struct merkle_node_s *left;
    struct merkle_node_s *right;
    struct merkle_node_s *parent;
    int                   is_leaf;
    uint8_t              *data;
    size_t                data_len;
} merkle_node;

typedef struct {
    merkle_node *root;
    size_t       leaf_count;
} merkle_tree;

typedef struct {
    merkle_hash path[MERKLE_PROOF_MAX_DEPTH];
    int         path_depth;
    int         directions[MERKLE_PROOF_MAX_DEPTH];
    merkle_hash leaf_hash;
    size_t      leaf_index;
} merkle_proof;

typedef struct patricia_node_s {
    uint8_t                   nibble_key[MERKLE_TRIE_KEY_MAX];
    int                       key_depth;
    merkle_hash               node_hash;
    uint8_t                  *value;
    size_t                    value_len;
    struct patricia_node_s   *children[MERKLE_MAX_CHILDREN];
    int                       child_count;
    struct patricia_node_s   *parent;
} patricia_node;

typedef struct {
    patricia_node *root;
    size_t         node_count;
} patricia_merkle_trie;

int  merkle_tree_init(merkle_tree *tree);
void merkle_tree_free(merkle_tree *tree);
int  merkle_tree_add_leaf(merkle_tree *tree, const uint8_t *data, size_t len);
int  merkle_tree_add_leaves(merkle_tree *tree, const uint8_t **data, const size_t *lens, size_t count);
int  merkle_tree_rebuild(merkle_tree *tree);
int  merkle_tree_get_root(const merkle_tree *tree, merkle_hash *root_hash);
int  merkle_tree_leaf_count(const merkle_tree *tree, size_t *count);
int  merkle_tree_get_leaf(const merkle_tree *tree, size_t index, uint8_t **data, size_t *len);

int  merkle_proof_generate(const merkle_tree *tree, size_t leaf_index, merkle_proof *proof);
int  merkle_proof_verify(const merkle_hash *root_hash, const merkle_proof *proof, int *valid);
void merkle_proof_free(merkle_proof *proof);

int  merkle_tree_compare_roots(const merkle_tree *a, const merkle_tree *b, int *equal);

void merkle_sha256(const uint8_t *data, size_t len, uint8_t out[MERKLE_HASH_LEN]);
void merkle_sha256d(const uint8_t *data, size_t len, uint8_t out[MERKLE_HASH_LEN]);

int  patricia_trie_init(patricia_merkle_trie *trie);
void patricia_trie_free(patricia_merkle_trie *trie);
int  patricia_trie_insert(patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                          const uint8_t *value, size_t value_len);
int  patricia_trie_lookup(const patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                          uint8_t **value, size_t *value_len);
int  patricia_trie_delete(patricia_merkle_trie *trie, const uint8_t *key, size_t key_len);
int  patricia_trie_get_root_hash(const patricia_merkle_trie *trie, merkle_hash *root_hash);
int  patricia_trie_rehash(patricia_merkle_trie *trie);
int  patricia_trie_prove(const patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                         merkle_proof *proof);
int  patricia_trie_verify_proof(const merkle_hash *root_hash, const uint8_t *key, size_t key_len,
                                const uint8_t *value, size_t value_len,
                                const merkle_proof *proof, int *valid);

#ifdef __cplusplus
}
#endif

#endif
