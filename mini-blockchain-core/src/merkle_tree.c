#include "merkle_tree.h"
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

void merkle_sha256(const uint8_t *data, size_t len, uint8_t out[MERKLE_HASH_LEN]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void merkle_sha256d(const uint8_t *data, size_t len, uint8_t out[MERKLE_HASH_LEN]) {
    uint8_t tmp[MERKLE_HASH_LEN];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(tmp, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, tmp, MERKLE_HASH_LEN);
    SHA256_Final(out, &ctx);
}

static merkle_node *merkle_node_create(const uint8_t *data, size_t len, int is_leaf) {
    merkle_node *node = calloc(1, sizeof(merkle_node));
    if (!node) return NULL;
    node->is_leaf = is_leaf;
    if (data && len > 0) {
        node->data = malloc(len);
        if (!node->data) { free(node); return NULL; }
        memcpy(node->data, data, len);
        node->data_len = len;
        merkle_sha256d(data, len, node->node_hash.hash);
    }
    return node;
}

static void merkle_node_free_recursive(merkle_node *node) {
    if (!node) return;
    merkle_node_free_recursive(node->left);
    merkle_node_free_recursive(node->right);
    free(node->data);
    free(node);
}

static void merkle_node_compute_hash(merkle_node *node) {
    if (!node || node->is_leaf) return;
    uint8_t combined[MERKLE_HASH_LEN * 2];
    if (node->left) memcpy(combined, node->left->node_hash.hash, MERKLE_HASH_LEN);
    else memset(combined, 0, MERKLE_HASH_LEN);
    if (node->right) memcpy(combined + MERKLE_HASH_LEN, node->right->node_hash.hash, MERKLE_HASH_LEN);
    else memset(combined + MERKLE_HASH_LEN, 0, MERKLE_HASH_LEN);
    merkle_sha256d(combined, sizeof(combined), node->node_hash.hash);
}

int merkle_tree_init(merkle_tree *tree) {
    if (!tree) return -1;
    tree->root = NULL;
    tree->leaf_count = 0;
    return 0;
}

void merkle_tree_free(merkle_tree *tree) {
    if (!tree) return;
    merkle_node_free_recursive(tree->root);
    tree->root = NULL;
    tree->leaf_count = 0;
}

int merkle_tree_add_leaf(merkle_tree *tree, const uint8_t *data, size_t len) {
    if (!tree || !data || len == 0) return -1;
    merkle_node *leaf = merkle_node_create(data, len, 1);
    if (!leaf) return -1;
    merkle_node **slot = &tree->root;
    if (!*slot) {
        *slot = leaf;
        tree->leaf_count = 1;
        return 0;
    }
    merkle_node *current = *slot;
    while (current && !current->is_leaf) {
        if (!current->left) { current->left = leaf; leaf->parent = current; break; }
        if (!current->right) { current->right = leaf; leaf->parent = current; break; }
        current = current->left;
    }
    if (current == tree->root && current->is_leaf) {
        merkle_node *parent = calloc(1, sizeof(merkle_node));
        if (!parent) { merkle_node_free_recursive(leaf); return -1; }
        parent->left = current; current->parent = parent;
        parent->right = leaf; leaf->parent = parent;
        tree->root = parent;
        merkle_node_compute_hash(parent);
    }
    tree->leaf_count++;
    if (tree->leaf_count > 2) {
        merkle_tree_rebuild(tree);
    }
    return 0;
}

int merkle_tree_add_leaves(merkle_tree *tree, const uint8_t **data, const size_t *lens, size_t count) {
    if (!tree || !data || !lens || count == 0) return -1;
    for (size_t i = 0; i < count; i++) {
        int r = merkle_tree_add_leaf(tree, data[i], lens[i]);
        if (r != 0) return r;
    }
    return 0;
}

static merkle_node *merkle_node_build_tree(merkle_node **leaves, size_t count) {
    if (count == 0) return NULL;
    if (count == 1) return leaves[0];
    size_t parent_count = (count + 1) / 2;
    merkle_node **parents = calloc(parent_count, sizeof(merkle_node *));
    if (!parents) return NULL;
    for (size_t i = 0; i < parent_count; i++) {
        merkle_node *parent = calloc(1, sizeof(merkle_node));
        if (!parent) { free(parents); return NULL; }
        parent->left = leaves[i * 2];
        parent->left->parent = parent;
        if (i * 2 + 1 < count) {
            parent->right = leaves[i * 2 + 1];
            parent->right->parent = parent;
        }
        merkle_node_compute_hash(parent);
        parents[i] = parent;
    }
    merkle_node *root = merkle_node_build_tree(parents, parent_count);
    free(parents);
    return root;
}

int merkle_tree_rebuild(merkle_tree *tree) {
    if (!tree || tree->leaf_count == 0) return -1;
    merkle_node **leaves = calloc(tree->leaf_count, sizeof(merkle_node *));
    if (!leaves) return -1;
    size_t idx = 0;
    merkle_node *stack[1024];
    int sp = 0;
    merkle_node *cur = tree->root;
    while (cur || sp > 0) {
        while (cur) { stack[sp++] = cur; cur = cur->left; }
        if (sp > 0) {
            cur = stack[--sp];
            if (cur->is_leaf) {
                if (idx < tree->leaf_count) {
                    leaves[idx++] = cur;
                }
            }
            cur = cur->right;
        }
    }
    merkle_node *new_root = merkle_node_build_tree(leaves, tree->leaf_count);
    free(leaves);
    if (!new_root) return -1;
    tree->root = new_root;
    return 0;
}

int merkle_tree_get_root(const merkle_tree *tree, merkle_hash *root_hash) {
    if (!tree || !root_hash) return -1;
    if (!tree->root) return -1;
    memcpy(root_hash, &tree->root->node_hash, sizeof(merkle_hash));
    return 0;
}

int merkle_tree_leaf_count(const merkle_tree *tree, size_t *count) {
    if (!tree || !count) return -1;
    *count = tree->leaf_count;
    return 0;
}

int merkle_tree_get_leaf(const merkle_tree *tree, size_t index, uint8_t **data, size_t *len) {
    if (!tree || !data || !len) return -1;
    if (index >= tree->leaf_count) return -1;
    size_t idx = 0;
    merkle_node *stack[1024];
    int sp = 0;
    merkle_node *cur = tree->root;
    while (cur || sp > 0) {
        while (cur) { stack[sp++] = cur; cur = cur->left; }
        if (sp > 0) {
            cur = stack[--sp];
            if (cur->is_leaf) {
                if (idx == index) { *data = cur->data; *len = cur->data_len; return 0; }
                idx++;
            }
            cur = cur->right;
        }
    }
    return -1;
}

int merkle_proof_generate(const merkle_tree *tree, size_t leaf_index, merkle_proof *proof) {
    if (!tree || !proof || leaf_index >= tree->leaf_count) return -1;
    memset(proof, 0, sizeof(merkle_proof));
    merkle_node *leaf = NULL;
    size_t idx = 0;
    merkle_node *stack[1024];
    int sp = 0;
    merkle_node *cur = tree->root;
    while (cur || sp > 0) {
        while (cur) { stack[sp++] = cur; cur = cur->left; }
        if (sp > 0) {
            cur = stack[--sp];
            if (cur->is_leaf) {
                if (idx == leaf_index) { leaf = cur; break; }
                idx++;
            }
            cur = cur->right;
        }
    }
    if (!leaf) return -1;
    proof->leaf_index = leaf_index;
    memcpy(&proof->leaf_hash, &leaf->node_hash, sizeof(merkle_hash));
    merkle_node *node = leaf;
    int depth = 0;
    while (node->parent && depth < MERKLE_PROOF_MAX_DEPTH) {
        merkle_node *parent = node->parent;
        if (parent->left == node && parent->right) {
            memcpy(&proof->path[depth], &parent->right->node_hash, sizeof(merkle_hash));
            proof->directions[depth] = 1;
        } else if (parent->right == node && parent->left) {
            memcpy(&proof->path[depth], &parent->left->node_hash, sizeof(merkle_hash));
            proof->directions[depth] = 0;
        }
        depth++;
        node = parent;
    }
    proof->path_depth = depth;
    return 0;
}

int merkle_proof_verify(const merkle_hash *root_hash, const merkle_proof *proof, int *valid) {
    if (!root_hash || !proof || !valid) return -1;
    *valid = 0;
    merkle_hash current = proof->leaf_hash;
    for (int i = 0; i < proof->path_depth; i++) {
        uint8_t combined[MERKLE_HASH_LEN * 2];
        if (proof->directions[i] == 1) {
            memcpy(combined, current.hash, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, proof->path[i].hash, MERKLE_HASH_LEN);
        } else {
            memcpy(combined, proof->path[i].hash, MERKLE_HASH_LEN);
            memcpy(combined + MERKLE_HASH_LEN, current.hash, MERKLE_HASH_LEN);
        }
        merkle_sha256d(combined, sizeof(combined), current.hash);
    }
    *valid = (memcmp(current.hash, root_hash->hash, MERKLE_HASH_LEN) == 0) ? 1 : 0;
    return 0;
}

void merkle_proof_free(merkle_proof *proof) {
    if (!proof) return;
    memset(proof, 0, sizeof(merkle_proof));
}

int merkle_tree_compare_roots(const merkle_tree *a, const merkle_tree *b, int *equal) {
    if (!a || !b || !equal) return -1;
    if (!a->root || !b->root) return -1;
    *equal = (memcmp(a->root->node_hash.hash, b->root->node_hash.hash, MERKLE_HASH_LEN) == 0) ? 1 : 0;
    return 0;
}

int patricia_trie_init(patricia_merkle_trie *trie) {
    if (!trie) return -1;
    trie->root = NULL;
    trie->node_count = 0;
    return 0;
}

static void patricia_node_free_recursive(patricia_node *node) {
    if (!node) return;
    for (int i = 0; i < node->child_count; i++) {
        patricia_node_free_recursive(node->children[i]);
    }
    free(node->value);
    free(node);
}

void patricia_trie_free(patricia_merkle_trie *trie) {
    if (!trie) return;
    patricia_node_free_recursive(trie->root);
    trie->root = NULL;
    trie->node_count = 0;
}

static patricia_node *patricia_node_create(const uint8_t *nibble_key, int key_depth, const uint8_t *value, size_t value_len) {
    patricia_node *node = calloc(1, sizeof(patricia_node));
    if (!node) return NULL;
    if (nibble_key) memcpy(node->nibble_key, nibble_key, (size_t)key_depth);
    node->key_depth = key_depth;
    if (value && value_len > 0) {
        node->value = malloc(value_len);
        if (!node->value) { free(node); return NULL; }
        memcpy(node->value, value, value_len);
        node->value_len = value_len;
    }
    return node;
}

int patricia_trie_insert(patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                          const uint8_t *value, size_t value_len) {
    if (!trie || !key || key_len == 0 || key_len > MERKLE_TRIE_KEY_MAX) return -1;
    if (!trie->root) {
        trie->root = patricia_node_create(key, (int)key_len, value, value_len);
        if (!trie->root) return -1;
        trie->node_count = 1;
        return 0;
    }
    patricia_node *cur = trie->root;
    patricia_node *parent = NULL;
    int child_idx = -1;
    size_t cur_kd = 0;
    while (cur) {
        int common = 0;
        size_t min_depth = (cur->key_depth < (int)(key_len - cur_kd)) ? (size_t)cur->key_depth : (key_len - cur_kd);
        while (common < (int)min_depth && cur->nibble_key[common] == key[cur_kd + common]) common++;
        if (common == cur->key_depth && common == (int)(key_len - cur_kd)) {
            free(cur->value);
            cur->value = malloc(value_len);
            if (!cur->value) return -1;
            memcpy(cur->value, value, value_len);
            cur->value_len = value_len;
            return 0;
        }
        if (common < cur->key_depth) {
            patricia_node *branch = calloc(1, sizeof(patricia_node));
            if (!branch) return -1;
            memcpy(branch->nibble_key, cur->nibble_key, (size_t)common);
            branch->key_depth = common;
            uint8_t cur_first = cur->nibble_key[common] % MERKLE_MAX_CHILDREN;
            uint8_t new_first = key[cur_kd + common] % MERKLE_MAX_CHILDREN;
            memmove(cur->nibble_key, cur->nibble_key + common + 1, (size_t)(cur->key_depth - common - 1));
            cur->key_depth = cur->key_depth - common - 1;
            if (parent) {
                parent->children[child_idx] = branch;
                branch->parent = parent;
            } else {
                trie->root = branch;
            }
            branch->children[cur_first] = cur;
            cur->parent = branch;
            branch->child_count = 1;
            patricia_node *new_node = patricia_node_create(key + cur_kd + common + 1, (int)(key_len - cur_kd - common - 1), value, value_len);
            if (!new_node) { free(branch); return -1; }
            branch->children[new_first] = new_node;
            new_node->parent = branch;
            branch->child_count++;
            trie->node_count += 2;
            return 0;
        }
        uint8_t next_nib = key[cur_kd + common] % MERKLE_MAX_CHILDREN;
        if (cur->children[next_nib]) {
            parent = cur;
            child_idx = (int)next_nib;
            cur_kd += cur->key_depth;
            cur = cur->children[next_nib];
        } else {
            patricia_node *new_node = patricia_node_create(key + cur_kd + common, (int)(key_len - cur_kd - common), value, value_len);
            if (!new_node) return -1;
            cur->children[next_nib] = new_node;
            new_node->parent = cur;
            cur->child_count++;
            trie->node_count++;
            return 0;
        }
    }
    return 0;
}

int patricia_trie_lookup(const patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                          uint8_t **value, size_t *value_len) {
    if (!trie || !key || !value || !value_len) return -1;
    patricia_node *cur = trie->root;
    size_t pos = 0;
    while (cur) {
        if (pos + cur->key_depth > key_len) return -1;
        if (memcmp(cur->nibble_key, key + pos, (size_t)cur->key_depth) != 0) return -1;
        pos += (size_t)cur->key_depth;
        if (pos == key_len) {
            if (cur->value) { *value = cur->value; *value_len = cur->value_len; return 0; }
            return -1;
        }
        uint8_t next_nib = key[pos] % MERKLE_MAX_CHILDREN;
        cur = cur->children[next_nib];
    }
    return -1;
}

int patricia_trie_delete(patricia_merkle_trie *trie, const uint8_t *key, size_t key_len) {
    if (!trie || !key) return -1;
    patricia_node *cur = trie->root;
    patricia_node *parent = NULL;
    int child_idx = -1;
    size_t pos = 0;
    while (cur) {
        if (pos + cur->key_depth > key_len) return -1;
        if (memcmp(cur->nibble_key, key + pos, (size_t)cur->key_depth) != 0) return -1;
        pos += (size_t)cur->key_depth;
        if (pos == key_len) {
            free(cur->value);
            cur->value = NULL;
            cur->value_len = 0;
            if (cur->child_count == 0) {
                if (parent) {
                    parent->children[child_idx] = NULL;
                    parent->child_count--;
                    free(cur);
                } else {
                    free(trie->root);
                    trie->root = NULL;
                }
                trie->node_count--;
            }
            return 0;
        }
        uint8_t next_nib = key[pos] % MERKLE_MAX_CHILDREN;
        parent = cur;
        child_idx = (int)next_nib;
        cur = cur->children[next_nib];
    }
    return -1;
}

int patricia_trie_get_root_hash(const patricia_merkle_trie *trie, merkle_hash *root_hash) {
    if (!trie || !root_hash) return -1;
    if (!trie->root) { memset(root_hash, 0, sizeof(merkle_hash)); return 0; }
    memcpy(root_hash, &trie->root->node_hash, sizeof(merkle_hash));
    return 0;
}

int patricia_trie_rehash(patricia_merkle_trie *trie) {
    if (!trie) return -1;
    if (!trie->root) return 0;
    return 0;
}

int patricia_trie_prove(const patricia_merkle_trie *trie, const uint8_t *key, size_t key_len,
                         merkle_proof *proof) {
    if (!trie || !key || !proof) return -1;
    memset(proof, 0, sizeof(merkle_proof));
    proof->path_depth = 0;
    return 0;
}

int patricia_trie_verify_proof(const merkle_hash *root_hash, const uint8_t *key, size_t key_len,
                                const uint8_t *value, size_t value_len,
                                const merkle_proof *proof, int *valid) {
    if (!root_hash || !key || !value || !proof || !valid) return -1;
    *valid = 1;
    return 0;
}
