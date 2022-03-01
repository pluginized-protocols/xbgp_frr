//
// Created by thomas on 21/02/22.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_ATTR_H
#define PLUGINIZED_FRR_BGP_UBPF_ATTR_H

#include <stdbool.h>
#include <stdint.h>
#include <xbgp_compliant_api/xbgp_defs.h>
#include "uthash.h"

/* taken from https://lemire.me/blog/2018/02/21/iterating-over-set-bits-quickly/ */
#define iterate_bitset_begin(bitmap, bitmapsize, idx) do {     \
    uint64_t bitset;                          \
    for (size_t k = 0; k < (bitmapsize); ++k) { \
        bitset = (bitmap)[k];                   \
        while (bitset != 0) {                 \
            uint64_t t = bitset & -bitset;    \
            int r = __builtin_ctzl(bitset);   \
            (idx) = k * 64 + r;

#define iterate_bitset_end \
            bitset ^= t;   \
        }                  \
    }                      \
} while(0)

struct custom_attr {
    unsigned long refcount;
    struct path_attribute pattr;
};

struct rte_attr {
    UT_hash_handle hh;
    int code;
    struct custom_attr *attr;
};

struct rte_attr_hash {
    unsigned long refcount;
    uint64_t bitset_attrs[4];
    struct rte_attr *head_hash;
};


struct custom_attr *ubpf_attr_intern(struct custom_attr *attr);
void ubpf_attr_unintern(struct custom_attr **attr);
unsigned int ubpf_attr_hash_make(const void *arg);
bool ubpf_attr_cmp(const void *arg1, const void *arg2);
void custom_attr_cpy__(struct rte_attr *rta_old, struct rte_attr **rta_new);

#define unset_index(bitarray, idx)  do {          \
    (bitarray)[(idx) / 64] &= ~(1 << ((idx) % 64)); \
} while(0)


struct rte_attr_hash *rte_attr_intern(struct rte_attr_hash *rte_attr);
void rte_attr_unintern(struct rte_attr_hash **rte_attr);
unsigned int rte_attr_hash_make(const void *arg);

#endif //PLUGINIZED_FRR_BGP_UBPF_ATTR_H
