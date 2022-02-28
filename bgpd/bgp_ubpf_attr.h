//
// Created by thomas on 21/02/22.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_ATTR_H
#define PLUGINIZED_FRR_BGP_UBPF_ATTR_H

#include <stdbool.h>
#include <stdint.h>
#include <xbgp_compliant_api/xbgp_defs.h>
#include "uthash.h"

struct custom_attr {
    unsigned long refcount;
    struct path_attribute pattr;
};

struct rte_attr {
    UT_hash_handle hh;
    int code;
    struct custom_attr *attr;
};


struct custom_attr *ubpf_attr_intern(struct custom_attr *attr);
void ubpf_attr_unintern(struct custom_attr **attr);
unsigned int ubpf_attr_hash_make(const void *arg);
bool ubpf_attr_cmp(const void *arg1, const void *arg2);

#define unset_index(bitarray, idx)  do {          \
    (bitarray)[(idx) / 64] &= ~(1 << ((idx) % 64)); \
} while(0)


#endif //PLUGINIZED_FRR_BGP_UBPF_ATTR_H
