//
// Created by thomas on 21/02/22.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_ATTR_H
#define PLUGINIZED_FRR_BGP_UBPF_ATTR_H

#include <stddef.h>
#include <stdbool.h>
#include <xbgp_compliant_api/xbgp_defs.h>
#include "uthash.h"

struct custom_attr {
    UT_hash_handle hh;
    int code;
    unsigned long refcount;
    struct path_attribute pattr;
};


struct custom_attr *ubpf_attr_intern(struct custom_attr *attr);
void ubpf_attr_unintern(struct custom_attr **attr);
unsigned int ubpf_attr_hash_make(const void *arg);
bool ubpf_attr_cmp(const void *arg1, const void *arg2);


#endif //PLUGINIZED_FRR_BGP_UBPF_ATTR_H
