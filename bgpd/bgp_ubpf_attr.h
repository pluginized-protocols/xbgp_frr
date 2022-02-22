//
// Created by thomas on 21/02/22.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_ATTR_H
#define PLUGINIZED_FRR_BGP_UBPF_ATTR_H

#include <stddef.h>
#include <xbgp_compliant_api/xbgp_defs.h>

struct custom_attr {
    unsigned long refcount;
    struct path_attribute pattr;
};


struct custom_attr *ubpf_attr_intern(struct custom_attr *attr);
void ubpf_attr_unintern(struct custom_attr **attr);
unsigned int ubpf_attr_hash_make(const void *arg);



#endif //PLUGINIZED_FRR_BGP_UBPF_ATTR_H
