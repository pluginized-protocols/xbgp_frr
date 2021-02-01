//
// Created by thomas on 12/03/20.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_H
#define PLUGINIZED_FRR_BGP_UBPF_H

#include <stdint.h>
#include <xbgp_compliant_api/xbgp_defs.h>

#define MAX_BUF_LEN 4096

enum type {
    TYPE_NULL = ARG_MAX_OPAQUE,
    INTEGER,
    MEMPOOL,
    BYTE_ARRAY,
    PARSE_STATE,
    WRITE_STATE,
    BUFFER_ARRAY,
    WRITE_STREAM,
    PREFIX_ARRAY,
    PEER_SRC,
    PEER_TO,
    PEERS_TO, // update group may concern multiple routers
    PEERS_TO_COUNT,
};


#define cond_cpy(start, offset, data, increment, max_len) ({ \
    int __ret;                                               \
    size_t __curr_size__ = (offset - start) + increment;     \
    if (__curr_size__ > max_len)  {                          \
        __ret = 0;                                           \
    } else {                                                 \
        memcpy(offset, data, increment);                     \
        offset += increment;                                 \
        __ret = 1;                                           \
    }                                                        \
    __ret;                                                   \
})

static inline int check_arg_decode(uint64_t ret_val) {
    return ret_val == EXIT_FAILURE ? 0 : 1;
}

static inline int ret_val_check_encode_attr(uint64_t val) {
    if (val > 4096) return 0; // RFC 4271 says 4KB max TODO CHECK
    if (val == 0) return 0;

    return 1;
}

static inline int ret_val_rte_decision(uint64_t val) {

    switch (val) {
        case BGP_ROUTE_TYPE_UNKNOWN:
        case BGP_ROUTE_TYPE_NEW:
        case BGP_ROUTE_TYPE_OLD:
            return 1;
        case BGP_ROUTE_TYPE_FAIL:
        default:
            return 0;
    }

}

static inline int ret_val_bgp_filter(uint64_t val) {

    switch (val) {
        case PLUGIN_FILTER_REJECT:
        case PLUGIN_FILTER_UNKNOWN:
        case PLUGIN_FILTER_ACCEPT:
            return 1;
        default:
            return 0;
    }

}

#endif //PLUGINIZED_FRR_BGP_UBPF_H
