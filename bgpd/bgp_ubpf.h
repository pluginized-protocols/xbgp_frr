//
// Created by thomas on 12/03/20.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_H
#define PLUGINIZED_FRR_BGP_UBPF_H

#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <context_hdr.h>

#define RTE_NEW 0
#define RTE_OLD 1
#define RTE_UNK 2
#define RTE_FAIL 3

#define PLUGIN_FILTER_ACCEPT 0
#define PLUGIN_FILTER_REJECT 1
#define PLUGIN_FILTER_UNK 2

#define get_data_attr(ubpf_attr)\
((ubpf_attr)->length > 8 ? (void *) (ubpf_attr)->data.ptr : &((ubpf_attr)->data.val))

enum ubpf_plugins {
    BGP_MED_DECISION = 1, // decision process MED insertion point
    BGP_DECODE_ATTR,
    BGP_ENCODE_ATTR,
    BGP_RECEIVE_UPDATE,
    BGP_PRE_INBOUND_FILTER,
    BGP_PRE_OUTBOUND_FILTER,
    BGP_SEND_UPDATE,
};

enum type {
    TYPE_NULL = 0,
    INTEGER,
    BGP_ROUTE,
    UNSIGNED_INT,
    MEMPOOL,
    BYTE_ARRAY,
    ATTRIBUTE_LIST,
    ATTRIBUTE,
    PARSE_STATE,
    WRITE_STATE,
    BUFFER_ARRAY,
    WRITE_STREAM,
    PREFIX_ARRAY,
    PEER_SRC,
    PEER_TO,
    PEERS_TO, // update group may concern multiple routers
    PEERS_TO_COUNT,
    PREFIX,
    RIB_ROUTE,
};

struct ubpf_attr {
    uint8_t code;
    uint8_t flags;
    uint16_t length;
    union {
        uint8_t *ptr;
        uint64_t val;
    } data;
};


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
        case RTE_UNK:
        case RTE_NEW:
        case RTE_OLD:
            return 1;
        case RTE_FAIL:
        default:
            return 0;
    }

}

static inline int ret_val_bgp_filter(uint64_t val) {

    switch (val) {
        case PLUGIN_FILTER_REJECT:
        case PLUGIN_FILTER_UNK:
        case PLUGIN_FILTER_ACCEPT:
            return 1;
        default:
            return 0;
    }

}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

struct path_attribute *get_attr(context_t *ctx);

int set_attr(context_t *ctx, struct path_attribute *attr);

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len);

struct path_attribute *get_attr_by_code_from_rte(context_t *ctx, uint8_t code, int args_rte);

uint32_t get_peer_router_id(context_t *ctx);

struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code);

struct ubpf_peer_info *get_src_peer_info(context_t *ctx);

struct ubpf_peer_info *get_peer_info(context_t *ctx, int *nb_peers);

union ubpf_prefix *get_prefix(context_t *ctx);

struct ubpf_nexthop *get_nexthop(context_t *ctx, union ubpf_prefix *fx);

#endif //PLUGINIZED_FRR_BGP_UBPF_H
