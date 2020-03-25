//
// Created by thomas on 12/03/20.
//

#ifndef PLUGINIZED_FRR_BGP_UBPF_H
#define PLUGINIZED_FRR_BGP_UBPF_H

#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <context_hdr.h>

#define get_data_attr(ubpf_attr)\
((ubpf_attr)->length > 8 ? (void *) (ubpf_attr)->data.ptr : &((ubpf_attr)->data.val))

enum ubpf_plugins {
    BGP_MED_DECISION = 1, // decision process MED insertion point
    BGP_DECODE_ATTR,
    BGP_ENCODE_ATTR,
};

enum ret_decision_process {
    BGP_UNK,
    BGP_NEW,
    BGP_OLD
};

enum type {
    TYPE_NULL = 0,
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
        case BGP_UNK:
        case BGP_NEW:
        case BGP_OLD:
            return 1;
        default:
            return 0;
    }

}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr);

struct path_attribute *get_attr(context_t *ctx);

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len);

struct path_attribute *get_attr_by_code_from_rte(context_t *ctx, uint8_t code, int args_rte);

#endif //PLUGINIZED_FRR_BGP_UBPF_H
