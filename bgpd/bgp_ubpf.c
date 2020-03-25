//
// Created by thomas on 12/03/20.
//

#include <lib/stream.h>
#include <tools_ubpf_api.h>
#include "bgp_ubpf.h"
#include "public.h"
#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_aspath.h"
#include "bgp_community.h"
#include "bgp_lcommunity.h"
#include "bgp_ecommunity.h"

static inline uint8_t flags(unsigned int optional, unsigned int transitive,
                            unsigned int partial, unsigned int length) {

    return (((optional << 3u) & 8u) |
            ((transitive << 2u) & 4u) |
            ((partial << 1u) & 2u) |
            (length & 1u)) << 4u;

}


static void clean_attr(void *_attr) {
    struct ubpf_attr *attr = _attr;
    if (!attr) return;

    if (attr->length > 8) {
        free(attr->data.ptr);
    }
}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr) {

    struct ubpf_attr attr;

    bpf_full_args_t *fargs;
    fargs = ctx->args;
    mem_pool *mp;

    if (fargs->args[4].type != MEMPOOL) return -1;
    mp = fargs->args[4].arg;

    attr.flags = flags;
    attr.code = code;
    attr.length = length;

    if (length > 8) {
        attr.data.ptr = malloc(length);
        if (!attr.data.ptr) return -1;
        memcpy(attr.data.ptr, decoded_attr, length);
    } else {
        memset(&attr.data.val, 0, sizeof(uint64_t));
        memcpy(&attr.data.val, decoded_attr, length);
    }


    if (add_single_mempool(mp, code, clean_attr, sizeof(struct ubpf_attr), &attr) != 0)
        return -1;

    return 0;
}

struct path_attribute *get_attr(context_t *ctx) {
    struct path_attribute *ubpf_attr;
    struct ubpf_attr *frr_attr;
    bpf_full_args_t *fargs;
    fargs = ctx->args;

    if (fargs->args[1].type != ATTRIBUTE) return NULL;
    frr_attr = fargs->args[1].arg;

    ubpf_attr = ctx_malloc(ctx, sizeof(struct path_attribute));
    if (!ubpf_attr) return NULL;

    ubpf_attr->code = frr_attr->code;
    ubpf_attr->flags = frr_attr->flags;
    ubpf_attr->len = frr_attr->length;
    ubpf_attr->data = ctx_malloc(ctx, frr_attr->length);

    if (!ubpf_attr->data) return NULL;
    memcpy(ubpf_attr->data, get_data_attr(frr_attr), frr_attr->length);

    return ubpf_attr;
}

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len) {

    bpf_full_args_t *fargs;
    size_t bytes_written;
    struct stream *s;

    fargs = ctx->args;

    if (fargs->args[1].type != WRITE_STREAM) return -1;
    s = fargs->args[1].arg;

    bytes_written = stream_write(s, ptr, len);
    if (bytes_written != len) return -1;

    return 0;
}

static inline int
frrmempool_to_ubpf_attr(context_t *ctx, struct ubpf_attr *frr_attr, struct path_attribute *ubpf_attr) {

    if (!frr_attr || !ubpf_attr) return -1;

    ubpf_attr->code = frr_attr->code;
    ubpf_attr->flags = frr_attr->flags;

    ubpf_attr->data = ctx_malloc(ctx, frr_attr->length);
    if (!ubpf_attr->data) return -1;

    memcpy(ubpf_attr->data, get_data_attr(frr_attr), frr_attr->length);
    ubpf_attr->len = frr_attr->length;

    return 0;
}

static inline size_t as_path_length(struct aspath *as_path, int is_as4) {

    int nb_as, nb_segments;
    struct assegment *curr_seg;

    nb_as = nb_segments = 0;
    for (curr_seg = as_path->segments; curr_seg != NULL; curr_seg = curr_seg->next) {
        nb_segments++;
        nb_as += curr_seg->length;
    }

    // 1 byte for aspath segment type
    // 1 byte segment length (nb of ASes)
    // `-> 2 * nb_segments
    // 2 or 4 bytes per ASes
    // `-> {2,4} * nb_as
    return (2 * nb_segments) + ((is_as4 ? 4 : 2) * nb_as);
}


static inline int
set_aspath_attr(context_t *ctx, struct path_attribute *ubpf_attr, struct aspath *aspath, int is_as4) {

    int i, as_size;
    struct assegment *curr_seg;
    uint8_t *offset;
    size_t attr_len;

    as_size = is_as4 ? 4 : 2;

    // allocate_memory
    attr_len = as_path_length(aspath, is_as4);
    if (attr_len == 0) return -1;
    ubpf_attr->data = ctx_malloc(ctx, attr_len);
    if (!ubpf_attr->data) return -1;
    offset = ubpf_attr->data;


    for (curr_seg = aspath->segments; curr_seg != NULL; curr_seg = curr_seg->next) {
        *offset = curr_seg->type;
        offset++;
        *((uint16_t *) offset) = curr_seg->length;
        offset += 2;

        for (i = 0; i < curr_seg->length; i++) {
            memcpy(offset, &(curr_seg->as[i]), as_size);
            offset += as_size;
        }
    }

    ubpf_attr->len = attr_len;
    ubpf_attr->code = is_as4 ? BGP_ATTR_AS4_PATH : BGP_ATTR_AS_PATH;
    ubpf_attr->flags = flags(0, 1, 0, attr_len > 255 ? 1 : 0);
    return 0;
}

static inline int
set_aggregator(context_t *ctx, uint32_t aggregator_addr, uint32_t as, int is_as4, struct path_attribute *ubpf_attr) {

    uint8_t *offset;

    ubpf_attr->flags = flags(1, 1, 0, 0);
    ubpf_attr->len = is_as4 ? 8 : 6;
    ubpf_attr->data = ctx_malloc(ctx, ubpf_attr->len);
    if (!ubpf_attr->data) return -1;

    offset = ubpf_attr->data;

    if (is_as4) {
        *((uint32_t *) offset) = as;
        offset += 4;
    } else {
        *((uint16_t *) offset) = (uint16_t) as;
        offset += 2;
    }

    *((uint32_t *) offset) = aggregator_addr;

    return 0;
}

#define fn_set_community(community_type, size_per_community)\
static inline int set_##community_type (context_t *ctx, struct community_type *c, struct path_attribute *ubpf_attr) {\
    uint16_t tot_len;\
    tot_len = c->size * size_per_community;\
    ubpf_attr->data = ctx_malloc(ctx, tot_len);\
    if (!ubpf_attr->data) return -1;\
    memcpy(ubpf_attr->data, c->val, tot_len);\
    ubpf_attr->len = tot_len;\
    ubpf_attr->flags = flags(1, 1, 0, tot_len > UINT8_MAX ? 1 : 0);\
    return 0;\
}

fn_set_community(community, 4)

fn_set_community(lcommunity, 6)

fn_set_community(ecommunity, 8)

static inline int set_cluster_list (context_t *ctx, struct cluster_list *c, struct path_attribute *ubpf_attr) {\
    uint16_t tot_len;\
    tot_len = c->length;\
    ubpf_attr->data = ctx_malloc(ctx, tot_len);\
    if (!ubpf_attr->data) return -1;\
    memcpy(ubpf_attr->data, c->list, tot_len);\
    ubpf_attr->len = tot_len;\
    ubpf_attr->flags = flags(1, 1, 0, tot_len > UINT8_MAX ? 1 : 0);\
    return 0;\
}

static inline int set_reach_nlri(context_t *ctx, struct bgp_nlri *nlri, struct attr *attr, struct path_attribute *ubpf_attr) {

    size_t offset;
    uint8_t *buffer;

    offset = 0;
    buffer = malloc(255);
    if(!buffer) return -1;

    // afi
    *((uint16_t *) buffer + offset) = nlri->afi;
    offset += 2;
    // safi
    *((uint8_t *) buffer + offset) = nlri->safi;
    offset += 1;

    // nexthop length
    *((uint8_t *) buffer + offset) = attr->mp_nexthop_len;
    offset += 1;

    // next hop is located somewhere is the attribute
    // according to afi/safi
    // TODO...

    return 0;
}

static inline int
frr_to_ubpf_attr(context_t *ctx, uint8_t code, struct bgp_path_info *frr_route, struct path_attribute *ubpf_attr) {

    struct attr *frr_attr;
    struct peer *peer;

    if (!frr_route || !ubpf_attr) return -1;

    frr_attr = frr_route->attr;
    peer = frr_route->peer;

    ubpf_attr->code = code;

    switch (code) {
        case BGP_ATTR_ORIGIN:
            ubpf_attr->len = 1;
            ubpf_attr->data = ctx_malloc(ctx, 1);
            if (!ubpf_attr->data) return -1;
            *((uint8_t *) ubpf_attr->data) = frr_attr->origin;
            break;
        case BGP_ATTR_AS4_PATH:
            if (set_aspath_attr(ctx, ubpf_attr, frr_attr->aspath, 1) != 0)
                return -1;
            break;
        case BGP_ATTR_AS_PATH:
            if (set_aspath_attr(ctx, ubpf_attr, frr_attr->aspath, 0) != 0)
                return -1;
            break;
        case BGP_ATTR_NEXT_HOP:

            ubpf_attr->len = 4; //ipv4 nexthop
            ubpf_attr->data = ctx_malloc(ctx, 4);
            if (!ubpf_attr->data) return -1;
            *((in_addr_t *) ubpf_attr->data) = frr_attr->nexthop.s_addr;
            break;
        case BGP_ATTR_MULTI_EXIT_DISC:
            ubpf_attr->flags = flags(1, 0, 0, 0);
            ubpf_attr->len = 4;
            ubpf_attr->data = ctx_malloc(ctx, 4);
            if (!ubpf_attr->data) return -1;
            *((uint32_t *) ubpf_attr->data) = frr_attr->med;
            break;
        case BGP_ATTR_LOCAL_PREF:
            ubpf_attr->flags = flags(1, 0, 0, 0);
            ubpf_attr->len = 4;
            ubpf_attr->data = ctx_malloc(ctx, 4);
            if (!ubpf_attr->data) return -1;
            *((uint32_t *) ubpf_attr->data) = frr_attr->local_pref;
            break;
        case BGP_ATTR_ATOMIC_AGGREGATE:
            ubpf_attr->flags = flags(0, 0, 0, 0);
            ubpf_attr->len = 0;
            ubpf_attr->data = NULL;
            break;
        case BGP_ATTR_AGGREGATOR:
            if (set_aggregator(ctx, frr_attr->aggregator_addr.s_addr,
                               frr_attr->aggregator_as, 0, ubpf_attr) != 0) {
                return -1;
            }
            break;

        case BGP_ATTR_AS4_AGGREGATOR:
            if (set_aggregator(ctx, frr_attr->aggregator_addr.s_addr,
                               frr_attr->aggregator_as, 1, ubpf_attr) != 0) {
                return -1;
            }
            break;
        case BGP_ATTR_COMMUNITIES:
            if (set_community(ctx, frr_attr->community, ubpf_attr) != 0) return -1;
            break;
        case BGP_ATTR_LARGE_COMMUNITIES:
            if (set_lcommunity(ctx, frr_attr->lcommunity, ubpf_attr)) return -1;
            break;
        case BGP_ATTR_ORIGINATOR_ID:
            ubpf_attr->flags = flags(1,0,0,0); // TODO CHANGE FLAGS
            ubpf_attr->len = 4;
            ubpf_attr->data = ctx_malloc(ctx, 4);
            if (!ubpf_attr->data) return -1;

            *((uint32_t *) ubpf_attr->data) = frr_attr->originator_id.s_addr;
            break;
        case BGP_ATTR_CLUSTER_LIST:
            if (set_cluster_list(ctx, frr_attr->cluster, ubpf_attr) != 0) return -1;
            break;
        case BGP_ATTR_EXT_COMMUNITIES:
            if (set_ecommunity(ctx, frr_attr->ecommunity, ubpf_attr) != 0) return -1;
            break;
        case BGP_ATTR_MP_REACH_NLRI:
        case BGP_ATTR_MP_UNREACH_NLRI:
            // TODO !
            return -1; // not implemented yet
        case BGP_ATTR_ENCAP:
        case BGP_ATTR_PREFIX_SID:
        case BGP_ATTR_PMSI_TUNNEL:
            return -1; //not handled !
        default:
            return -1;
    }

    return 0;
}

static inline int find_idx_arg(context_t *ctx, int type) {

    int i;
    bpf_full_args_t *fargs;

    if (!ctx) return -1;

    fargs = ctx->args;

    for (i = 0; i < fargs->nargs; i++) {
        if (fargs->args[i].type == type) return i;
    }

    return -1;
}

struct path_attribute *get_attr_by_code_from_rte(context_t *ctx, uint8_t code, int args_rte) {

    unsigned int i;
    bpf_full_args_t *fargs;
    struct ubpf_attr *frrmempool_attr;
    struct bgp_path_info *frr_route;
    struct path_attribute *ubpf_attr;
    fargs = ctx->args;
    mem_pool *mp;

    frrmempool_attr = NULL;

    if (args_rte >= fargs->nargs) return NULL;
    if (fargs->args[args_rte].type != BGP_ROUTE) return NULL;
    frr_route = fargs->args[args_rte].arg;

    mp = frr_route->attr->ubpf_mempool;
    if (mp) frrmempool_attr = get_mempool_ptr(mp, code);

    ubpf_attr = ctx_malloc(ctx, sizeof(struct path_attribute));
    if (!ubpf_attr) return NULL;

    if (!frrmempool_attr) {
        if (frrmempool_to_ubpf_attr(ctx, frrmempool_attr, ubpf_attr) != 0) return NULL;
        return ubpf_attr;
    }

    // check if it is an attribute handled by frrouting
    frr_to_ubpf_attr(ctx, code, frr_route, ubpf_attr);

}