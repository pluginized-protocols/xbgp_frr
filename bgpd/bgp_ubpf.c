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
#include "ubpf_prefix.h"

static inline uint8_t flags(unsigned int optional, unsigned int transitive,
                            unsigned int partial, unsigned int length) {

    return (((optional << 3u) & 8u) |
            ((transitive << 2u) & 4u) |
            ((partial << 1u) & 2u) |
            (length & 1u)) << 4u;

}

static inline int frr_known_bgp_attr(int code) {
    switch (code) {
        case BGP_ATTR_ORIGIN:
        case BGP_ATTR_AS_PATH:
        case BGP_ATTR_AS4_PATH:
        case BGP_ATTR_NEXT_HOP:
        case BGP_ATTR_MULTI_EXIT_DISC:
        case BGP_ATTR_LOCAL_PREF:
        case BGP_ATTR_ATOMIC_AGGREGATE:
        case BGP_ATTR_AGGREGATOR:
        case BGP_ATTR_AS4_AGGREGATOR:
        case BGP_ATTR_COMMUNITIES:
        case BGP_ATTR_LARGE_COMMUNITIES:
        case BGP_ATTR_ORIGINATOR_ID:
        case BGP_ATTR_CLUSTER_LIST:
        case BGP_ATTR_EXT_COMMUNITIES:
        case BGP_ATTR_ENCAP:
        case BGP_ATTR_PMSI_TUNNEL:
            return 1;
        default:
            return 0;
    }
}

/* data MUST be stored in the pointer ubpf_attr->data.ptr ! */
static inline int ubpf_to_frr_attr(struct attr *frr_attr, struct ubpf_attr *ubpf_attr) {

    uint32_t *cluster_list;
    struct in_addr *clust_alloc;
    struct cluster_list tmp, *cp_cluster;
    int i;

    switch (ubpf_attr->code) {
        case BGP_ATTR_ORIGIN:
            frr_attr->origin = *ubpf_attr->data.ptr == BGP_ORIGIN_EGP ? BGP_ORIGIN_EGP :
                               *ubpf_attr->data.ptr == BGP_ORIGIN_IGP ? BGP_ORIGIN_IGP : BGP_ORIGIN_INCOMPLETE;
            break;
        case BGP_ATTR_AS_PATH:
        case BGP_ATTR_AS4_PATH:
            return -1; // todo
        case BGP_ATTR_NEXT_HOP:
            frr_attr->nexthop.s_addr = htonl(*((uint32_t *) ubpf_attr->data.ptr));
            break;
        case BGP_ATTR_MULTI_EXIT_DISC:
            frr_attr->med = *((uint32_t *) ubpf_attr->data.ptr);
            break;
        case BGP_ATTR_LOCAL_PREF:
            frr_attr->local_pref = *((uint32_t *) ubpf_attr->data.ptr);
            break;
        case BGP_ATTR_ATOMIC_AGGREGATE:
            frr_attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);
            break;
        case BGP_ATTR_AGGREGATOR:
        case BGP_ATTR_AS4_AGGREGATOR:
            return -1; // TODO
        case BGP_ATTR_COMMUNITIES:
        case BGP_ATTR_LARGE_COMMUNITIES:
        case BGP_ATTR_EXT_COMMUNITIES:
            //  all communities are represented to Network Order inside FRRouting
            return -1; // TODO
        case BGP_ATTR_ORIGINATOR_ID:
            frr_attr->originator_id.s_addr = htonl(*((uint32_t *) ubpf_attr->data.ptr));
            break;
        case BGP_ATTR_CLUSTER_LIST:

            cluster_list = (uint32_t *) ubpf_attr->data.ptr;
            clust_alloc = XMALLOC(MTYPE_CLUSTER_VAL, ubpf_attr->length);
            for (i = 0; i < ubpf_attr->length / 4; i++) {
                clust_alloc[i].s_addr = htonl(cluster_list[i]);
            }

            tmp.length = ubpf_attr->length;
            tmp.list = clust_alloc;
            cp_cluster = plugin_cluster_cpy(&tmp);

            if (cp_cluster != &tmp) XFREE(MTYPE_CLUSTER_VAL, clust_alloc);

            frr_attr->cluster = cp_cluster;
            break;

        case BGP_ATTR_ENCAP:
        case BGP_ATTR_PMSI_TUNNEL:
        default:
            return -1; /* not implemented */
    }

    return 0;
}


static void clean_attr(void *_attr) {
    struct ubpf_attr *attr = _attr;
    if (!attr) return;

    if (attr->length > 8) {
        free(attr->data.ptr);
    }
}

static void *get_arg_from_type(context_t *ctx, unsigned int type_arg) {
    int i;
    bpf_full_args_t *fargs;

    fargs = ctx->args;
    for (i = 0; i < fargs->nargs; i++) {
        if (fargs->args[i].type == type_arg) {
            return fargs->args[i].arg;
        }
    }
    return NULL;
}

int copy_attr_data(struct ubpf_attr *attr, uint8_t *data, int length) {

    if (length > 8) {
        attr->data.ptr = malloc(length);
        if (!attr->data.ptr) return -1;
        memcpy(attr->data.ptr, data, length);
    } else {
        memset(&attr->data.val, 0, 8);
        memcpy(&attr->data.val, data, length);
    }

    return 0;
}

int add_attr(context_t *ctx, uint code, uint flags, uint16_t length, uint8_t *decoded_attr) {

    struct ubpf_attr attr;
    struct attr *frr_attr;
    mem_pool *mp;

    frr_attr = get_arg_from_type(ctx, ATTRIBUTE_LIST);
    if (!frr_attr) return -1;
    mp = frr_attr->ubpf_mempool;

    attr.flags = flags;
    attr.code = code;
    attr.length = length;
    attr.data.ptr = decoded_attr; /* temp storing, copy_attr_data will update this field */

    if (!mp) {
        return -1;
    }

    // if the attribute is decoded by one plugin on DECODE side
    // there must be a plugin to decode it on ENCODE side.
    // the attribute is not handled by FRRouting anymore !
    if (copy_attr_data(&attr, decoded_attr, length) != 0) return -1;

    if (add_single_mempool(mp, code, clean_attr, sizeof(struct ubpf_attr), &attr) != 0)
        return -1;

    return 0;
}

int set_attr(context_t *ctx, struct path_attribute *attr) {
    return add_attr(ctx, attr->code, attr->flags, attr->len, attr->data);
}

struct path_attribute *get_attr(context_t *ctx) {
    struct path_attribute *ubpf_attr;
    struct ubpf_attr *frr_attr;
    bpf_full_args_t *fargs;
    fargs = ctx->args;

    if (fargs->args[0].type != ATTRIBUTE) return NULL;
    frr_attr = fargs->args[0].arg;

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
    attr_len = as_path_length(aspath, 1); // default to 32-bits per ASes for the plugin
    if (attr_len == 0) return -1;
    ubpf_attr->data = ctx_malloc(ctx, attr_len);
    if (!ubpf_attr->data) return -1;
    offset = ubpf_attr->data;


    for (curr_seg = aspath->segments; curr_seg != NULL; curr_seg = curr_seg->next) {
        *offset = curr_seg->type;
        offset++;
        *((uint8_t *) offset) = curr_seg->length;
        offset += 1;

        for (i = 0; i < curr_seg->length; i++) {
            *((uint32_t *) offset) = htonl(curr_seg->as[i]);
            offset += 4;
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

static inline int set_cluster_list(context_t *ctx, struct cluster_list *c, struct path_attribute *ubpf_attr) {
    \
    uint16_t tot_len;\
    tot_len = c->length;\
    ubpf_attr->data = ctx_malloc(ctx, tot_len);\
    if (!ubpf_attr->data) return -1;\

    memcpy(ubpf_attr->data, c->list, tot_len);\
    ubpf_attr->len = tot_len;\
    ubpf_attr->flags = flags(1, 1, 0, tot_len > UINT8_MAX ? 1 : 0);\
    return 0;\

}

static inline int
set_reach_nlri(context_t *ctx, struct bgp_nlri *nlri, struct attr *attr, struct path_attribute *ubpf_attr) {

    size_t offset;
    uint8_t *buffer;

    offset = 0;
    buffer = malloc(255);
    if (!buffer) return -1;

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
frr_to_ubpf_attr(context_t *ctx, uint8_t code, struct attr *frr_attr, struct path_attribute *ubpf_attr) {

    if (!frr_attr || !ubpf_attr) return -1;
    ubpf_attr->code = code;

    if (code >= 1 && code <= 64) {
        if (!(frr_attr->flag & (1ULL << (code - 1u)))) return -1;
    } else {
        return -1; // known frr attribute identifiers are below 64
    }

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
            ubpf_attr->flags = flags(1, 0, 0, 0); // TODO CHANGE FLAGS
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

    if (frrmempool_attr) {
        if (frrmempool_to_ubpf_attr(ctx, frrmempool_attr, ubpf_attr) != 0) return NULL;
        return ubpf_attr;
    }

    // check if it is an attribute handled by frrouting
    frr_to_ubpf_attr(ctx, code, frr_route->attr, ubpf_attr);

    fprintf(stderr, "Not implemented yet...\n");
    abort();
}

struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code) {
    unsigned int i;
    struct attr *attr;
    bpf_full_args_t *fargs;
    struct ubpf_attr *frrmempool_attr;
    struct path_attribute *plugin_attr;

    fargs = ctx->args;
    attr = NULL;
    mem_pool *mp;

    attr = get_arg_from_type(ctx, ATTRIBUTE_LIST);
    if (!attr) return NULL;
    mp = attr->ubpf_mempool;

    plugin_attr = ctx_malloc(ctx, sizeof(*plugin_attr));
    if (!plugin_attr) {
        return NULL;
    }
    /* 1. first, check into the memory pool */
    frrmempool_attr = get_mempool_ptr(mp, code);
    if (frrmempool_attr) {
        if (frrmempool_to_ubpf_attr(ctx, frrmempool_attr, plugin_attr) != 0) {
            return NULL;
        } else {
            return plugin_attr;
        }
    } else {
        /* 2. if not in the memory pool, look on the attribute itself */
        if (frr_to_ubpf_attr(ctx, code, attr, plugin_attr) != 0) {
            return NULL;
        } else {
            return plugin_attr;
        }
    }
}

static inline void fill_peer_info(struct ubpf_peer_info *pinfo, struct peer *peer, int local) {
    union sockunion *sk;

    pinfo->capability = 0; // TODO
    pinfo->router_id = local ? ntohl(peer->bgp->router_id.s_addr) : ntohl(peer->remote_id.s_addr);

    sk = local == 1 ? peer->su_local : &peer->su;

    if (sk) {
        if (sk->sa.sa_family == AF_INET) { // IPv4 connection
            pinfo->addr.af = AF_INET;
            pinfo->addr.addr.in = sk->sin.sin_addr;
        } else { // IPv6 connection
            pinfo->addr.af = AF_INET6;
            pinfo->addr.addr.in6 = sk->sin6.sin6_addr;
        }
    } else {
        // local may be null
        pinfo->addr.af = AF_UNSPEC;
        memset(&pinfo->addr.addr, 0, sizeof(pinfo->addr.addr));
    }

    pinfo->as = local ? peer->bgp->as : peer->as;
    pinfo->peer_type = peer->sort == BGP_PEER_EBGP ? BGP_PEER_EBGP : BGP_PEER_IBGP;
}

static struct ubpf_peer_info *ubpf_peer_info_(context_t *ctx, int which_peer) {

    struct peer *peer = get_arg_from_type(ctx, which_peer);
    struct ubpf_peer_info *pinfo, *local_pinfo;
    if (!peer) return NULL;

    pinfo = ctx_malloc(ctx, sizeof(*pinfo));
    local_pinfo = ctx_malloc(ctx, sizeof(*local_pinfo));

    if (!pinfo || !local_pinfo) return NULL;

    fill_peer_info(pinfo, peer, 0);
    fill_peer_info(local_pinfo, peer, 1);

    pinfo->local_bgp_session = local_pinfo;

    return pinfo;
}

struct ubpf_peer_info *get_src_peer_info(context_t *ctx) {
    return ubpf_peer_info_(ctx, PEER_SRC);
}

struct ubpf_peer_info *get_peer_info(context_t *ctx, int *nb_peers) { // array of peers :'(
    struct ubpf_peer_info *ubpf_peers, *local_sessions;
    int i;
    struct peer **peers = get_arg_from_type(ctx, PEERS_TO);
    int *peer_count = get_arg_from_type(ctx, PEERS_TO_COUNT);

    if (!peers || !peer_count || !nb_peers) {
        return NULL;
    }

    ubpf_peers = ctx_malloc(ctx, *peer_count * sizeof(struct ubpf_peer_info));
    local_sessions = ctx_malloc(ctx, *peer_count * sizeof(struct ubpf_peer_info));
    if (!ubpf_peers || !local_sessions) return NULL;

    for (i = 0; i < *peer_count; i++) {
        fill_peer_info(ubpf_peers + i, peers[i], 0);
        fill_peer_info(local_sessions + i, peers[i], 0);

        ubpf_peers[i].local_bgp_session = local_sessions + i;
    }

    *nb_peers = *peer_count;
    return ubpf_peers;
}

union ubpf_prefix *get_prefix(context_t *ctx) {

    struct prefix *frr_pfx;
    union ubpf_prefix *ubpf_pfx;

    frr_pfx = get_arg_from_type(ctx, PREFIX);
    ubpf_pfx = ctx_malloc(ctx, sizeof(*ubpf_pfx));
    if (!frr_pfx) {
        fprintf(stderr, "Can't get FRR prefix\n");
        return NULL;
    }

    if (frr_pfx->family == AF_INET) {

        ubpf_pfx->family = AF_INET;
        ubpf_pfx->ip4_pfx.family = AF_INET;
        ubpf_pfx->ip4_pfx.prefix_len = frr_pfx->prefixlen;
        ubpf_pfx->ip4_pfx.p.s_addr = frr_pfx->u.prefix4.s_addr;

    } else if (frr_pfx->family == AF_INET6) {

        ubpf_pfx->family = AF_INET6;
        ubpf_pfx->ip4_pfx.family = AF_INET6;
        ubpf_pfx->ip4_pfx.prefix_len = frr_pfx->prefixlen;
        ubpf_pfx->ip6_pfx.p = frr_pfx->u.prefix6;
    } else {
        fprintf(stderr, "Unknown FRR prefix family\n");
        return NULL;
    }

    return ubpf_pfx;

}

struct ubpf_nexthop *get_nexthop(context_t *ctx, union ubpf_prefix *fx) {
    struct bgp_path_info *pi;
    struct ubpf_nexthop *nexthop;
    pi = get_arg_from_type(ctx, RIB_ROUTE);
    if (!pi) return NULL;

    nexthop = ctx_malloc(ctx, sizeof(*nexthop));

    if (!nexthop) return NULL;

    nexthop->igp_metric = pi->extra->igpmetric;
    nexthop->route_type = -1;

    return nexthop;
}
