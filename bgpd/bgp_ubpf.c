//
// Created by thomas on 12/03/20.
//

#include <lib/stream.h>

#include "xbgp_compliant_api/xbgp_plugin_host_api.h"
#include "ubpf_public.h"
#include <xbgp_compliant_api/xbgp_ubpf_attr.h>
#include <tools_ubpf_api.h>
#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_aspath.h"
#include "bgp_community.h"
#include "bgp_lcommunity.h"
#include "bgp_ecommunity.h"
#include "bgp_ubpf.h"
#include "bgp_io.h"
#include "bgp_packet.h"
#include "bgp_ubpf_attr.h"

static ssize_t conv_origin(struct attr *host_attr, uint8_t *buf, size_t buf_len) {
    size_t required_size = sizeof(host_attr->origin);
    if (required_size > buf_len) return -1;

    memcpy(buf, &host_attr->origin, required_size);
    return required_size;
}

static int set_origin(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    if (ubpf_attr->code != BGP_ATTR_ORIGIN) return -1;
    host_attr->origin = *ubpf_attr->data;
    return 0;
}

static ssize_t conv_aspath(struct attr *host_attr, uint8_t *buf, size_t buf_len) {

    int i;
    struct assegment *curr_seg;
    uint8_t *offset;
    uint32_t as_path_cnv;
    struct aspath *aspath = host_attr->aspath;

    offset = buf;
    for (curr_seg = aspath->segments; curr_seg != NULL; curr_seg = curr_seg->next) {

        if (!cond_cpy(buf, offset, &curr_seg->type, 1, buf_len)) return -1;
        if (!cond_cpy(buf, offset, &curr_seg->length, 1, buf_len)) return -1;

        for (i = 0; i < curr_seg->length; i++) {
            as_path_cnv = htonl(curr_seg->as[i]);
            if (!cond_cpy(buf, offset, &as_path_cnv, sizeof(uint32_t), buf_len)) {
                return -1;
            }
        }
    }

    return offset - buf;
}

static int set_aspath(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return ubpf_set_aspath(ubpf_attr, host_attr, 0);
}

static int set_as4path(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return ubpf_set_aspath(ubpf_attr, host_attr, 1);
}

#define u32_attr_fn(field, id) \
static ssize_t conv_##field (struct attr *host_attr, uint8_t *buf, size_t buf_len) { \
    if (buf_len < sizeof(host_attr->nexthop)) { \
        return -1; \
    }                      \
    if (!(host_attr->flag & ATTR_FLAG_BIT(id)))  {              \
      return -1;                       \
    }\
    memcpy(buf, &host_attr->field, sizeof(host_attr->field))       ;                \
    return sizeof(uint32_t); \
}

u32_attr_fn(nexthop, BGP_ATTR_NEXT_HOP)

u32_attr_fn(med, BGP_ATTR_MULTI_EXIT_DISC)

u32_attr_fn(local_pref, BGP_ATTR_LOCAL_PREF)

u32_attr_fn(originator_id, BGP_ATTR_ORIGINATOR_ID)

#define set_u32_attr_fn(field, attr_code)                                          \
static int set_##field(struct path_attribute *ubpf_attr, struct attr *host_attr) { \
    uint32_t conv_u32val;                                                          \
    if (ubpf_attr->code != attr_code) {                                            \
        return -1;                                                                 \
    }                                                                              \
    memcpy(&conv_u32val, ubpf_attr->data, sizeof(uint32_t));                       \
    conv_u32val = ntohl(conv_u32val);                                              \
    memcpy(&host_attr->field, &conv_u32val, sizeof(uint32_t));                     \
    return 0;                                                                      \
}

set_u32_attr_fn(nexthop, BGP_ATTR_NEXT_HOP)

set_u32_attr_fn(med, BGP_ATTR_MULTI_EXIT_DISC)

set_u32_attr_fn(local_pref, BGP_ATTR_LOCAL_PREF)

set_u32_attr_fn(originator_id, BGP_ATTR_ORIGINATOR_ID)


static ssize_t conv_aggregator(struct attr *host_attr, uint8_t *buf, size_t buf_len) {
    uint8_t *offset;

    offset = buf;

    if (!cond_cpy(buf, offset, &host_attr->aggregator_as, sizeof(host_attr->aggregator_addr), buf_len)) {
        return -1;
    }
    if (!cond_cpy(buf, offset, &host_attr->aggregator_addr, sizeof(host_attr->aggregator_addr), buf_len)) {
        return -1;
    }
    return offset - buf;
}

static int set_aggregator_(struct path_attribute *ubpf_attr, struct attr *host_attr, int as4n) {
    uint8_t *offset;
    if (ubpf_attr->code != BGP_ATTR_AGGREGATOR && ubpf_attr->code != BGP_ATTR_AS4_AGGREGATOR) {
        return -1;
    }

    offset = ubpf_attr->data;

    host_attr->aggregator_as = as4n ? *(uint32_t *) offset : *(uint16_t *) offset;
    offset += as4n ? 4 : 2;

    memcpy(&host_attr->aggregator_addr, offset, sizeof(uint32_t));

    return 0;
}

static int set_aggregator(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return set_aggregator_(ubpf_attr, host_attr, 0);
}

static int set_aggregator4(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return set_aggregator_(ubpf_attr, host_attr, 1);
}

#define communities_func(community_type, size_community) \
static ssize_t conv_##community_type (struct attr *host_attr, uint8_t *buf, size_t buf_len) {\
    uint16_t tot_len = host_attr->community_type->size * size_community;\
    if (tot_len > buf_len) {\
        return -1;\
    }\
    memcpy(buf, host_attr->community_type->val, tot_len);\
    return tot_len;\
}

communities_func(community, 4)

communities_func(lcommunity, 6)

communities_func(ecommunity, 8)


static ssize_t conv_cluster_list(struct attr *host_attr, uint8_t *buf, size_t buf_len) {
    uint16_t tot_len;
    if (!host_attr->cluster) return -1;
    tot_len = host_attr->cluster->length;


    if (tot_len > buf_len) return -1;
    memcpy(buf, host_attr->cluster->list, host_attr->cluster->length);
    return tot_len;
}

static ssize_t noop(struct attr *host_attr, uint8_t *buf, size_t buf_len) {
    return 0;
}


static ssize_t conv_err(struct attr *host_attr, uint8_t *buf, size_t buf_len) {
    return -1;
}

static int set_err(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return -1;
}

static int set_noop(struct path_attribute *ubpf_attr, struct attr *host_attr) {
    return 0;
}


static struct {
    ssize_t (*conv_attr)(struct attr *host_attr, uint8_t *temp, size_t buf_len);

    int (*set_attr)(struct path_attribute *attr, struct attr *host_attr);

    uint16_t flags;
} michel[] = {
        [BGP_ATTR_ORIGIN] = {
                .conv_attr = conv_origin,
                .set_attr = set_origin,
                .flags = BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_AS4_PATH] = {
                .conv_attr = conv_aspath,
                .set_attr = set_as4path,
                .flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_LOCAL_PREF] = {
                .conv_attr = conv_local_pref,
                .set_attr = set_local_pref,
                .flags = BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_AS_PATH] = {
                .conv_attr = conv_aspath,
                .set_attr = set_aspath,
                .flags = BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_NEXT_HOP] = {
                .conv_attr = conv_nexthop,
                .set_attr= set_nexthop,
                .flags = BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_MULTI_EXIT_DISC] = {
                .conv_attr = conv_med,
                .set_attr= set_med,
                .flags = BGP_ATTR_FLAG_OPTIONAL
        },
        [BGP_ATTR_ATOMIC_AGGREGATE] = {
                .conv_attr = noop,
                .set_attr = set_noop,
                .flags = BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_AGGREGATOR] = {
                .conv_attr = conv_aggregator,
                .set_attr= set_aggregator,
                .flags = BGP_ATTR_FLAG_TRANS | BGP_ATTR_FLAG_OPTIONAL
        },
        [BGP_ATTR_AS4_AGGREGATOR] = {
                .conv_attr = conv_aggregator,
                .set_attr = set_aggregator4,
                .flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_COMMUNITIES] = {
                .conv_attr = conv_community,
                .set_attr = set_ubpf_community,
                .flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_LARGE_COMMUNITIES] = {
                .conv_attr = conv_lcommunity,
                .set_attr = set_ubpf_lcommunity,
                .flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_EXT_COMMUNITIES] = {
                .conv_attr = conv_ecommunity,
                .set_attr = set_ubpf_ecommunity,
                .flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANS
        },
        [BGP_ATTR_ORIGINATOR_ID] = {
                .conv_attr = conv_originator_id,
                .set_attr = set_originator_id,
                .flags = BGP_ATTR_FLAG_OPTIONAL
        },
        [BGP_ATTR_CLUSTER_LIST] = {
                .conv_attr = conv_cluster_list,
                .set_attr = set_ubpf_cluster_list,
                .flags = BGP_ATTR_FLAG_OPTIONAL
        },
        [BGP_ATTR_MP_REACH_NLRI] = {
                .conv_attr = conv_err,
                .set_attr = set_err,
                .flags = BGP_ATTR_FLAG_OPTIONAL
        },
        [BGP_ATTR_MP_UNREACH_NLRI] = {
                .conv_attr = conv_err,
                .set_attr = set_err,
                .flags = BGP_ATTR_FLAG_OPTIONAL
        },
};


static inline uint8_t flags(unsigned int optional, unsigned int transitive,
                            unsigned int partial, unsigned int length) {

    return (((optional << 3u) & 8u) |
            ((transitive << 2u) & 4u) |
            ((partial << 1u) & 2u) |
            (length & 1u)) << 4u;

}

static inline int ubpf_to_frr_attr(struct attr *frr_attr, struct path_attribute *ubpf_attr) {

    switch (ubpf_attr->code) {
        case BGP_ATTR_ORIGIN:
        case BGP_ATTR_AS4_PATH:
        case BGP_ATTR_AS_PATH:
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
            if (michel[ubpf_attr->code].set_attr(ubpf_attr, frr_attr) != 0) {
                return -1;
            }
            break;
        case BGP_ATTR_MP_REACH_NLRI:   // MP-BGP is handled in a special way.
        case BGP_ATTR_MP_UNREACH_NLRI: // They are treated directly in the UPDATE process
        default:
            return -1; //not handled by FRRouting !
    }

    return 0;
}


static inline void set_index(uint64_t *bitarray, size_t idx) {
    bitarray[idx / 64] |= (1 << (idx % 64));
}

int add_attr(context_t *ctx, uint8_t code, uint8_t flags, uint16_t length, uint8_t *decoded_attr) {
    struct attr *frr_attr;
    struct custom_attr *attr;
    struct rte_attr *rt_attr;
    struct rte_attr *rt_find;
    frr_attr = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE_LIST);
    if (!frr_attr) return -1;

    attr = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*attr) + length);
    rt_attr = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*rt_attr));

    attr->pattr.flags = flags;
    attr->pattr.code = code;
    attr->pattr.length = length;
    attr->refcount = 0;

    rt_attr->attr = attr;
    rt_attr->code = code;

    // if the attribute is decoded by one plugin on DECODE side
    // there must be a plugin to decode it on ENCODE side.
    // the attribute is not handled by FRRouting anymore !
    memcpy(attr->pattr.data, decoded_attr, length);

    if (!frr_attr->custom_attrs) {
        frr_attr->custom_attrs = XCALLOC(MTYPE_UBPF_ATTR, sizeof(*frr_attr->custom_attrs));
    }
    /* check if the hashmap is already interned.
     * if yes, we must copy the hashmap to avoid
     * modifying routes using the old interned
     * attribute structure */
    if (frr_attr->custom_attrs->refcount > 0) {
        frr_attr->custom_attrs = custom_attr_cpy(frr_attr->custom_attrs);
        assert(frr_attr->custom_attrs->refcount == 0);
    }

    DL_SEARCH(frr_attr->custom_attrs->head_hash, rt_find, rt_attr, rte_attr_cmp);
    if (rt_find) {
        DL_DELETE(frr_attr->custom_attrs->head_hash, rt_find);
        XFREE(MTYPE_UBPF_ATTR, rt_find);
        frr_attr->custom_attrs -= 1;
    }

    DL_APPEND(frr_attr->custom_attrs->head_hash, rt_find);
    return 0;
}

int set_attr(context_t *ctx, struct path_attribute *attr) {
    return add_attr(ctx, attr->code, attr->flags, attr->length, attr->data);
}

struct path_attribute *get_attr(context_t *ctx) {
    struct path_attribute *ubpf_attr;
    struct path_attribute *frr_attr;
    size_t tot_len;

    frr_attr = get_arg_from_type(ctx, ARG_BGP_ATTRIBUTE);
    if (!frr_attr) return NULL;

    tot_len = sizeof(struct path_attribute) + frr_attr->length;
    ubpf_attr = ctx_malloc(ctx, tot_len);
    if (!ubpf_attr) return NULL;

    memcpy(ubpf_attr, frr_attr, tot_len);

    return ubpf_attr;
}

int write_to_buffer(context_t *ctx, uint8_t *ptr, size_t len) {
    size_t bytes_written;
    struct stream *s;

    s = get_arg_from_type(ctx, WRITE_STREAM);
    if (!s) return -1;
    bytes_written = stream_write(s, ptr, len);
    if (bytes_written != len) return -1;

    return 0;
}


#define check_or_fail(code)                                 \
do {                                                        \
    if (!CHECK_FLAG(frr_attr->flag, ATTR_FLAG_BIT(code))) { \
        return -1;                                          \
    }                                                       \
} while(0)

#define ATTR_FLAG_BIT_CUST(X) ({   \
    int _ret;                      \
    if ((X) >= 1 && (X) <= 64) {   \
        _ret = 1ULL << ((X)-1u);    \
    } else {                       \
        _ret = 0;                  \
    }                              \
    _ret;                          \
})

static inline struct path_attribute *
frr_to_ubpf_attr(context_t *ctx, uint8_t code, struct attr *frr_attr) {
    uint8_t *buf;
    int data_attr_len;
    struct path_attribute *attr;

    buf = malloc(MAX_BUF_LEN);
    if (!buf) {
        return NULL;
    }

    switch (code) {
        case BGP_ATTR_ORIGIN:
        case BGP_ATTR_AS4_PATH:
        case BGP_ATTR_AS_PATH:
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
            data_attr_len = michel[code].conv_attr(frr_attr, buf, MAX_BUF_LEN);
            if (data_attr_len == -1) goto err;
            break;
        case BGP_ATTR_MP_REACH_NLRI:   // MP-BGP is handled in a special way.
        case BGP_ATTR_MP_UNREACH_NLRI: // They are treated directly in the UPDATE process
        default:
            return NULL; //not handled !
    }

    attr = ctx_malloc(ctx, sizeof(struct path_attribute) + data_attr_len);
    if (!attr) goto err;

    attr->code = code;
    attr->length = data_attr_len;
    memcpy(attr->data, buf, data_attr_len);
    attr->flags = michel[code].flags;
    free(buf);
    return attr;
    err:
    free(buf);
    return NULL;
}

static struct path_attribute *get_attr_by_code__(context_t *ctx, int code, int args_rte) {
    struct attr *frr_attr = NULL;
    struct path_attribute *mempool_attr, *ret_attr;
    struct rte_attr *find = NULL;
    struct rte_attr to_find;
    to_find.code = code;

    switch (args_rte) {
        case ARG_BGP_ROUTE_NEW:
        case ARG_BGP_ROUTE_OLD:
        case ARG_BGP_ROUTE:
            frr_attr = ((struct bgp_path_info *) get_arg_from_type(ctx, args_rte))->attr;
            break;
        case ARG_BGP_ATTRIBUTE:
        case ARG_BGP_ATTRIBUTE_LIST:
            frr_attr = get_arg_from_type(ctx, args_rte);
            break;
        default:
            return NULL;
    }

    if (!frr_attr) return NULL;
    /* 1. check first attr is in custom_attr */
    if (frr_attr->custom_attrs) {
        DL_SEARCH(frr_attr->custom_attrs->head_hash, find, &to_find, rte_attr_cmp);
    }

    if (find) {
        /* if in mempool set mempool attr*/
        mempool_attr = &find->attr->pattr;
    } else {
        /* if not in mempool, check if stored by frr internals */
        return frr_to_ubpf_attr(ctx, code, frr_attr);
    }

    /* if in mempool */
    if (mempool_attr) {
        ret_attr = ctx_malloc(ctx, sizeof(struct path_attribute) + mempool_attr->length);
        if (!ret_attr) return NULL;
        memcpy(ret_attr, mempool_attr, sizeof(struct path_attribute) + mempool_attr->length);
        return ret_attr;
    }
    return NULL;
}


struct path_attribute *get_attr_from_code(context_t *ctx, uint8_t code) {
    return get_attr_by_code__(ctx, code, ARG_BGP_ATTRIBUTE_LIST);
}

struct path_attribute *get_attr_from_code_by_route(context_t *ctx, uint8_t code, int rte) {

    int rte_to_internal_id;

    switch (rte) {
        case BGP_ROUTE_TYPE_NEW:
            rte_to_internal_id = ARG_BGP_ROUTE_NEW;
            break;
        case BGP_ROUTE_TYPE_OLD:
            rte_to_internal_id = ARG_BGP_ROUTE_OLD;
            break;
        case BGP_ROUTE_TYPE_UNDEF:
            rte_to_internal_id = ARG_BGP_ROUTE;
            break;
        default:
            return NULL;
    }

    return get_attr_by_code__(ctx, code, rte_to_internal_id);
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
    pinfo->peer_type = peer->sort == BGP_PEER_EBGP ? EBGP_SESSION : IBGP_SESSION;
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


static int frr_prefix_to_ubpf(struct prefix *frr_pfx, struct ubpf_prefix *ubpf_pfx) {

    ubpf_pfx->prefixlen = frr_pfx->prefixlen;

    switch (frr_pfx->family) {
        case AF_INET:
            ubpf_pfx->afi = XBGP_AFI_IPV4;
            ubpf_pfx->safi = XBGP_SAFI_UNICAST;
            memcpy(ubpf_pfx->u, &frr_pfx->u.prefix4, sizeof(frr_pfx->u.prefix4.s_addr));
            break;
        case AF_INET6:
            ubpf_pfx->afi = XBGP_AFI_IPV6;
            ubpf_pfx->safi = XBGP_SAFI_UNICAST;
            memcpy(ubpf_pfx->u, &frr_pfx->u.prefix6, sizeof(frr_pfx->u.prefix6));
            break;
        default:
            // not handled
            return -1;
    }

    return 0;
}

static inline int ubpf_prefix_to_frr(struct ubpf_prefix *pfx, struct prefix *frr_pfx) {
    memset(frr_pfx, 0, sizeof(*frr_pfx));
    frr_pfx->prefixlen = pfx->prefixlen;

    switch (pfx->afi) {
        case XBGP_AFI_IPV4:
            frr_pfx->family = AF_INET;
            memcpy(&frr_pfx->u.prefix4, pfx->u, sizeof(frr_pfx->u.prefix4));
            break;
        case XBGP_AFI_IPV6:
            frr_pfx->family = AF_INET6;
            memcpy(&frr_pfx->u.prefix6, pfx->u, sizeof(frr_pfx->u.prefix6));
            break;
        default:
            return -1;
    }
    return 0;
}

struct ubpf_prefix *get_prefix(context_t *ctx) {

    struct prefix *frr_pfx;
    struct ubpf_prefix *ubpf_pfx;

    frr_pfx = get_arg_from_type(ctx, ARG_BGP_PREFIX);
    ubpf_pfx = ctx_malloc(ctx, sizeof(*ubpf_pfx));
    if (!frr_pfx) {
        fprintf(stderr, "Can't get FRR prefix\n");
        return NULL;
    }

    if (frr_prefix_to_ubpf(frr_pfx, ubpf_pfx) != 0) return NULL;

    return ubpf_pfx;

}

struct ubpf_nexthop *get_nexthop(context_t *ctx, struct ubpf_prefix *fx) {
    struct bgp_path_info *pi;
    struct ubpf_nexthop *nexthop;
    pi = get_arg_from_type(ctx, ARG_BGP_ROUTE_RIB);
    if (!pi) return NULL;

    nexthop = ctx_malloc(ctx, sizeof(*nexthop));

    if (!nexthop) return NULL;
    if (!pi->extra) {
        nexthop->igp_metric = 0;
    } else {
        nexthop->igp_metric = pi->extra->igpmetric;
    }

    nexthop->route_type = -1;

    return nexthop;
}

static int get_set_attrs(struct attr *attr, short *set_attr, size_t set_attr_len) {

    int len, i;
    size_t nb_attrs;
    short attr_ids[] = {
            BGP_ATTR_ORIGIN, BGP_ATTR_AS_PATH, BGP_ATTR_NEXT_HOP,
            BGP_ATTR_MULTI_EXIT_DISC, BGP_ATTR_LOCAL_PREF, BGP_ATTR_ATOMIC_AGGREGATE,
            BGP_ATTR_AGGREGATOR, BGP_ATTR_COMMUNITIES, BGP_ATTR_ORIGINATOR_ID,
            BGP_ATTR_CLUSTER_LIST, BGP_ATTR_DPA, BGP_ATTR_ADVERTISER,
            BGP_ATTR_RCID_PATH, BGP_ATTR_MP_REACH_NLRI, BGP_ATTR_MP_UNREACH_NLRI,
            BGP_ATTR_EXT_COMMUNITIES, BGP_ATTR_AS4_PATH, BGP_ATTR_AS4_AGGREGATOR,
            BGP_ATTR_AS_PATHLIMIT, BGP_ATTR_PMSI_TUNNEL, BGP_ATTR_ENCAP,
            BGP_ATTR_LARGE_COMMUNITIES, BGP_ATTR_PREFIX_SID
    };

    len = sizeof(attr_ids) / sizeof(attr_ids[0]);

    for (i = 0, nb_attrs = 0; i < len; i++) {

        if (CHECK_FLAG(attr->flag, ATTR_FLAG_BIT_CUST(attr_ids[i]))) {
            if (nb_attrs >= set_attr_len) return -1;
            set_attr[nb_attrs++] = attr_ids[i];
        }
    }
    return nb_attrs;
}

static int bgp_rte_node_to_ubpf(context_t *ctx, struct bgp_path_info *pi, struct prefix *p, struct bgp_route **rte_) {
    short set_attr[30];
    int nb_attrs;
    int i;
    struct path_attribute *pattr;
    struct bgp_route *rte;

    if (pi == NULL) {
        fprintf(stderr, "pi null\n");
        goto err;
    }
    if (p == NULL) {
        fprintf(stderr, "p null\n");
        goto err;
    }

    nb_attrs = get_set_attrs(pi->attr, set_attr, sizeof(set_attr) / sizeof(set_attr[0]));
    if (nb_attrs == -1) {
        return -1;
    }

    rte = ctx_malloc(ctx, sizeof(*rte));
    if (!rte) goto err;
    memset(rte, 0, sizeof(*rte));
    *rte_ = rte;

    frr_prefix_to_ubpf(p, &rte->pfx);
    rte->attr_nb = nb_attrs;

    rte->attr = ctx_malloc(ctx, nb_attrs * sizeof(struct path_attribute *));
    if (!rte->attr) goto err;

    rte->peer_info = ctx_calloc(ctx, 1, sizeof(struct ubpf_peer_info));
    if (!rte->peer_info) goto err;

    for (i = 0; i < nb_attrs; i++) {
        pattr = frr_to_ubpf_attr(ctx, set_attr[i], pi->attr);
        if (pattr == NULL) goto err;
        rte->attr[i] = pattr;
    }

    fill_peer_info(rte->peer_info, pi->peer, 0);
    rte->type = pi->type;
    rte->uptime = bgp_clock() - pi->uptime; // TODO TEST !
    return 0;

    err:
    return -1;
}

struct bgp_route *get_bgp_route(context_t *ctx, enum BGP_ROUTE_TYPE type) {
    struct bgp_route *rte;
    struct bgp_path_info *pi;
    short set_attr[30];

    switch (type) {
        case BGP_ROUTE_TYPE_NEW:
            pi = get_arg_from_type(ctx, ARG_BGP_ROUTE_NEW);
            break;
        case BGP_ROUTE_TYPE_OLD:
            pi = get_arg_from_type(ctx, ARG_BGP_ROUTE_OLD);
            break;
        case BGP_ROUTE_TYPE_UNDEF:
            pi = get_arg_from_type(ctx, ARG_BGP_ROUTE);
            break;
        case BGP_ROUTE_TYPE_UNKNOWN:
        case BGP_ROUTE_TYPE_FAIL:
            return NULL;
    }

    if (!pi) return NULL;
    if (!pi->net) return NULL;

    memset(set_attr, 0, sizeof(set_attr));

    if (bgp_rte_node_to_ubpf(ctx, pi, &pi->net->p, &rte) != 0) return NULL;

    return rte;
}

int set_peer_info(context_t *ctx, uint32_t router_id, int key, void *value, int len) {
    // TODO. Not handled yet
    return -1;
}


#define MAX_ITER_ID 256
static bgp_table_iter_t *iters[256] = {0};
static int alloc_table_iter = -1;


int new_rib_iterator(context_t *ctx, int afi, int safi) {
    int i;
    struct bgp *bgp;
    bgp_table_iter_t iter;

    bgp = bgp_get_default();
    if (!bgp) return -1;

    bgp_table_iter_init(&iter, bgp->rib[afi][safi]);

    for (i = 0; i < MAX_ITER_ID; i++) {
        alloc_table_iter = (alloc_table_iter + 1) % MAX_ITER_ID;
        if (iters[alloc_table_iter] == NULL) {
            iters[alloc_table_iter] = malloc(sizeof(*iters[alloc_table_iter]));
            if (!iters[alloc_table_iter]) return -1;

            memcpy(iters[alloc_table_iter], &iter, sizeof(iter));
            return alloc_table_iter;
        }
    }

    return -1;
}

struct bgp_route *next_rib_route(context_t *ctx, unsigned int iterator_id) {
    struct bgp_route *rte;
    struct bgp_path_info *pi;
    bgp_table_iter_t *it;
    struct bgp_node *n;

    if (iterator_id >= MAX_ITER_ID) return NULL;

    it = iters[iterator_id];
    if (it == NULL) return NULL;

    if (bgp_table_iter_is_done(it)) {
        rib_iterator_clean(ctx, iterator_id);
        return NULL;
    }

    if (!rib_has_route(ctx, iterator_id)) {
        return NULL;
    }

    n = bgp_table_iter_next(it);

    for (; n; n = bgp_table_iter_next(it)) {
        for (pi = bgp_node_get_bgp_path_info(n); pi; pi = pi->next) {
            if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&

                (pi->type == ZEBRA_ROUTE_BGP
                 && (pi->sub_type == BGP_ROUTE_NORMAL
                     || pi->sub_type == BGP_ROUTE_IMPORTED))) {

                if (bgp_rte_node_to_ubpf(ctx, pi, &n->p, &rte) == -1) goto err;
                return rte;
            }
        }
    }

    err:
    return NULL;
}

int rib_has_route(context_t *ctx, unsigned int iterator_id) {
    bgp_table_iter_t *it;

    if (iterator_id > MAX_ITER_ID) return 0;
    it = iters[iterator_id];
    if (it == NULL) return 0;

    return !bgp_table_iter_is_done(it);
}

void rib_iterator_clean(context_t *ctx, unsigned int iterator_id) {
    bgp_table_iter_t *it;

    if (iterator_id > MAX_ITER_ID) return;
    it = iters[iterator_id];
    if (it == NULL) return;

    bgp_table_iter_cleanup(it);
    free(it);
    iters[iterator_id] = NULL;
}

static int equal_addr(struct ubpf_peer_info *pinfo, union sockunion *frr_remote_socket) {
    /* both family must be equal to compare their addresses */
    if (frr_remote_socket->sa.sa_family != pinfo->addr.af) return 0;

    switch (pinfo->addr.af) {
        case AF_INET:
            return pinfo->addr.addr.in.s_addr == frr_remote_socket->sin.sin_addr.s_addr;
        case AF_INET6:
            return memcmp(&pinfo->addr.addr.in6, &frr_remote_socket->sin6.sin6_addr,
                          sizeof(pinfo->addr.addr.in6)) == 0;
        default:
            return 0;
    }
}

int remove_route_from_rib(context_t *ctx, struct ubpf_prefix *pfx, struct ubpf_peer_info *pinfo) {
    struct bgp *bgp;
    struct bgp_table *table;
    struct prefix frr_pfx;
    bgp = bgp_get_default();
    int match = 0;

    if (bgp) return -1;

    table = bgp->rib[pfx->afi][pfx->safi];

    struct list *matches = list_new();
    matches->del = (void (*)(void *)) bgp_unlock_node;

    ubpf_prefix_to_frr(pfx, &frr_pfx);

    bgp_table_range_lookup(table, &frr_pfx, pfx->prefixlen, matches);

    /* search for peers that hold the route with pinfo */
    struct bgp_node *bgp_node;
    struct listnode *bgp_listnode;
    struct bgp_path_info *bgp_path_info;

    for (ALL_LIST_ELEMENTS_RO(matches, bgp_listnode, bgp_node)) {
        bgp_path_info = bgp_node_get_bgp_path_info(bgp_node);
        if (!bgp_path_info) continue;

        if (pinfo->router_id != 0) {
            if (pinfo->router_id == bgp_path_info->peer->remote_id.s_addr) {
                match = 1;
                break;
            }
        } else if (equal_addr(pinfo, bgp_path_info->peer->su_remote)) {
            match = 1;
            break;
        }

    }

    /* then delete the route from rib */
    if (match) {
        /* handles the withdraw announce */
        bgp_rib_remove(bgp_node, bgp_path_info, bgp_path_info->peer, pfx->afi, pfx->safi);
    }

    list_delete(&matches);
    return 0;
}

struct bgp_route *get_rib_out_entry(context_t *ctx, uint8_t af_family,
        struct ubpf_prefix *pfx, struct ubpf_peer_info *pinfo) {
    struct bgp *bgp;
    struct prefix p;
    struct bgp_node *n;
    struct bgp_path_info *pi;
    struct bgp_route *rte;

    bgp = bgp_get_default();
    if (!bgp) return NULL;

    p.family = afi2family(pfx->afi);
    p.prefixlen = pfx->prefixlen;
    if (pfx->afi == XBGP_AFI_IPV4) {
        memcpy(&p.u.prefix4, pfx->u, sizeof(p.u.prefix4));
    } else {
        memcpy(&p.u.prefix6, pfx->u, sizeof(p.u.prefix6));
    }

    n = bgp_node_match(bgp->rib[pfx->afi][pfx->safi], &p);
    if (!n) return NULL;

    for (pi = bgp_node_get_bgp_path_info(n); pi; pi = pi->next) {
        if (pi->type == ZEBRA_ROUTE_BGP &&
            (pi->sub_type == BGP_ROUTE_NORMAL || pi->sub_type == BGP_ROUTE_IMPORTED) &&
            memcmp(&pi->peer->remote_id.s_addr, &pinfo->router_id, sizeof(pinfo->router_id)) == 0) {

            if (bgp_rte_node_to_ubpf(ctx, pi, &pi->net->p, &rte) != 0) return NULL;
            return rte;
        }
    }


    return NULL;
}

int get_vrf(context_t *ctx, struct vrf_info *info) {
    const char *vrf_name;
    size_t vrf_name_len;
    int *vrf_id;

    if (!info) return -1;
    vrf_id = get_arg_from_type(ctx, ARG_BGP_VRF);
    if (vrf_id == NULL) return -1;

    vrf_name = vrf_id_to_name(*vrf_id);
    vrf_name_len = strnlen(vrf_name, IF_NAMESIZE);

    if (strncmp(vrf_name, "n/a", MIN(4, vrf_name_len)) == 0) return -1;
    if (info->str_len >= vrf_name_len) {
        strncpy(info->name, vrf_name, vrf_name_len);
    }
    info->vrf_id = *vrf_id;

    return 0;
}


static struct peer *bgp_find_peer__(const char *peer_str) {
    union sockunion su;
    return str2sockunion(peer_str, &su) ? NULL : peer_lookup(NULL, &su);
}


int schedule_bgp_message(context_t *ctx, int type, struct bgp_message *message, const char *peer_ip) {
    struct stream *s;
    struct peer *peer;

    peer = bgp_find_peer__(peer_ip);

    if (!peer) return -1;
    if (!message->buf || message->buf_len <= 0) return -1;

    s = stream_new(BGP_MAX_PACKET_SIZE);

    bgp_packet_set_marker(s, type);
    stream_put(s, message->buf, message->buf_len);
    bgp_packet_set_size(s);

    bgp_packet_add(peer, s);
    bgp_writes_on(peer);
    return 0;
}

/**
 * Very dangerous, must be used
 * only if graceful restart is supported
 * AND enabled in both BGP speakers (i.e.
 * us and the remote neighbor)
 */
int peer_session_reset(context_t *ctx, const char *peer_ip) {
    struct peer *peer;
    peer = bgp_find_peer__(peer_ip);

    if (!peer) return -1;
    if (!bgp_flag_check(peer->bgp, BGP_FLAG_GRACEFUL_RESTART)) {
        // graceful restart not enabled
        // don't reset the connection
        return -1;
    }

    bgp_session_reset(peer);
    return 0;
}