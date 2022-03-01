//
// Created by thomas on 21/02/22.
//

#include "bgp_ubpf_attr.h"

#include <stdbool.h>
#include <string.h>
#include "hash.h"
#include "jhash.h"
#include "bgp_memory.h"
#include "assert.h"
#include <stdint.h>

#define MAX_ATTRIBUTES 256

static struct hash *attrs[MAX_ATTRIBUTES] = {0};

static struct hash *hash_attr = NULL;

inline unsigned int ubpf_attr_hash_make(const void *arg) {
    const struct custom_attr *cattr = arg;
    return jhash(cattr->pattr.data, cattr->pattr.length, 0xcafebabe + cattr->pattr.code);
}

inline bool ubpf_attr_cmp(const void *arg1, const void *arg2) {
    const struct custom_attr *attr1 = arg1;
    const struct custom_attr *attr2 = arg2;

    if (attr1 == NULL && attr2 == NULL) {
        return true;
    } if (attr1 == NULL || attr2 == NULL) {
        return false;
    }

    return ((attr1->pattr.length ==  attr2->pattr.length) &&
            (memcmp(attr1->pattr.data, attr2->pattr.data, attr1->pattr.length) == 0));
}

static void ubpf_attr_init(uint8_t code) {
    /* if hash is already init stop now */
    if (attrs[code]) return;

    attrs[code] = hash_create(ubpf_attr_hash_make, ubpf_attr_cmp, "Custom UBPF Attrs");
}


inline unsigned int rte_attr_hash_make(const void *arg) {
    const struct rte_attr_hash *rte_hash = arg;
    struct rte_attr *find;
    int idx;
    uint32_t key = 0xc0ffee;

    iterate_bitset_begin(rte_hash->bitset_attrs, 4, idx) {
        HASH_FIND_INT(rte_hash->head_hash, &idx, find);
        assert(find != NULL);
        key = jhash_1word(ubpf_attr_hash_make(find->attr), key);
    } iterate_bitset_end;

    return key;
}

static inline bool rte_attr_hash_cmp(const void *arg1, const void *arg2) {
    int idx;
    const struct rte_attr_hash *attrs1 = arg1;
    const struct rte_attr_hash *attrs2 = arg2;
    struct rte_attr *cattr1, *cattr2;

    /* check custom attrs */
    if (memcmp(attrs1->bitset_attrs,
               attrs2->bitset_attrs,
               sizeof(attrs1->bitset_attrs)) != 0) {
        return false;
    }

    iterate_bitset_begin(attrs1->bitset_attrs, 4, idx) {
        HASH_FIND_INT(attrs1->head_hash, &idx, cattr1);
        HASH_FIND_INT(attrs2->head_hash, &idx, cattr2);
        assert(cattr1 != NULL && cattr2 != NULL);
        if (cattr1->attr != cattr2->attr) {
            return false;
        }
    } iterate_bitset_end;

    return true;
}

static inline void attr_hash_init(void) {
    if (hash_attr) return;
    hash_attr = hash_create(rte_attr_hash_make, rte_attr_hash_cmp, "Hash attrs");
}

static inline void *ubpf_attr_hash_alloc(void *arg) {
    /* arg should be allocated in plugins */
    const struct custom_attr *attr = arg;
    struct custom_attr *new_attr;

    new_attr = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*attr) + attr->pattr.length);

    new_attr->refcount = 0;
    new_attr->pattr.length = attr->pattr.length;
    new_attr->pattr.code = attr->pattr.code;
    new_attr->pattr.flags = attr->pattr.flags;

    memcpy(new_attr->pattr.data, attr->pattr.data, attr->pattr.length);

    return new_attr;
}

/* attr is used with memory of plugin */
struct custom_attr *ubpf_attr_intern(struct custom_attr *attr) {
    struct custom_attr *find;

    assert(attr->refcount == 0);

    if (!attrs[attr->pattr.code]) {
        ubpf_attr_init(attr->pattr.code);
    }

    find = hash_get(attrs[attr->pattr.code], attr, hash_alloc_intern);
    if (attr != find) {
        XFREE(MTYPE_UBPF_ATTR, attr);
    }

    find->refcount += 1;

    return find;
}

void ubpf_attr_unintern(struct custom_attr **attr) {
    (*attr)->refcount -= 1;
    if ((*attr)->refcount == 0) {
        XFREE(MTYPE_UBPF_ATTR, *attr);
        *attr = NULL;
    }
}

static inline void free_rte_hash(struct rte_attr_hash **rte_hash) {
    struct rte_attr *rta, *rta_tmp;

    if (!(*rte_hash)) return;

    HASH_ITER(hh, (*rte_hash)->head_hash, rta, rta_tmp) {
        HASH_DEL((*rte_hash)->head_hash, rta);
        ubpf_attr_unintern(&rta->attr);
        XFREE(MTYPE_UBPF_ATTR, rta);
    }
    XFREE(MTYPE_UBPF_ATTR, rte_hash);
    *rte_hash = NULL;
}

struct rte_attr_hash *rte_attr_intern(struct rte_attr_hash *rte_attr) {
    struct rte_attr_hash *find;
    struct custom_attr *custom_find;
    struct rte_attr *rta, *rta_tmp;
    assert(rte_attr->refcount == 0);

    if (!hash_attr) {
        attr_hash_init();
    }

    /* intern all custom attrs */
    HASH_ITER(hh, rte_attr->head_hash, rta, rta_tmp) {
        custom_find = ubpf_attr_intern(rta->attr);
        rta->attr = custom_find;
    }

    find = hash_get(hash_attr, rte_attr, hash_alloc_intern);
    if (rte_attr != find) {
        free_rte_hash(&rte_attr);
    }

    find->refcount += 1;
    return find;
}

void rte_attr_unintern(struct rte_attr_hash **rte_attr) {
    struct rte_attr *rta, *rta_tmp;
    (*rte_attr)->refcount -= 1;

    // HERE UNINTERN CUSTOM ATTRS ?

    if ((*rte_attr)->refcount == 0) {
        free_rte_hash(rte_attr);
    }
}

void custom_attr_cpy__(struct rte_attr *rta_old, struct rte_attr **rta_new) {
    struct rte_attr *rta, *rta_tmp;
    struct rte_attr *rta_cpy;
    struct rte_attr *rta_allcpy = NULL;

    HASH_ITER(hh, rta_old, rta, rta_tmp) {
        rta_cpy = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*rta_cpy));
        rta_cpy->code = rta->code;
        rta_cpy->attr = rta->attr;

        HASH_ADD_INT(rta_allcpy, code, rta_cpy);
    }

    *rta_new = rta_allcpy;
}