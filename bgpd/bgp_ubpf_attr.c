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

inline int rte_attr_cmp(const struct rte_attr *attr1, const struct rte_attr *attr2) {
    return attr1->code - attr2->code;
}

inline unsigned int ubpf_attr_hash_make(const void *arg) {
    uint32_t my_hash;
    struct custom_attr *cattr = (void *) arg; // gcc silent this
    my_hash = jhash(cattr->pattr.data, cattr->pattr.length, 0xcafebabe + cattr->pattr.code);

    cattr->cached_hash = my_hash;
    return my_hash;
}

inline bool ubpf_attr_cmp(const void *arg1, const void *arg2) {
    const struct custom_attr *attr1 = arg1;
    const struct custom_attr *attr2 = arg2;

    if (attr1 == NULL && attr2 == NULL) {
        return true;
    }
    if (attr1 == NULL || attr2 == NULL) {
        return false;
    }

    return ((attr1->pattr.length == attr2->pattr.length) &&
            (memcmp(attr1->pattr.data, attr2->pattr.data, attr1->pattr.length) == 0));
}

static void ubpf_attr_init(uint8_t code) {
    /* if hash is already init stop now */
    if (attrs[code]) return;

    attrs[code] = hash_create(ubpf_attr_hash_make, ubpf_attr_cmp, "Custom UBPF Attrs");
}


inline unsigned int rte_attr_hash_make(const void *arg) {
    const struct rte_attr_hash *rte_hash = arg;
    struct rte_attr *rta;
    uint32_t key = 0xc0ffee;

    DL_FOREACH(rte_hash->head_hash, rta) {
        /* hash precomputed at attribute creation */
        key = jhash_1word(rta->attr->cached_hash, key);
    }
    return key;
}

static inline bool rte_attr_hash_cmp(const void *arg1, const void *arg2) {
    const struct rte_attr_hash *attrs1 = arg1;
    const struct rte_attr_hash *attrs2 = arg2;
    struct rte_attr *rta1, *rta2;

    if (attrs1 == NULL && attrs2 == NULL) {
        return true;
    }
    if (attrs1 == NULL || attrs2 == NULL) {
        return false;
    }

    /* check custom attrs */
    if (attrs1->nb_elems != attrs2->nb_elems) return false;

    for (rta1 = attrs1->head_hash, rta2 = attrs2->head_hash;
         rta1 && rta2; rta1 = rta1->next, rta2 = rta2->next) {
        if (rta1->attr != rta2->attr) {
            return false;
        }
    }
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
    struct custom_attr *ret;
    if (!*attr) return;
    if ((*attr)->refcount) {
        (*attr)->refcount -= 1;
    }
    if ((*attr)->refcount == 0) {
        ret = hash_release(attrs[(*attr)->pattr.code], *attr);
        assert(ret != NULL);
        XFREE(MTYPE_UBPF_ATTR, *attr);
        *attr = NULL;
    }
}

static inline void free_rte_hash(struct rte_attr_hash **rte_hash) {
    struct rte_attr *rta, *rta_tmp;

    if (!(*rte_hash)) return;

    DL_FOREACH_SAFE((*rte_hash)->head_hash, rta, rta_tmp) {
        DL_DELETE((*rte_hash)->head_hash, rta);
        ubpf_attr_unintern(&rta->attr);
        XFREE(MTYPE_UBPF_ATTR, rta);
    }
    XFREE(MTYPE_UBPF_ATTR, *rte_hash);
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

    /* NO ! done at attr creation ! intern all custom attrs */
    /*DL_FOREACH_SAFE(rte_attr->head_hash, rta, rta_tmp) {
        custom_find = ubpf_attr_intern(rta->attr);
        rta->attr = custom_find;
    }*/

    DL_SORT(rte_attr->head_hash, rte_attr_cmp);

    find = hash_get(hash_attr, rte_attr, hash_alloc_intern);
    if (rte_attr != find) {
        free_rte_hash(&rte_attr);
    }

    find->refcount += 1;
    return find;
}

void rte_attr_unintern(struct rte_attr_hash **rte_attr) {
    struct rte_attr_hash *attr;
    struct rte_attr_hash *ret;
    if (!*rte_attr) return;

    attr = *rte_attr;

    if (attr->refcount) {
        attr->refcount -= 1;
    }

    // HERE UNINTERN CUSTOM ATTRS ?

    if (attr->refcount == 0) {
        ret = hash_release(hash_attr, *rte_attr);
        assert(ret != NULL);
        free_rte_hash(rte_attr);
    }
}

struct rte_attr_hash *custom_attr_cpy(struct rte_attr_hash *rta_old) {
    struct rte_attr_hash *new_hash;
    struct rte_attr *rta, *rta_cpy;

    new_hash = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*new_hash));

    new_hash->head_hash = NULL;
    new_hash->nb_elems = rta_old->nb_elems;
    new_hash->refcount = 0; // rta_old->refcount;

    DL_FOREACH(rta_old->head_hash, rta) {
        rta_cpy = XMALLOC(MTYPE_UBPF_ATTR, sizeof(*rta_cpy));
        rta_cpy->code = rta->code;
        rta_cpy->attr = rta->attr;

        /* already sorted, now need to sort */
        DL_APPEND(new_hash->head_hash, rta_cpy);
        rta->attr->refcount += 1;
    }

    return new_hash;
}