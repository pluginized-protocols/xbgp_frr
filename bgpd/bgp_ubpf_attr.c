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
    }
}