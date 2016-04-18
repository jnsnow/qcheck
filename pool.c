#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include "pool.h"

typedef struct pool {
    void *pool;
    struct pool *next;
} pool;

struct poolset {
    pool *pools;       /* link to first pool */
    pool *active;      /* link to active pool */
    size_t length;     /* size of each pool */
    size_t atom_size;  /* size of each element within a pool */
    size_t last_i;     /* allocation index */
    int (*empty)(void *); /* callback to check if an element is empty/unused */
};

poolset *new_poolset(uint64_t pool_length, uint64_t atom_size)
{
    poolset *ps;

    if (pool_length == 0 || atom_size == 0) {
        return NULL;
    }

    ps = (poolset *)calloc(1, sizeof(poolset));
    if (!ps) {
        return NULL;
    }

    ps->length = pool_length;
    ps->atom_size = atom_size;
    return ps;
}

void delete_poolset(poolset *ps)
{
    pool *node, *tmp;

    for (node = ps->pools; node;) {
        free(node->pool);
        tmp = node->next;
        free(node);
        node = tmp;
    }
    free(ps);
}

static int alloc_pool(poolset *ps)
{
    void *tmp;
    pool *node;
    int rc;

    if (!ps) {
        return -1;
    }

    node = (pool *)malloc(sizeof(pool));
    if (!node) {
        rc = -errno;
        return rc;
    }
    node->next = NULL;

    assert(ps->length && ps->atom_size);
    tmp = calloc(ps->length, ps->atom_size);
    if (!tmp) {
        rc = -errno;
        free(node);
        return rc;
    }
    node->pool = tmp;

    if (ps->pools == NULL) {
        ps->pools = node;
    } else {
        assert(ps->active);
        ps->active->next = node;
    }

    ps->active = node;
    ps->last_i = 0;
    return 0;
}

static int empty_atom(poolset *ps, char *element)
{
    if (ps->empty == NULL) {
        char *buff = (char *)element;
        int i = ps->atom_size;
        while (i--) {
            if (*buff++ != '\0') {
                return 0;
            }
        }
        return 1;
    } else {
        return ps->empty(element);
    }
}

void *pool_get_atom(poolset *ps)
{
    char *atom;
    int i, j;

    if (!ps) {
        return NULL;
    }

    if (!ps->pools) {
        alloc_pool(ps);
    }

    /* (1) Check active pool */
    for (i = 0; i < ps->length; i++) {
        j = (i + ps->last_i) % ps->length;
        atom = (char *)ps->active->pool + (j * ps->atom_size);
        if (empty_atom(ps, atom)) {
            ps->last_i = (j + 1) % ps->length;
            return (void *)atom;
        }
    }

    /* (2) Create a new pool, and try again */
    if (alloc_pool(ps)) {
        return NULL;
    }
    return pool_get_atom(ps);
}
