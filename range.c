#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "pool.h"
#include "range.h"
#include "rbtree.h"

typedef struct rnode {
    struct rb_node node;
    struct rnode *next;
    range range;
} rnode;

typedef struct {
    struct rb_root tree;  /* Tree of ranges in set */
    poolset *ps;          /* Pool of nodes for tree */
    rnode *free;          /* free list of recycled nodes */
    uint64_t size;        /* Total size in-range */
    /* Total size represented for each type */
    uint64_t sizes[sizeof(mask_t) * 8];
} rangeset_t;

#define RANGE_OF(x)  (((rnode *)(x))->range)
#define r_offset(x)  (RANGE_OF(x).offset)
#define r_length(x)  (RANGE_OF(x).length)
#define r_end(x)     (RANGE_OF(x).end)

rangeset *new_rangeset(uint64_t pool_size)
{
    rangeset_t *tmp = (rangeset_t *)calloc(sizeof(rangeset_t), 1);
    if (!tmp) {
        perror("Couldn't allocate memory for rangeset");
        return NULL;
    }
    tmp->tree = RB_ROOT;
    tmp->ps = new_poolset(pool_size, sizeof(rnode));
    if (!tmp->ps) {
        free(tmp);
        return NULL;
    }
    return (rangeset *)tmp;
}

void delete_rangeset(rangeset *rset)
{
    rangeset_t *rs = (rangeset_t *)rset;

    delete_poolset(rs->ps);
    free(rs);
}

static rnode *pop_free_range(rangeset_t *rs)
{
    rnode *tmp;

    if (rs->free) {
        tmp = rs->free;
        rs->free = tmp->next;
        tmp->next = NULL;
        return tmp;
    }
    return NULL;
}

static rnode *get_range(rangeset_t *rs)
{
    rnode *tmp;

    if (!rs) {
        return NULL;
    }

    /* (1) Check free node list */
    tmp = pop_free_range(rs);
    if (tmp) {
        return tmp;
    }

    /* (2) Check pool */
    return pool_get_atom(rs->ps);
}

static rnode *new_range(rangeset_t *rs, uint64_t offset,
                        uint64_t length, mask_t typemask)
{
    rnode *node = get_range(rs);
    if (!node) {
        return NULL;
    }

    node->range.offset = offset;
    node->range.length = length;
    node->range.end = offset + length;
    node->range.typemask = typemask;
    return node;
}

/**
 * add to free list of nodes for re-use.
 */
static void return_range_node(rangeset_t *rs, rnode *node)
{
    node->range.offset = 0;
    node->range.length = 0;
    node->range.end = 0;
    node->next = rs->free;
    rs->free = node;
}

/**
 * unlink node from range tree, add to free list of nodes for re-use.
 */
static void delete_range_node(rangeset_t *rs, rnode *node)
{
    rb_erase(&node->node, &rs->tree);
    return_range_node(rs, node);
}

/**
 * Given a range in a tree, find the next lowest range.
 */
static rnode *next_lowest(rnode *range)
{
    return (rnode *)rb_prev(&range->node);
}

/**
 * Given a range in a tree, find the next highest range.
 */
static rnode *next_highest(rnode *range)
{
    return (rnode *)rb_next(&range->node);
}

/**
 * Merge two ranges into one, deleting the 'right' range.
 */
static void merge(rangeset_t *rs, rnode *left, rnode *right)
{
    assert(left->range.offset < right->range.offset);
    assert(left->range.end == right->range.offset);
    left->range.length += right->range.length;
    left->range.end = right->range.end;
    assert(left->range.end == left->range.offset + left->range.length);
    delete_range_node(rs, right);
}

/**
 * Check to the 'left' of a node to see if it can be merged.
 */
static void check_merge_left(rangeset_t *rs, rnode *node)
{
    rnode *neighbor = next_lowest(node);

    if (neighbor && \
        neighbor->range.end == node->range.offset && \
        node->range.typemask == neighbor->range.typemask) {
        merge(rs, neighbor, node);
    }
}

/**
 * Check to the 'right' of a node to see if it can be merged.
 */
static void check_merge_right(rangeset_t *rs, rnode *node)
{
    rnode *neighbor = next_highest(node);

    if (neighbor && \
        node->range.end == neighbor->range.offset && \
        node->range.typemask == neighbor->range.typemask) {
        merge(rs, node, neighbor);
    }
}

/* Returns typemask of conflicting range, or 0 if there are no overlaps. */
int range_overlap(rangeset *rset, uint64_t offset, uint64_t len,
                  const range **r)
{
    rangeset_t *rs = (rangeset_t *)rset;
    struct rb_root *root = &rs->tree;
    struct rb_node **new = &(root->rb_node);

    while (*new) {
        rnode *this = (rnode *)*new;
        bool left = (offset < this->range.offset);
        if (left) {
            new = &((*new)->rb_left);
            if (offset + len > this->range.offset) {
                if (r) {
                    *r = &this->range;
                }
                return this->range.typemask;
            }
        } else {
            new = &((*new)->rb_right);
            if (offset < this->range.end) {
                if (r) {
                    *r = &this->range;
                }
                return this->range.typemask;
            }
        }
    }

    return 0;
}

/**
 * link new node into range tree. Coalesce where appropriate.
 * @return: 0 if successful, -ERRNO on error, +typemask on collision.
 *          range **r is updated with a pointer to the conflicting range if
 *          it is provided.
 */
int add_range(rangeset *rset, uint64_t offset, uint64_t len, mask_t typemask,
              const range **r)
{
    rangeset_t *rs = (rangeset_t *)rset;
    struct rb_root *root = &rs->tree;
    struct rb_node **new = &(root->rb_node), *parent = NULL;
    rnode *tmp;
    int rc, i;

    rc = range_overlap(rset, offset, len, r);
    if (rc) {
        return rc; /* 0 or +typemask */
    }

    while (*new) {
        rnode *this = (rnode *)*new;
        bool left = (offset < this->range.offset);
        parent = *new;
        if (left) {
            new = &((*new)->rb_left);
            if (offset + len == this->range.offset && \
                typemask == this->range.typemask) {
                /* Parent's offset is pushed left. The parent's offset can never
                 * be pushed below left-child because overlaps are prohibited.
                 * Parent may be able to merge with its nearest-left-neighbor */
                this->range.offset = offset;
                this->range.length += len;
                assert(this->range.end == \
                       this->range.offset + this->range.length);
                check_merge_left(rs, this);
                goto out;
            }
        } else {
            new = &((*new)->rb_right);
            if (this->range.end == offset && this->range.typemask == typemask) {
                /* Coalesce into parent (extends parent's range)
                 * parent may be able to merge with its nearest-right-neighbor.
                 */
                this->range.length += len;
                this->range.end = offset + len;
                assert(this->range.end == this->range.offset + this->range.length);
                check_merge_right(rs, this);
                goto out;
            }
        }
    }

    /* Add new node and rebalance tree. */
    tmp = new_range(rs, offset, len, typemask);
    if (!tmp) {
        return -ENOMEM;
    }
    rb_link_node(&tmp->node, parent, new);
    rb_insert_color(&tmp->node, root);
 out:
    rs->size += len;
    while (typemask) {
        i = ffs(typemask) - 1;
        rs->sizes[i] += len;
        typemask = typemask & ~(1 << i);
    }
    return 0;
}

static void fprint_range_inorder(FILE *stream, rnode *node)
{
    if (node == NULL) {
        return;
    }

    fprint_range_inorder(stream, (rnode *)node->node.rb_left);
    fprintf(stream, "0x%09"PRIx64" - 0x%09"PRIx64"\n",
            node->range.offset, node->range.end - 1);
    fprint_range_inorder(stream, (rnode *)node->node.rb_right);
}

void fprint_ranges(FILE *stream, rangeset *rset)
{
    rangeset_t *rs = (rangeset_t *)rset;
    fprint_range_inorder(stream, (rnode *)rs->tree.rb_node);
}

void print_ranges(rangeset *rset)
{
    fprint_ranges(stdout, rset);
}

static int _range_traversal(rnode *node, enum traversal order, mask_t typemask,
                            int (*fn)(const range *range, void *opaque), void *opaque)
{
    int rc;

#define _RN_CALLBACK(ORDER) do {                                        \
        if ((order == (ORDER)) && (node->range.typemask & typemask)) {  \
            rc = fn(&node->range, opaque);                              \
            if (rc) {                                                   \
                return rc;                                              \
            }                                                           \
        }                                                               \
    } while (0);

    if (node == NULL) {
        return 0;
    }

    _RN_CALLBACK(T_PREORDER);
    _range_traversal((rnode *)node->node.rb_left, order, typemask, fn, opaque);
    _RN_CALLBACK(T_INORDER);
    _range_traversal((rnode *)node->node.rb_right, order, typemask, fn, opaque);
    _RN_CALLBACK(T_POSTORDER);

    return 0;
}

int range_traversal_filter(rangeset *rset, enum traversal order,
                            mask_t typemask,
                           int (*fn)(const range *node, void *opaque), void *opaque)
{
    rangeset_t *rs = (rangeset_t *)rset;
    return _range_traversal((rnode *)rs->tree.rb_node, order,
                            typemask, fn, opaque);
}

int range_traversal(rangeset *rset, enum traversal order,
                     int (*fn)(const range *node, void *opaque), void *opaque)
{
    return range_traversal_filter(rset, order, (mask_t)-1, fn, opaque);
}

uint64_t get_size(rangeset *rset)
{
    return ((rangeset_t *)rset)->size;
}

uint64_t get_type_size(rangeset *rset, unsigned type_index)
{
    if (!rset || type_index > sizeof(mask_t) * 8) {
        return 0;
    }
    return ((rangeset_t *)rset)->sizes[type_index];
}
