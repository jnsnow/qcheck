#ifndef __RANGE_H
#define __RANGE_H

#include <stdint.h>
#include <stdbool.h>

/* If you change this, you'll also have to change usages of ffs()
 * in range.c, which expect an integer. */
typedef int mask_t;

typedef struct range {
    mask_t typemask; /* Bitmask with arbitrary bits set to identify the range */
    uint64_t offset;
    uint64_t length;
    uint64_t end;
} range;

enum traversal {
    T_PREORDER,
    T_INORDER,
    T_POSTORDER,
};

typedef void *rangeset;

rangeset *new_rangeset(uint64_t pool_size);
void delete_rangeset(rangeset *rset);
int add_range(rangeset *rset, uint64_t offset,
              uint64_t len, mask_t type, const range **r);
void fprint_ranges(FILE *stream, rangeset *rset);
void print_ranges(rangeset *rset);
int range_traversal(rangeset *rset, enum traversal order,
                     int (*fn)(const range *node, void *opaque), void *opaque);
int range_traversal_filter(rangeset *rset, enum traversal order,
                           mask_t typemask,
                           int (*fn)(const range *node, void *opaque), void *opaque);
uint64_t get_size(rangeset *rset);
uint64_t get_type_size(rangeset *rset, unsigned type_index);
int range_overlap(rangeset *rset, uint64_t offset,
                  uint64_t len, const range **r);

#endif
