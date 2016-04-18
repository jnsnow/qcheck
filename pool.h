#ifndef __POOL_H
#define __POOL_H

#include <stdint.h>

typedef struct poolset poolset;

poolset *new_poolset(uint64_t pool_length, uint64_t atom_size);
void delete_poolset(poolset *ps);
void *pool_get_atom(poolset *ps);

#endif
