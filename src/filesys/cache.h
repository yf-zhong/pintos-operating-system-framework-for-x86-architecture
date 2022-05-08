#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

void cache_init(void);
void cache_destroy(void);
void cache_reset(void);
unsigned int get_cache_hit_cnt(void);
unsigned int get_cache_miss_cnt(void);
void cache_read(void* dest, block_sector_t bst);
void cache_write(void* src, block_sector_t bst);

#endif