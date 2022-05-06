#include "filesys/cache.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

struct cache_block {
  char content[BLOCK_SECTOR_SIZE];
  bool is_dirty;
  bool is_valid;
  block_sector_t bst;
  struct rw_lock lock;
  struct list_elem elem;
  // for testing purpose
  unsigned int hit_cnt;
  unsigned int miss_cnt;
};

struct list cache;
struct lock cache_lock;

struct cache_block* new_cache_block();
struct cache_block* find_block_and_acq_lock(block_sector_t bst, bool reader);


/* make a new cache block */
struct cache_block* new_cache_block() {
  struct cache_block* b = (struct cache_block*) calloc(sizeof(struct cache_block), 1);
  b->is_dirty = false;
  b->is_valid = false;
  rw_lock_init(&b->lock);
  b->hit_cnt = 0;
  b->miss_cnt = 0;
  return b;
}

/* initialize 64 blocks in cache and the cache lock */
void cache_init() {
  list_init(&cache);
  lock_init(&cache_lock);
  for (int i = 0; i < 64; i++) {
    struct cache_block* b = new_cache_block();
    list_push_front(&cache, &b->elem);
  }
}

void cache_read(void* dest, block_sector_t bst) {
  struct cache_block* b = find_block_and_acq_lock(bst, true);
  memcpy(dest, b->content, BLOCK_SECTOR_SIZE);
  rw_lock_release(&b->lock, true);
}

void cache_write(void* src, block_sector_t bst) {
  struct cache_block* b = find_block_and_acq_lock(bst, false);
  memcpy(b->content, src, BLOCK_SECTOR_SIZE);
  b->is_dirty = true;
  rw_lock_release(&b->lock, false);
}

/* find the cache block corespond to the given sector, 
   if none match, evict the oldest unused one and cache the new block. 
   This function will acquire the lock in the cache block but won't release it upon return
   So caller should release the lock when its work is done
*/
struct cache_block* find_block_and_acq_lock(block_sector_t bst, bool reader) {
  bool not_found = true;
  // acquire lock for the cache so only 1 thread can access the cache at a time
  lock_acquire(&cache_lock);
  struct list_elem* e = list_begin(&cache);
  struct cache_block* b;
  // find the cache block corespond to the given sector
  while (e != list_end(&cache) && not_found) {
    b = list_entry(e, struct cache_block, elem);
    if (b->is_valid && b->bst == bst) {
      not_found = false;
    }
    e = list_next(e);
  }
  // if sector is in cache, b is the block of that sector in cache
  // if sector is not in cache, b is the last block in cache
  e = &b->elem;
  // move the block to the front of the cache
  list_remove(e);
  list_push_front(&cache, e);
  if (not_found) {
    b->miss_cnt++;
    rw_lock_acquire(&b->lock, false);
    // write cache block to disk if it is valid and dirty
    if (b->is_valid && b->is_dirty) {
      block_write(fs_device, b->bst, b->content);
    }
    // update cache block content and sector number, mark the cache block valid and not dirty
    b->bst = bst;
    block_read(fs_device, bst, b->content);
    b->is_valid = true;
    b->is_dirty = false;
    rw_lock_release(&b->lock, false);
  }
  else {
    b->hit_cnt++;
  }
  rw_lock_acquire(&b->lock, reader);
  lock_release(&cache_lock);
  return b;
}

void cache_destroy() {
  while (!list_empty(&cache)) {
    struct list_elem* e = list_pop_front(&cache);
    struct cache_block* b = list_entry(e, struct cache_block, elem);
    // acquire write lock because we want to destroy the cache block, 
    // so wait for any access from other threads to finish
    rw_lock_acquire(&b->lock, false);
    // write any dirty block to disk
    if (b->is_valid && b->is_dirty) {
      block_write(fs_device, b->bst, b->content);
    }
    // can release the lock before destroying the block because thread holds the cache lock,
    // so no other thread can access the destroying block
    rw_lock_release(&b->lock, false);
    free(b);
  }
}

void cache_reset() {
  lock_acquire(&cache_lock);
  cache_destroy();
  cache_init();
}

unsigned int get_cache_hit_cnt() {
  int total_hit_cnt = 0;
  lock_acquire(&cache_lock);
  struct list_elem* e = list_begin(&cache);
  while (e != list_end(&cache)) {
    struct cache_block* b = list_entry(e, struct cache_block, elem);
    total_hit_cnt += b->hit_cnt;
    e = list_next(e);
  }
  lock_release(&cache_lock);
  return total_hit_cnt;
}

unsigned int get_cache_miss_cnt() {
  int total_miss_cnt = 0;
  lock_acquire(&cache_lock);
  struct list_elem* e = list_begin(&cache);
  while (e != list_end(&cache)) {
    struct cache_block* b = list_entry(e, struct cache_block, elem);
    total_miss_cnt += b->miss_cnt;
    e = list_next(e);
  }
  lock_release(&cache_lock);
  return total_miss_cnt;
}
