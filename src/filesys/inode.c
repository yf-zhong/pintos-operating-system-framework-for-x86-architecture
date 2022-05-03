#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[125]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

struct cache_block {
  char content[BLOCK_SECTOR_SIZE];
  bool is_dirty;
  bool is_valid;
  block_sector_t bst;
  struct rw_lock lock;
  struct list_elem elem;
  // for testing purpose
  int hit_cnt;
  int miss_cnt;
};

struct list cache;
struct lock cache_lock;


struct cache_block* new_cache_block();
struct cache_block* find_block_and_acq_lock(block_sector_t bst, bool reader);
void cache_read(void* dest, block_sector_t bst);
void cache_write(void* src, block_sector_t bst);

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

int get_cache_hit_cnt() {
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

int get_cache_miss_cnt() {
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


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      cache_write(disk_inode, sector);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          cache_write(zeros, disk_inode->start + i);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read(&inode->data, inode->sector);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(buffer + bytes_read, sector_idx);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      cache_read(bounce, sector_idx);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(buffer + bytes_written, sector_idx);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        cache_read(bounce, sector_idx);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(bounce, sector_idx);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }
