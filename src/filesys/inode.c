#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INUMBER_PER_BLOCK 128 // Number of block_sector_t per block
#define DIR_NUM 12
#define INDIR_NUM 1
#define D_INDIR_NUM 1
#define MAX_WITHOUT_D_INDIR (INUMBER_PER_BLOCK + DIR_NUM)

void fill_sector_with_zeros(block_sector_t);
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[DIR_NUM]; /* Direct block pointer. */
  block_sector_t indirect; /* Indirect block pointer. */
  block_sector_t indirect_double; /* Double indirect block pointer. */

  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t unused[112]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long, not inlcude internal or root. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Return the number of all sectors for an inode SIZE bytes, including root and internal nodes */
static size_t bytes_to_blocks(off_t size) {
  size_t data_num = bytes_to_sectors(size);
  size_t internal_num = 0;
  if (data_num > DIR_NUM) {
    internal_num += INDIR_NUM;
  }
  if (data_num > MAX_WITHOUT_D_INDIR) {
    internal_num += D_INDIR_NUM + DIV_ROUND_UP(data_num - MAX_WITHOUT_D_INDIR, INUMBER_PER_BLOCK);
  }
  return data_num + internal_num;
}

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock; /* Lock for each inode struct. */  
};

/* helper for proj3 task3 */
int get_open_cnt(struct inode* inode) {
  return inode->open_cnt;
}

int get_bst(struct inode* inode) {
  return inode->sector;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  struct inode_disk* inode_content = calloc(BLOCK_SECTOR_SIZE, 1);
  if (inode_content == NULL) {
    return -1;
  }
  cache_read((void*)inode_content, inode->sector);
  if (pos > inode_content->length) {
    free(inode_content);
    return -1;
  }
  int sector_num = pos / BLOCK_SECTOR_SIZE + 1;

  if (sector_num <= DIR_NUM) {
    block_sector_t result = inode_content->direct[sector_num - 1];
    free(inode_content);
    if (result == 0) {
      return -1;
    } else {
      return result;
    }
  } else if (sector_num <= MAX_WITHOUT_D_INDIR) {
    sector_num -= DIR_NUM;
    block_sector_t* indir_content = calloc(BLOCK_SECTOR_SIZE, 1);
    if (indir_content == NULL) {
      return -1;
    }
    cache_read((void*)indir_content, inode_content->indirect);
    block_sector_t result = indir_content[sector_num - 1];
    free(indir_content);
    free(inode_content);
    if (result == 0) {
      return -1;
    } else {
      return result;
    }
  } else {
    sector_num -= MAX_WITHOUT_D_INDIR;
    // Read first level indirect pointer
    block_sector_t* indir_content = calloc(BLOCK_SECTOR_SIZE, 1);
    cache_read((void*)indir_content, inode_content->indirect_double);

    // Read second level indirect pointer
    block_sector_t* indir2_content = calloc(BLOCK_SECTOR_SIZE, 1);
    cache_read((void*)indir2_content, indir_content[sector_num / INUMBER_PER_BLOCK]); // Start from 0, no need to + 1
    
    block_sector_t result = indir2_content[sector_num % INUMBER_PER_BLOCK - 1];
    free(inode_content);
    free(indir_content);
    free(indir2_content);
    if (result == 0) {
      return -1;
    } else {
      return result;
    }
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Protect open inode list */
struct lock inode_list_lock;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&inode_list_lock);
}

void fill_sector_with_zeros(block_sector_t bst) {
  static char zeros[BLOCK_SECTOR_SIZE];
  cache_write(zeros, bst);
}

/* Call resize in inode_write and inode_create */
bool inode_resize(struct inode_disk* ind_d, off_t size) {
  // Get block number including all internal and root block
  off_t old_size = ind_d->length;
  ind_d->length = size;

  size_t num_block_old = bytes_to_blocks(old_size);
  size_t num_block_new = bytes_to_blocks(size);

  // no resize needed
  if (num_block_old == num_block_new) {
    return true;
  }

  size_t new_alloc_num = num_block_new > num_block_old ? (num_block_new - num_block_old) : 0;
  // list for storing allocated sector number
  block_sector_t* new_block_list = malloc(new_alloc_num * sizeof(block_sector_t));
  if (new_block_list == NULL && new_alloc_num != 0) {
    ind_d->length = old_size;
    return false;
  }
  // if allocate not success
  if (!free_map_allocate_non_consecutive(new_alloc_num, new_block_list)) {
    free(new_block_list);
    ind_d->length = old_size;
    return false;
  }

  // fill all new allocated sectors with zeros
  for (size_t i = 0; i < new_alloc_num; i++) {
    fill_sector_with_zeros(new_block_list[i]);
  }

  int new_list_i = 0;
  // Handle direct pointer
  for (int i = 0; i < DIR_NUM; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && ind_d->direct[i] != 0) {
      // Shrink
      free_map_release(ind_d->direct[i], 1);
      ind_d->direct[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && ind_d->direct[i] == 0) {
      // Grow
      ind_d->direct[i] = new_block_list[new_list_i++];
      // fill the new allocated sector with zero
      static char zeros[BLOCK_SECTOR_SIZE];
      cache_write(zeros, ind_d->direct[i]);
    }
  }
  if (ind_d->indirect == 0 && size <= DIR_NUM * BLOCK_SECTOR_SIZE) {
    free(new_block_list);
    return true;
  }

  // Handle indirect pointer, hit only if indir ptr is needed
  block_sector_t* buffer = malloc(INUMBER_PER_BLOCK * sizeof(block_sector_t));
  if (buffer == NULL) {
    free(new_block_list);
    ind_d->length = old_size;
    return false;
  }
  memset(buffer, 0, BLOCK_SECTOR_SIZE);
  // Create indirect pointer if not exist, read from disk otherwise
  if (ind_d->indirect == 0) {
    ind_d->indirect = new_block_list[new_list_i++];
  } else {
    cache_read((void*)buffer, ind_d->indirect);
  }
  for (int i = 0; i < INUMBER_PER_BLOCK; i++) {
    if (size <= (DIR_NUM + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
      // Shrink
      free_map_release(buffer[i], 1);
      buffer[i] = 0;
    } else if (size > (DIR_NUM + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      // Grow
      buffer[i] = new_block_list[new_list_i++];
    }
  }
  cache_write((void*)buffer, ind_d->indirect);
  free(buffer);
  if (ind_d->indirect_double == 0 && size <= MAX_WITHOUT_D_INDIR * BLOCK_SECTOR_SIZE) {
    free(new_block_list);
    return true;
  }

  // Handle doubly indirect pointer, hit only if db indir ptr is needed
  block_sector_t* buffer1 = malloc(INUMBER_PER_BLOCK * sizeof(block_sector_t));
  if (buffer1 == NULL) {
    free(new_block_list);
    ind_d->length = old_size;
    return false;
  }
  memset(buffer1, 0, BLOCK_SECTOR_SIZE);
  // Load doubly indirect pointer into buffer
  if (ind_d->indirect_double == 0) {
    ind_d->indirect_double = new_block_list[new_list_i++];
  } else {
    cache_read((void*)buffer1, ind_d->indirect_double);
  }
  // Handle sub-indir ptr
  for (int i = 0; i < INUMBER_PER_BLOCK; i++) {
    if (size <= (MAX_WITHOUT_D_INDIR + i * INUMBER_PER_BLOCK) * BLOCK_SECTOR_SIZE && buffer1[i] != 0) {
      // Shrink first pointer
      free_map_release(buffer1[i], 1);
      buffer1[i] = 0;
    } else if (size > (MAX_WITHOUT_D_INDIR + i * INUMBER_PER_BLOCK) * BLOCK_SECTOR_SIZE) {
      // Grow first pointer
      block_sector_t* buffer2 = malloc(INUMBER_PER_BLOCK * sizeof(block_sector_t));
      if (buffer2 == NULL) {
        free(buffer1);
        free(new_block_list);
        ind_d->length = old_size;
        return false;
      }
      memset(buffer2, 0, BLOCK_SECTOR_SIZE);
      if (buffer1[i] == 0) {
        buffer1[i] = new_block_list[new_list_i++];
      } else {
        cache_read((void*)buffer2, buffer1[i]);
      }
      for (int j = 0; j < INUMBER_PER_BLOCK; j++) {
        if (size <= (MAX_WITHOUT_D_INDIR + i * INUMBER_PER_BLOCK + j) * BLOCK_SECTOR_SIZE && buffer2[j] != 0) {
          // Shrink second pointer
          free_map_release(buffer2[j], 1);
          buffer2[j] = 0;
        } else if (size > (MAX_WITHOUT_D_INDIR + i * INUMBER_PER_BLOCK + j) * BLOCK_SECTOR_SIZE && buffer2[j] == 0) {
          // Grow second pointer
          buffer2[j] = new_block_list[new_list_i++];
        }
      }
      cache_write((void*)buffer2, buffer1[i]);
      free(buffer2);
    }
  }
  cache_write((void*)buffer1, ind_d->indirect_double);
  free(buffer1);
  free(new_block_list);
  return true;
}

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
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;

    if (inode_resize(disk_inode, length)) {
      cache_write(disk_inode, sector);
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
  lock_acquire(&inode_list_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      lock_release(&inode_list_lock);
      return inode;
    }
  }
  lock_release(&inode_list_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */

  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);

  lock_acquire(&inode_list_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&inode_list_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  if (inode != NULL)
    inode->open_cnt++;
  lock_release(&inode->inode_lock);
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
    lock_acquire(&inode->inode_lock);
    list_remove(&inode->elem);
    lock_release(&inode->inode_lock);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      struct inode_disk* ind_d = calloc(BLOCK_SECTOR_SIZE, 1);
      if (ind_d == NULL) {
        return;
      }
      cache_read(ind_d, inode->sector);
      // Resize the inode to be 0 size so that all blocks are deallocated
      inode_resize(ind_d, 0);
      free_map_release(inode->sector, 1);
      free(ind_d);
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
    if ((int)sector_idx == -1) {
      return bytes_read;
    }

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

  // Resize inode if necessary
  off_t new_length = size + offset;
  struct inode_disk* ind_d = calloc(BLOCK_SECTOR_SIZE, 1);
  if (ind_d == NULL) {
    return 0;
  }
  cache_read(ind_d, inode->sector);

  lock_acquire(&inode->inode_lock);
  if (new_length > ind_d->length) {
    if (!inode_resize(ind_d, new_length)) {
      lock_release(&inode->inode_lock);
      free(ind_d);
      return 0;
    }
  }
  lock_release(&inode->inode_lock);
  cache_write(ind_d, inode->sector);

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
      cache_write((void *) (buffer + bytes_written), sector_idx);
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
  free(ind_d);
  free(bounce);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk* ind_d = calloc(BLOCK_SECTOR_SIZE, 1);
  if (ind_d == NULL) {
    return -1;
  }
  cache_read(ind_d, inode->sector);
  off_t length = ind_d->length;
  free(ind_d);
  return length;
}
