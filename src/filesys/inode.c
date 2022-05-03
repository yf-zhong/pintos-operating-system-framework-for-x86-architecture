#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[12]; /* Direct block pointer. */
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
  if (data_num <= 12) {
    return data_num + 1;
  } else if (data_num <= 128 + 12) {
    return data_num + 2;
  } else {
    return data_num + (data_num - 140) / 128 + 3;
  }
}

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock /* Lock for each inode struct. */  
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  size_t sector_num = bytes_to_sectors(pos);
  struct cache_block* b = find_block_and_acq_lock(inode->sector, true);
  struct inode_disk* inode_content = b->content;
  rw_lock_release(&b->lock);
  if (sector_num <= 12) {
    return inode_content->direct[sector_num - 1];
  } else if (sector_num <= 128 + 12) {
    sector_num -= 12;
    b = find_block_and_acq_lock(inode->sector, true);
    block_sector_t* indir_content = b->content;
    rw_lock_release(&b->lock);
    return indir_content[sector_num - 1];
  } else {
    sector_num -= 128 + 12;
    b = find_block_and_acq_lock(inode_content->indirect_double, true);
    block_sector_t* indir2_content = b->content;
    rw_lock_release(&b->lock);
    b = find_block_and_acq_lock(indir2_content[sector_num / 128], true);
    block_sector_t* indir_content = b->content;
    rw_lock_release(&b->lock);
    return indir_content[sector_num % 128 - 1];
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

/* Call resize in inode_write and inode_create */
bool inode_resize(struct inode_disk* ind_d, off_t size) {
  // Get block number including all internal and root block
  size_t num_block_old = bytes_to_blocks(ind_d->length);
  size_t num_block_new = bytes_to_blocks(size);
  if (num_block_new <= num_block_old) {
    return true;
  }

  // Allocate blocks from free map in advance
  size_t new_alloc_num = num_block_new - num_block_old;
  block_sector_t new_block_list[new_alloc_num];
  bool success = free_map_allocate_non_consecutive(new_alloc_num, &new_block_list);
  if (!success) {
    return false;
  }

  int new_list_i = 0;
  // Handle direct pointer
  for (int i = 0; i < 12; i++) {
    if (size > BLOCK_SECTOR_SIZE * i && ind_d->direct[i] == 0) {
      ind_d->direct[i] = new_block_list[new_list_i++];
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write(fs_device, new_block_list[i], zeros);
    }
  }
  if (ind_d->indirect == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
    ind_d->length = size;
    return true;
  }
  block_sector_t buffer[128];
  memset(buffer, 0, 512);
  // Create indirect pointer if not exist, read from disk otherwise
  if (ind_d->indirect == 0) {
    ind_d->indirect = new_block_list[new_list_i++];
  } else {
    block_read(ind_d->indirect, buffer);
  }
  // Handle indirect pointer value
  for (int i = 0; i < 128; i++) {
    if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
      buffer[i] = new_block_list[new_list_i++];
    }
  }
  block_write(fs_device, ind_d->indirect, buffer);
  if (ind_d->indirect_double == 0 && size <= 150 * BLOCK_SECTOR_SIZE) {
    ind_d->length = size;
    return true;
  }

  // Handle doubly indirect pointer
  block_sector_t buffer[128];
  memset(buffer, 0, 512);
  // Load doubly indirect pointer into buffer
  if (ind_d->indirect_double == 0) {
    ind_d->indirect_double = new_block_list[new_list_i++];
  } else {
    block_read(ind_d->indirect_double, buffer);
  }
  for (int i = 0; i < 128; i++) {
    block_sector_t buffer2[128];
    memset(buffer2, 0, 512);
    if (buffer[i] == 0) {
      buffer[i] = new_block_list[new_list_i++];
    } else {
      block_read(buffer[i], buffer2);
    }
    for (int j = 0; j < 128; j++) {
      if (size > (150 + i * 128 + j) * BLOCK_SECTOR_SIZE && buffer2[j] == 0) {
        buffer2[j] = new_block_list[new_list_i++];
      }
    }
    block_write(fs_device, buffer[i], buffer2);
  }
  block_write(fs_device, ind_d->indirect_double, buffer);
  ind_d->length = size;
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
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    if (inode_resize(disk_inode, length)) {
      block_write(fs_device, sector, disk_inode);
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
  block_read(fs_device, inode->sector, &inode->data);
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
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
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
      block_write(fs_device, sector_idx, buffer + bytes_written);
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
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
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
