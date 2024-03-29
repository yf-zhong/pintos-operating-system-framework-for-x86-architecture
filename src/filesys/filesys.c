#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/cache.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

unsigned int fs_device_read() { return read_cnt(fs_device); }

unsigned int fs_device_write() { return write_cnt(fs_device); }

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();
  cache_init();

  if (format)
    do_format();

  free_map_open();
  thread_current()->pcb->cwd = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  cache_destroy();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
/* change the directory to the directory specified in path */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* d = tracing(name, true);
  if (d == NULL) {
    return false;
  }
  char last_name[NAME_MAX + 1];
  bool check = get_last_name(name, last_name);
  if (!check) {
    return false;
  }
  bool success =
      (d != NULL && free_map_allocate(1, &inode_sector) &&
       inode_create(inode_sector, initial_size) && dir_add(d, last_name, inode_sector, false));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(d);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
/* change the directory to the directory specified in path */
struct file* filesys_open(const char* name, bool* is_dir) {
  struct dir* d = tracing(name, false);
  if (d == NULL) {
    return NULL;
  }
  if (is_dir != NULL) {
    struct dir* pd = tracing(name, true);
    char last_name[NAME_MAX + 1];
    strlcpy(last_name, "", sizeof(last_name));
    get_last_name(name, last_name);
    *is_dir = check_is_dir(pd, last_name) || (strlen(last_name) == 0);
    dir_close(pd);
  }
  struct inode* inode = dir_get_inode(d);
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
/* change the directory to the directory specified in path */
bool filesys_remove(const char* name) {
  struct dir* d = tracing(name, false);
  if (d == NULL) {
    return false;
  }
  char last_name[NAME_MAX + 1];
  get_last_name(name, last_name);
  if (strcmp(last_name, ".") == 0 || strcmp(last_name, "..") == 0) {
    dir_close(d);
    return false;
  }
  struct inode* inode = dir_get_inode(d);
  struct dir* parent_dir = tracing(name, true);

  if (check_is_dir(parent_dir, last_name)) {
    if (get_open_cnt(inode) > 1) {
      dir_close(d);
      dir_close(parent_dir);
      return false;
    }
    int count = 0;
    char unused[NAME_MAX + 1];
    while (dir_readdir(d, unused)) {
      count++;
    }
    if (count != 2) {
      dir_close(d);
      dir_close(parent_dir);
      return false;
    }
  }

  bool result = dir_remove(parent_dir, last_name);
  dir_close(d);
  dir_close(parent_dir);

  return result;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
