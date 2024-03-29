#include "filesys/directory.h"
#include <stdio.h>
#include "lib/string.h"
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  bool is_directory;           /* Is directory or file? (For proj3 task3) */
};

static int get_next_part(char part[NAME_MAX + 1], const char** srcp);
void cut_path(char* p, char* container);
void remove_dot(const char* p, char* container);

struct inode* get_inode(struct dir* dir) {
  return dir->inode;
}

/* Used to remove all the "." in the path given.
  Do this because "." will be very annoying when we
  try to find the parent directory through the path.
*/
void remove_dot(const char* p, char* container) {
  container[0] = '\0';
  char last[NAME_MAX + 1];
  size_t len = strlen(p) + 2;
  int result = get_next_part(last, &p);
  while (result > 0) {
    strlcat(container, last, len);
    strlcat(container, "/", len);
    result = get_next_part(last, &p);
  }
  if (result < 0) {
    container[0] = '\0';
  }
}

/* Remove the final portion of the path.
  i.e. take the path of the parent directory
  of the file/dir given.
*/
void cut_path(char* p, char* container) {
  size_t len = strlen(p);
  if (len == 0) {
    return;
  }
  while (len >= 2 && p[len - 2] != '/') {
    len--;
  }
  strlcpy(container, p, len);
}

/* parsing the path and trace the directory until no more path string or error occurs. 
Mainly used in mkdir and chdir 
if is_md is true, find the parent directory of given path
open the returning directory
*/
struct dir* tracing(const char* path, bool is_md) {
  if (strcmp(path, "") == 0) {
    return NULL;
  }
  char clean_path[strlen(path) + 2];
  strlcpy(clean_path, "", sizeof(clean_path));
  remove_dot(path, clean_path);
  if (is_md) {
    char temp[strlen(path) + 2];
    strlcpy(temp, clean_path, strlen(clean_path) + 1);
    cut_path(temp, clean_path);
  }
  struct dir* root = dir_open_root();
  struct dir* cwd = thread_current()->pcb->cwd;
  char curr[NAME_MAX + 1] = "";
  struct dir* curr_dir = NULL;
  struct inode* curr_inode = NULL;
  char* clean_path_ptr = clean_path;
  int flag = get_next_part(curr, &clean_path_ptr);

  if (flag > 0) {
    // if can find current_name in either cwd or root
    if (dir_lookup(cwd, curr, &curr_inode) || dir_lookup(root, curr, &curr_inode)) {
      dir_close(root);
      curr_dir = dir_open(curr_inode);
      int result = get_next_part(curr, &clean_path_ptr);
      while (result > 0) {
        if (dir_lookup(curr_dir, curr, &curr_inode)) {
          struct dir* dir_to_close = curr_dir;
          curr_dir = dir_open(curr_inode);
          dir_close(dir_to_close);
          result = get_next_part(curr, &clean_path_ptr);
        } else {
          result = -1;
        }
      }
      if (result == -1) {
        dir_close(curr_dir);
        return NULL;
      }
      return curr_dir;
    } else {
      dir_close(root);
      return NULL;
    }
  } else {
    if (is_md) {
      dir_close(root);
      return dir_reopen(cwd);
    }
    if (flag != 0) {
      dir_close(root);
      return NULL;
    } else {
      dir_close(root);
      return dir_reopen(cwd);
    }
  }
}

/* Getter for inode_sector */
block_sector_t get_inode_sector(struct dir* de) { return get_bst(de->inode); }

/* Use similar logic as dir_readdir() to retrieve the corresponding dir_entry
  and check whether it is file or directory */
bool check_is_dir(struct dir* parent_dir, char name[NAME_MAX + 1]) {
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
    return true;
  }
  struct dir_entry e;
  off_t pos = parent_dir->pos;
  while (inode_read_at(parent_dir->inode, &e, sizeof e, parent_dir->pos) == sizeof e) {
    parent_dir->pos += sizeof e;
    if (e.in_use && strcmp(e.name, name) == 0) {
      parent_dir->pos = pos;
      return e.is_directory;
    }
  }
  parent_dir->pos = pos;
  return false;
}

/* Helper provided in spec for parsing path */
/* Extracts a file name part from *SRCP into PART, and updates *SRCP 
   so that the next call will return the next file name part. 
   Returns 1 if successful, 0 at end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;
  /* Copy up to NAME_MAX character from SRC to DST. Add null terminator. */
  do {
    /* Skip leading slashes. If it's all slashes, we're done. */
    while (*src == '/') {
      src++;
    }
    if (*src == '\0') {
      return 0;
    }
    while (*src != '/' && *src != '\0') {
      if (dst < part + NAME_MAX) {
        *dst++ = *src;
      } else {
        return -1;
      }
      src++;
    }
    *dst = '\0';
    /* Advance source pointer. */
    *srcp = src;
  } while (strcmp(part, ".") == 0);

  return 1;
}

/* get the last name of the path. That is, retrieve the actual "file name" from a complete path. */
bool get_last_name(const char* dir, char name[NAME_MAX + 1]) {
  char last[NAME_MAX + 1];
  int result = get_next_part(last, &dir);
  while (result > 0) {
    strlcpy(name, last, NAME_MAX + 1);
    result = get_next_part(last, &dir);
  }
  if (result < 0) {
    return false;
  }
  return true;
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector, bool is_dir) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  e.is_directory = is_dir;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}
