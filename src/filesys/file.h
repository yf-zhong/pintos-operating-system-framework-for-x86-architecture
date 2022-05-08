#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include <list.h>
#include "devices/block.h"

struct inode;

/* One element in the file descriptor table */
struct file_descriptor {
  int fd;            /* File descriptor */
  struct file* file; /* File description */
  struct dir* dir;
  struct list_elem elem;
  bool is_directory; /* file or directory (for proj3 task3) */
};

/* Opening and closing files. */
struct file* file_open(struct inode*);
struct file* file_reopen(struct file*);
void file_close(struct file*);
struct inode* file_get_inode(struct file*);

/* Reading and writing. */
off_t file_read(struct file*, void*, off_t);
off_t file_read_at(struct file*, void*, off_t size, off_t start);
off_t file_write(struct file*, const void*, off_t);
off_t file_write_at(struct file*, const void*, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write(struct file*);
void file_allow_write(struct file*);

/* File position. */
void file_seek(struct file*, off_t);
off_t file_tell(struct file*);
off_t file_length(struct file*);

block_sector_t file_get_inumber(struct file*);

#endif /* filesys/file.h */
