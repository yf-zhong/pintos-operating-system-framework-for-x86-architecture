#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct lock file_sys_lock;  /* Lock for the file system operation */

/* File operation syscalls */
// void sys_create(struct intr_frame*, const char*, unsigned);
// void sys_remove(struct intr_frame*, const char*);
// void sys_open(struct intr_frame*, const char*);
// void sys_filesize(struct intr_frame*, int);
// void sys_read(struct intr_frame*, int, void*, unsigned);
// void sys_write(struct intr_frame*, int, const void*, unsigned);
// void sys_seek(struct intr_frame*, int, unsigned);
// void sys_tell(struct intr_frame*, int);
// void sys_close(struct intr_frame*, int);

#endif /* userprog/syscall.h */
