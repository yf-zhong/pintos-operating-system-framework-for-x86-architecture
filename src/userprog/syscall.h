#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
void syscall_init(void);

/* File operation syscalls */
void sys_create(struct intr_frame*, const char*, unsigned);
void sys_remove(struct intr_frame*, const char*);
void sys_open(struct intr_frame*, const char*);
void sys_filesize(struct intr_frame*, int);
void sys_read(struct intr_frame*, int, void*, unsigned);
void sys_write(struct intr_frame*, int, const void*, unsigned);
void sys_seek(struct intr_frame*, int, unsigned);
void sys_tell(struct intr_frame*, int);
void sys_close(struct intr_frame*, int);

/* FPU ops */
void sys_comp_e(struct intr_frame*, int);

/* Lock for the file system operation */
struct lock file_sys_lock;

/* For part 2 task 3: user thread */
void sys_pthread_create(struct intr_frame*, stub_fun, pthread_fun, const void *);
void sys_pthread_exit(struct intr_frame*);
void sys_pthread_join(struct intr_frame*, tid_t tid);

void sys_lock_init(struct intr_frame*, struct lock*);
void sys_lock_acquire(struct intr_frame*, struct lock*);

void sys_get_tid(struct intr_frame* f);

#endif /* userprog/syscall.h */
