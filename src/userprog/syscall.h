#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
void syscall_init(void);

/* Lock for the file system operation */
struct lock file_sys_lock;


#endif /* userprog/syscall.h */
