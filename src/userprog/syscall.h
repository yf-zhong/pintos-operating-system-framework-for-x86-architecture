#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);


/* File operation syscalls */
void file_create(struct intr_frame*, const char*, unsigned);
void file_remove(struct intr_frame*, const char*);
void file_open(struct intr_frame*, const char*);
void file_filesize(struct intr_frame*, int);
void file_read(struct intr_frame*, int, void*, unsigned);
void file_write(struct intr_frame*, int, const void*, unsigned);
void file_seek(struct intr_frame*, int, unsigned);
void file_tell(struct intr_frame*, int);
void file_close(struct intr_frame*, int);

#endif /* userprog/syscall.h */
