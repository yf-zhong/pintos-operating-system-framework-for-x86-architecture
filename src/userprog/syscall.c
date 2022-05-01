#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "lib/float.h"

static void syscall_handler(struct intr_frame*);

bool is_valid_addr(uint32_t);
bool is_valid_str(const char*);
void sys_practice(struct intr_frame*, int);
void sys_halt(void);
void sys_exec(struct intr_frame*, const char*);
void sys_wait(struct intr_frame*, pid_t);
void sys_exit(struct intr_frame*, int);

bool is_valid_addr(uint32_t addr) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  for (int i = 0; i < 4; i++) {
    if (!(is_user_vaddr((const char *) addr + i) && pagedir_get_page(pd, (const char *) addr + i))) {
      return false;
    }
  }
  return true;
}

bool is_valid_str(const char* c) {
  uint32_t* pd = thread_current()->pcb->pagedir;
  while (is_user_vaddr(c) && pagedir_get_page(pd, c)) {
    if (*c == '\0') {
      return true;
    }
    c++;
  }
  return false;
}

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock); /* Init the lock for file syscall */
}

void sys_practice(struct intr_frame* f, int i) {
  f->eax = i + 1;
  return;
}

void sys_halt() {
  shutdown_power_off();
}

void sys_exec(struct intr_frame* f, const char* cmd_line) {
  if (is_valid_str(cmd_line)) {
    f->eax = process_execute(cmd_line);
  }
  else {
    sys_exit(f, -1);
  }
  return;
}

void sys_wait(struct intr_frame* f, pid_t pid) {
  f->eax = process_wait(pid);
  return;
}

void sys_exit(struct intr_frame* f, int status) {
    f->eax = status;
    struct process* pcb = thread_current()->pcb;
    pcb->curr_as_child->exit_status = status;
    process_exit();
}

void sys_create(struct intr_frame* f, const char* file, unsigned initial_size) {  
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  /* Get current user program pcb */
  bool flag;
  /* Lock required */
  lock_acquire(&file_sys_lock);
  flag = filesys_create(file, initial_size);
  /* Lock release required */
  lock_release(&file_sys_lock);
  f->eax = flag;
  return;
}

void sys_remove(struct intr_frame* f, const char* file) {
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  bool flag;
  lock_acquire(&file_sys_lock);
  flag = filesys_remove(file);
  lock_release(&file_sys_lock);
  f->eax = flag;
  return;
}

void sys_open(struct intr_frame* f, const char* file) {
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  struct process* pcb = thread_current()->pcb;
  lock_acquire(&file_sys_lock);
  struct file *new_file = filesys_open(file);
  lock_release(&file_sys_lock);
  if (!new_file) {
    f->eax = -1;
    lock_release(&file_sys_lock);
    return;
  }
  struct file_descriptor *new_file_descriptor = (struct file_descriptor *) malloc(sizeof(struct file_descriptor));
  if (!new_file_descriptor) {
    sys_exit(f, -1);
  }
  new_file_descriptor->fd = pcb->cur_fd++;
  new_file_descriptor->file = new_file;
  list_push_back(&(pcb->file_descriptor_table) ,&(new_file_descriptor->elem));
  f->eax = new_file_descriptor->fd;
  return;
}

void sys_filesize(struct intr_frame* f, int fd) {
  if (fd <= 1) {
    sys_exit(f, -1);
  }
  off_t file_size;
  lock_acquire(&file_sys_lock);
  struct file_descriptor *my_file_des = find_file_des(fd);
  if (!my_file_des) {
    lock_release(&file_sys_lock);
    sys_exit(f, -1);
  }
  file_size = file_length(my_file_des->file);
  lock_release(&file_sys_lock);
  f->eax = file_size;
  return;
}

void sys_read(struct intr_frame* f, int fd, void* buffer, unsigned size) {
  if (!buffer) {
    sys_exit(f, -1);
  }
  if (!is_valid_addr((uint32_t)buffer)) {
    sys_exit(f, -1);
  }
  off_t number_read = 0;
  if (fd == 0) {
    for (unsigned i = 0; i < size; i++) {
      number_read += input_getc();
    }
    return;
  } else if (fd == 1 || fd < 0) {
    sys_exit(f, -1);
  }
  lock_acquire(&file_sys_lock);
  struct file_descriptor *my_file_des = find_file_des(fd);
  if (!my_file_des) {
    lock_release(&file_sys_lock);
    sys_exit(f, -1);
  }
  number_read = file_read(my_file_des->file, buffer, size);
  lock_release(&file_sys_lock);
  f->eax = number_read;
  return;
}

void sys_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  /* Argument validation (may need to test whether buffer is big enough) */
  if (!is_valid_addr((uint32_t)buffer)) {
    sys_exit(f, -1);
  }
  if (fd == 1) {
    putbuf(buffer, size);
  } else if (fd <= 0) {
    sys_exit(f, -1);
  } else {
    int bytes_read;
    lock_acquire(&file_sys_lock);
    struct file_descriptor* my_file_des = find_file_des(fd);
    if (my_file_des) {
      bytes_read = file_write(my_file_des->file, buffer, size);
      f->eax = bytes_read;
      lock_release(&file_sys_lock);
      return;
    }
    f->eax = -2;
    lock_release(&file_sys_lock);
  }
  return;
}

void sys_seek(struct intr_frame* f, int fd, unsigned position) {
  if (fd <= 1) {
    printf("fd: %d can't be seeked. (Either it is a stdin, out, err, or invalid)", fd);
    f->eax = -1;
    return;
  }
  lock_acquire(&file_sys_lock);
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    file_seek(my_file_des->file, position);
    f->eax = 0;
    lock_release(&file_sys_lock);
    return;
  }
  f->eax = -1;
  lock_release(&file_sys_lock);
  return;
}

void sys_tell(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  lock_acquire(&file_sys_lock);
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    f->eax = file_tell(my_file_des->file);
    lock_release(&file_sys_lock);
    return;
  }
  f->eax = -1;
  lock_release(&file_sys_lock);
  return;
}

void sys_close(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  lock_acquire(&file_sys_lock);
  struct file_descriptor* my_file_des = find_file_des(fd);
  if (my_file_des) {
    file_close(my_file_des->file);
    f->eax = 0;
    list_remove(&my_file_des->elem);
    free(list_entry(&my_file_des->elem, struct file_descriptor, elem));
    lock_release(&file_sys_lock);
    return;
  }
  f->eax = -1;
  lock_release(&file_sys_lock);
  return;
}

void sys_comp_e(struct intr_frame* f, int num) {
  if (num <= 0) {
    printf("n: %d is invalid.", num);
    f->eax = -1;
    return;
  }
  f->eax = sys_sum_to_e(num);
  return;
}

void sys_inumber(struct intr_frame* f, int fd) {
  if (fd < 0) {
    printf("fd: %d is invalid.", fd);
    f->eax = -1;
    return;
  }
  struct file_descriptor* cur_file_des = find_file_des(fd);
  struct inode* inode = cur_file_des->file->inode;
  f->eax = inode_get_inumber(inode);
  return;
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

   /* Validate stack pointer */
  if (!is_valid_addr((uint32_t)args)) {
    sys_exit(f, -1);
  }

  int num_args = 0;
  switch(args[0]) {
    case SYS_WRITE:
    case SYS_READ:
      num_args = 3;
      break;
    case SYS_CREATE:
    case SYS_SEEK:
      num_args = 2;
      break;
    case SYS_PRACTICE:
    case SYS_EXIT:
    case SYS_HALT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_INUMBER:
      num_args = 1;
      break;
    default:
      num_args = 0;
  }

  if (!is_user_vaddr(args + num_args)) {
    sys_exit(f, -1);
  }

  switch(args[0]) {
    case SYS_PRACTICE:
      sys_practice(f, args[1]);
      break;
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_WAIT:
      sys_wait(f, args[1]);
      break;
    case SYS_EXEC:
      if (((sizeof(pid_t) - 1) & (unsigned long) &args[1]) || !is_valid_addr((uint32_t) &args[1])) {
        sys_exit(f, -1);
      }
      sys_exec(f, (char*) args[1]);
      break;
    case SYS_EXIT:
      sys_exit(f, args[1]);
      break;

    /* File operations */
    case SYS_CREATE:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_create(f, (const char*) args[1], args[2]);
      break;
    case SYS_REMOVE:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_remove(f, (const char*) args[1]);
      break;
    case SYS_OPEN:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
        sys_exit(f, -1);
      }
      sys_open(f, (const char*) args[1]);
      break;
    case SYS_FILESIZE:
      sys_filesize(f, args[1]);
      break;
    case SYS_READ:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
        sys_exit(f, -1);
      }
      sys_read(f, args[1], (void*) args[2], args[3]);
      break;
    case SYS_WRITE:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
        sys_exit(f, -1);
      }
      sys_write(f, args[1], (const void*) args[2], args[3]);
      break;
    case SYS_SEEK:
      sys_seek(f, args[1], args[2]);
      break;
    case SYS_TELL:
      sys_tell(f, args[1]);
      break;
    case SYS_CLOSE:
      sys_close(f, args[1]);
      break;

    /* FPU ops */
    case SYS_COMPUTE_E:
      sys_comp_e(f, args[1]);
      break;

    /* File system inode */
    case SYS_INUMBER:
      sys_inumber(f, arg[1]);
      break;
  
    default:
      f->eax = -1; /* If the NUMBER is not defined */
  }
}
