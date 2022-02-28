#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include "threads/malloc.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

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
  // check if cmd_line valid
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
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
    struct process* pcb = thread_current()->pcb;
    pcb->curr_as_child->exit_status = status;
    process_exit();
}

void sys_create(struct intr_frame* f, const char* file, unsigned initial_size) {  
  /* Todo: Argument validation */
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
  // use filesys_remove(const char *name)
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
  // use filesys_open(const char *name)
  if (!is_valid_str(file)) {
    sys_exit(f, -1);
  }
  // int flag;
  lock_acquire(&file_sys_lock);
  struct process* pcb = thread_current()->pcb;
  struct file *new_file = filesys_open(file);
  if (!new_file) {
    f->eax = -1;
    return;
  }
  struct file_descriptor *new_file_descriptor = (struct file_descriptor *) malloc(sizeof(struct file_descriptor));
  if (!new_file_descriptor) {
    sys_exit(f, -1);
  }
  // new_file_descriptor->fd = list_size(pcb->file_descriptor_table) + 1;
  new_file_descriptor->fd = pcb->cur_fd++; /* Alter 2, Alter 1 above, choose later */
  new_file_descriptor->file = new_file;
  /* ref_cnt is commented out, no need */
  // lock_acquire(&(pcb->ref_cnt_lock));
  // int ref_cnt = 1;
  // lock_release(&(pcb->ref_cnt_lock));
  list_push_back(&(pcb->file_descriptor_table) ,&(new_file_descriptor->elem));
  f->eax = new_file_descriptor->fd;
  lock_release(&file_sys_lock);
  return;
}

// void sys_filesize(struct intr_frame* f, int fd) {return;}

// void sys_read(struct intr_frame* f, int fd, void* buffer, unsigned size) {return;}

void sys_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  /* Argument validation (may need to test whether buffer is big enough) */
  if (!buffer) {
    // f->eax = -1;
    // return;
    sys_exit(f, -1);
  }
  
  if (fd == 1) {
    putbuf(buffer, size);
  } else if (fd <= 0) {
    /* TODO: May need revise */
    // f->eax = -1;
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
    file_tell(my_file_des->file);
    f->eax = 0;
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
    free(my_file_des);
    lock_release(&file_sys_lock);
    return;
  }
  f->eax = -1;
  lock_release(&file_sys_lock);
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

  int num_args = 0;
  switch(args[0]) {
    case SYS_WRITE: case SYS_READ:
      num_args = 3;
      break;
    case SYS_CREATE: case SYS_SEEK:
      num_args = 2;
      break;
    default:
      num_args = 1;
      break;
  }
  for (int i = 0; i <= num_args; i++) {
    if (!is_valid_addr((uint32_t) &args[i])) {
      f->eax = -1;
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
      process_exit();
    }
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
      sys_create(f, (const char*) args[1], args[2]);  /* Revision */
      break;
    case SYS_REMOVE:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
          sys_exit(f, -1);
      }
      sys_remove(f, (const char*) args[1]);  /* Revision, no local test provided */
      break;
    case SYS_OPEN:
      if ((sizeof(char*) - 1) & (unsigned long) &args[1]) {
          sys_exit(f, -1);
      }
      sys_open(f, (const char*) args[1]);                  /* Working */
      break;
    case SYS_FILESIZE:
    //   sys_filesize(f, args[1]);           /* Pending */
    //   use file_length(struct file*)
      break;
    case SYS_READ:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
          sys_exit(f, -1);
      }
    //   sys_read(f, args[1]);    /* Pending */
    //   use file_read(struct file*, void *, off_t)
      break;
    case SYS_WRITE:
      if ((sizeof(void*) - 1) & (unsigned long) &args[2]) {
          sys_exit(f, -1);
      }
      sys_write(f, args[1], (const void*) args[2], args[3]);   /* Revision needed */
    //   use file_write()
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
    default:
      f->eax = -3; /* If the NUMBER is not defined */
  }
}
